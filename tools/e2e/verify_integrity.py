import struct, sys, zlib, re
M64 = (1 << 64) - 1
SEED = int(sys.argv[4], 0)
def seed_magic(tag):
    z = (SEED ^ tag) & M64
    z ^= z >> 31
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 27
    z ^= (tag * 0x9E3779B97F4A7C15) & M64
    z &= M64
    m = (z ^ (z >> 32)) & 0xFFFFFFFF
    return m if m else 1
INTEGRITY_MAGIC = seed_magic(0x52474E49)
DAT_MAGIC = seed_magic(0x54414448)
d = open(sys.argv[1], 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
cof = pe + 4; opt = cof + 20
optsz = struct.unpack_from('<H', d, cof + 16)[0]
nsec = struct.unpack_from('<H', d, cof + 2)[0]
so = opt + optsz
secs = []
for i in range(nsec):
    s = so + i * 40
    nm = d[s:s+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, ra = struct.unpack_from('<IIII', d, s + 8)
    secs.append((nm, va, vs, ra, rs))
def r2o(rva):
    for nm, va, vs, ra, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None
# 8k-5: audit data lives in its own section.
if not any(nm.startswith('.hdat') for nm, va, vs, ra, rs in secs):
    print('  FAIL audit data section (.hdat*) missing'); sys.exit(1)
# Read the manifest RVA from the vault.
vault = None
for nm, va, vs, ra, rs in secs:
    if nm != '.hydavm':
        continue
    for off in range(ra, ra + rs - 4):
        if struct.unpack_from('<I', d, off)[0] == 0x52494D50:
            vault = off
            break
    if vault:
        break
if vault is None:
    print('  FAIL vault not found'); sys.exit(1)
integ_rva = struct.unpack_from('<I', d, vault + 16)[0]
if integ_rva == 0:
    print("  FAIL manifest RVA is zero (no audit)"); sys.exit(1)
mo = r2o(integ_rva)
mg, ver, cnt, dat_rva, selfcrc, salt, _, _ = struct.unpack_from('<IIIIIIII', d, mo)
if mg != INTEGRITY_MAGIC or ver != 2:
    print(f'  FAIL manifest signature/version: {mg:#x}/{ver}'); sys.exit(1)
if cnt == 0 or cnt > 1024 or dat_rva == 0:
    print(f'  FAIL manifest fields: cnt={cnt} dat={dat_rva:#x}'); sys.exit(1)

# Independent decoder mirroring the C++ side.
M = (1 << 64) - 1
def mix(vip, key):
    z = ((vip ^ key) * 0x2C1B3C6D) & M
    z ^= z >> 29
    z = (z * 0x297A2D39) & M
    z ^= z >> 32
    z = (z * 0x1B873593) & M
    z ^= z >> 29
    return z
def ks(z, i):
    lo = (z >> (8 * (i & 7))) & 0xFF
    hi = (z >> (8 * ((i + 4) & 7))) & 0xFF
    k = lo ^ hi
    if i >= 8:
        k ^= 0xA5
    return k
def hydak_key(rva, seed):
    z = (seed ^ 0x9E3779B97F4A7C15) & M
    z ^= (rva * 0xC2B2AE3D27D4EB4F) & M
    z ^= z >> 29
    z = (z * 0xBF58476D1CE4E5B9) & M
    z ^= z >> 32
    return z or 1
def integrity_key(salt, man_rva, seed):
    z = (salt * 0x9E3779B97F4A7C15) & M
    z ^= (man_rva + 0x165667B19E3779F9) & M
    z ^= seed
    z ^= z >> 29
    z = (z * 0xBF58476D1CE4E5B9) & M
    z ^= z >> 32
    return z or 1
if len(sys.argv) > 4:
    SEED = int(sys.argv[4], 0)
else:
    src = open(sys.argv[3], encoding='utf-8').read()
    m = re.search(r'#define\s+HYDA_VM_SEED\s+(0x[0-9A-Fa-f]+)', src)
    if not m:
        print('  FAIL could not read the sample seed'); sys.exit(1)
    SEED = int(m.group(1), 0)

do = r2o(dat_rva)
if do is None:
    print('  FAIL data container RVA not in the file'); sys.exit(1)
# Container is encrypted: no plaintext header signature in the file.
if struct.unpack_from('<I', d, do)[0] == DAT_MAGIC:
    print('  FAIL data container is plaintext (must be encrypted)'); sys.exit(1)
blk = bytearray(d[do:do + 32 + cnt * 16])
k = hydak_key(dat_rva, SEED)
for idx in range(0, len(blk) // 8 + 1):
    z = mix(idx, k)
    for b in range(8):
        i = idx * 8 + b
        if i < len(blk):
            blk[i] ^= (z >> (8 * b)) & 0xFF
hm, hv, htot, hcnt, hsalt, hcrc = struct.unpack_from('<IIIIII', blk, 0)
if hm != DAT_MAGIC or hv != 1:
    print(f'  FAIL data container signature: {hm:#x}/{hv}'); sys.exit(1)
if htot != 32 + cnt * 16 or hcnt != cnt or hsalt != salt or hcrc != selfcrc:
    print(f'  FAIL data container header does not match the manifest'); sys.exit(1)
# Inner layer: integrity_crypt -> chunk array.
ck = integrity_key(salt, integ_rva, SEED)
pay = bytearray(blk[32:32 + cnt * 16])
prev = 0
i = 0
while i < len(pay):
    z = mix(i & ~7, ck)
    for j in range(8):
        if i >= len(pay):
            break
        c = pay[i]
        pay[i] = (c - ks(z, i) - prev) & 0xFF
        prev = c
        i += 1
if zlib.crc32(bytes(pay)) & 0xFFFFFFFF != selfcrc:
    print('  FAIL self_crc mismatch (decrypted shard array)'); sys.exit(1)
# Chunk CRCs must match the file bytes exactly.
def sec_of(rva):
    for nm, va, vs, ra, rs in secs:
        if va <= rva < va + max(vs, rs):
            return nm
    return None
bad = 0
covered = set()
for i in range(cnt):
    rva, size, want, _f = struct.unpack_from('<IIII', pay, i * 16)
    covered.add(sec_of(rva))
    off = r2o(rva)
    if off is None or off + size > len(d):
        bad += 1; continue
    if zlib.crc32(d[off:off + size]) & 0xFFFFFFFF != want:
        bad += 1
if bad:
    print(f'  FAIL {bad} shard CRCs do not match the file bytes'); sys.exit(1)
if not any(nm and nm not in ('.text', '.rdata') for nm in covered):
    print('  FAIL integrity only covers .text/.rdata'); sys.exit(1)
print(f'  OK   8k manifest: {cnt} shards, rva {integ_rva:#x}, data container '
      f'rva {dat_rva:#x} (RVA-bound encrypted), salt {salt:#x}')
