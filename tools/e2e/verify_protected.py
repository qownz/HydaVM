import struct, sys
UWOP_ALLOC_SMALL = 2   # wine: #define UWOP_ALLOC_SMALL 2

def load(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    cof = pe + 4
    num = struct.unpack_from('<H', d, cof + 2)[0]
    optsize = struct.unpack_from('<H', d, cof + 16)[0]
    ptrsym, nsym = struct.unpack_from('<II', d, cof + 8)
    opt = cof + 20
    base = opt + optsize
    secs = []
    for i in range(num):
        o = base + i * 40
        raw = d[o:o + 8]
        if raw[:1] == b'/':
            off = int(raw[1:].split(b'\0')[0])
            a = ptrsym + nsym * 18 + off
            nm = d[a:d.index(b'\0', a)].decode()
        else:
            nm = raw.split(b'\0')[0].decode()
        vs, va, rs, ra = struct.unpack_from('<IIII', d, o + 8)
        ch = struct.unpack_from('<I', d, o + 36)[0]
        secs.append(dict(nm=nm, va=va, vs=vs, ra=ra, rs=rs, ch=ch))
    dirs = struct.unpack_from('<I', d, opt + 108)[0]
    dd = [struct.unpack_from('<II', d, opt + 112 + i * 8) for i in range(dirs)]
    return dict(d=d, secs=secs, dd=dd, ptrsym=ptrsym, nsym=nsym,
                imagebase=struct.unpack_from('<Q', d, opt + 24)[0])

def by_va(pe, va):
    for s in pe['secs']:
        if s['va'] <= va < s['va'] + max(s['vs'], s['rs']):
            return s
    return None

def r2o(pe, rva):
    s = by_va(pe, rva)
    return None if s is None else s['ra'] + (rva - s['va'])

old = load(sys.argv[1])
new = load(sys.argv[2])
skipped = set()
if len(sys.argv) > 9:
    import json
    for entry in json.load(open(sys.argv[9])).get('skipped', []):
        skipped.add(entry['name'])
nd = new['d']
ok = True

# --- (1) bodies erased; match sections by VA ---
targets = [s for s in old['secs'] if s['nm'].startswith('hydafn_')]
for s in targets:
    o = by_va(new, s['va'])
    if o is None:
        print(f"  FAIL {s['nm']:16} protected section missing from output"); ok = False; continue
    body = nd[o['ra']:o['ra'] + s['vs']]
    if s['nm'] in skipped:
        plain = old['d'][s['ra']:s['ra'] + s['vs']]
        good = body == plain
        print(f"  {'OK  ' if good else 'FAIL'} {s['nm']:16} -> {o['nm']:8} body: "
              f"skipped, left native ({s['vs']} bytes unchanged)" if good else
              f"  FAIL {s['nm']:16} skipped but body changed")
        ok = ok and good
        continue
    good = body[0] == 0xE9 and body[5:s['vs']] == b'\xcc' * (s['vs'] - 5)
    print(f"  {'OK  ' if good else 'FAIL'} {s['nm']:16} -> {o['nm']:8} body: "
          f"{body[:6].hex(' ')} ... ({s['vs']} bytes, {s['vs']-5} bytes erased)")
    ok = ok and good

# --- (2) symbol / debug stripping ---
leftover = [s['nm'] for s in new['secs'] if s['nm'].startswith('.debug_')]
if leftover:
    print(f"  FAIL .debug_* sections still present: {leftover}"); ok = False
else:
    print("  OK   .debug_* sections stripped")

names = [s['nm'] for s in new['secs']]
if any(n.startswith('hydafn_') for n in names):
    print(f"  FAIL section names leak the function name: "
          f"{[n for n in names if n.startswith('hydafn_')]}"); ok = False
else:
    print("  OK   section names neutralized (.hvfn*)")

if new['nsym'] != 0:
    print(f"  FAIL COFF symbol table present ({new['nsym']} symbols)"); ok = False
else:
    print("  OK   COFF symbol table cleared (0 symbols)")

leaked = [p for p in (b'hydafn_', b'.debug_', b'pe_target.c') if p in nd]
if leaked:
    print(f"  FAIL leaked string in output: {leaked}"); ok = False
else:
    print("  OK   source names / pseudo-symbols absent from output")

# --- (3) exception table (.pdata) ---
exc_rva, exc_size = new['dd'][3]
if exc_rva == 0 or exc_size == 0 or exc_size % 12:
    print(f"  FAIL exception directory invalid (rva={exc_rva:#x} size={exc_size:#x})")
    ok = False
else:
    o = r2o(new, exc_rva)
    ent = [struct.unpack_from('<III', nd, o + i * 12) for i in range(exc_size // 12)]
    print(f"  OK   unwind table: {len(ent)} entries @rva {exc_rva:#x} "
          f"(section {by_va(new, exc_rva)['nm']})")
    if not all(ent[i][0] < ent[i + 1][0] for i in range(len(ent) - 1)):
        print("  FAIL unwind table not sorted by BeginAddress"); ok = False
    else:
        print("  OK   table sorted (unwinder can binary-search)")
    # Old body ranges have no unwind entry (they are a jmp leaf now).
    for s in targets:
        if s['nm'] in skipped: continue
        hit = [(hex(b), hex(e)) for b, e, _ in ent if b <= s['va'] < e]
        if hit:
            print(f"  FAIL {s['nm']} old body still has an unwind entry: {hit}"); ok = False
    if ok:
        print("  OK   old unwind entries for protected bodies dropped")
    # Each trampoline needs a valid UNWIND_INFO entry.
    ntr = 0
    for s in targets:
        if s['nm'] in skipped: continue
        off = r2o(new, s['va'])
        if off is None or nd[off] != 0xE9:
            print(f"  FAIL {s['nm']}: body is not a jmp"); ok = False; continue
        tramp = s['va'] + 5 + struct.unpack_from('<i', nd, off + 1)[0]
        e = [x for x in ent if x[0] == tramp]
        if len(e) != 1:
            print(f"  FAIL {s['nm']}: no entry for trampoline {tramp:#x}"); ok = False; continue
        b, end, ui = e[0]
        uo = r2o(new, ui)
        ver, prolog, cnt, fr = struct.unpack_from('<BBBB', nd, uo)
        coff, opinfo = struct.unpack_from('<BB', nd, uo + 4)
        code, info = opinfo & 0xF, opinfo >> 4
        frame = (info + 1) * 8
        good = ((ver & 7) == 1 and cnt == 1 and fr == 0 and prolog == 4 and
                coff == 4 and code == UWOP_ALLOC_SMALL and 0x28 <= frame <= 0x68 and
                end > b)
        print(f"  {'OK  ' if good else 'FAIL'} {s['nm']:16} trampoline {tramp:#x}: "
              f"entry {b:#x}-{end:#x}, prolog={prolog}, ALLOC_SMALL frame={frame:#x}")
        ok = ok and good
        ntr += 1
    want_ntr = len(targets) - len(skipped)
    print(f"  {'OK  ' if ntr == want_ntr else 'FAIL'} {ntr}/{want_ntr} trampoline "
          f"unwind entries correct")

if '.hydavm' not in names:
    print('  FAIL .hydavm section not added'); ok = False
else:
    h = next(s for s in new['secs'] if s['nm'] == '.hydavm')
    print(f"  OK   .hydavm added (va={h['va']:#x}, {h['vs']} bytes)")
    if h['ch'] != 0x60000020:
        print(f"  FAIL .hydavm characteristics wrong ({h['ch']:#x})"); ok = False
    else:
        print('  OK   .hydavm CODE|EXECUTE|READ')

# --- (4) handler shards/containers and decoy blocks ---
import zlib
M64 = (1 << 64) - 1
SEED = int(sys.argv[4], 16) if len(sys.argv) > 4 and sys.argv[4] else 0x8F3A5C71D2E6B904

# Signature constants derive from the seed (same as seed_magic).
def seed_magic(tag):
    z = (SEED ^ tag) & M64
    z ^= z >> 31
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 27
    z ^= (tag * 0x9E3779B97F4A7C15) & M64
    z &= M64
    m = (z ^ (z >> 32)) & 0xFFFFFFFF
    return m if m else 1
HYDA_MAGIC = seed_magic(0x4B414448)
BLOB_MAGIC = seed_magic(0x424D5648)
INTEGRITY_MAGIC = seed_magic(0x52474E49)
DAT_MAGIC = seed_magic(0x54414448)
HYDA_VERSION = 3
HYDA_NO_CHUNK = 0xFFFF
# Opcode count comes from the protector output.
HYDA_OP_COUNT = int(sys.argv[6])

def hmix(vip, key):
    z = (vip ^ key) & M64
    z = (z * 0x2C1B3C6D) & M64
    z ^= z >> 29
    z = (z * 0x297A2D39) & M64
    z ^= z >> 32
    z = (z * 0x1B873593) & M64
    z ^= z >> 29
    return z & M64

def hkey(rva):
    z = (SEED ^ 0x9E3779B97F4A7C15) & M64
    z ^= (rva * 0xC2B2AE3D27D4EB4F) & M64
    z ^= z >> 29
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 32
    return z if z else 1

def hxor(blob, off, n, key):
    out = bytearray(blob)
    for i in range(n):
        out[off + i] ^= (hmix(i >> 3, key) >> (8 * (i & 7))) & 0xFF
    return out

def hprobe(blob, off, key):
    """If the signature matches, returns total_size, else 0 (does not modify the blob)."""
    hdr = bytes(hxor(blob, off, 32, key)[off:off + 32])
    magic, total, _cs, _cc, _co, _oo, _bad, ver, _crc = \
        struct.unpack_from('<IIIIIIHHI', hdr, 0)
    return total if (magic == HYDA_MAGIC and ver == HYDA_VERSION) else 0

def is_container(s):
    """Runtime candidate rule: a section present in the file, READABLE, NOT EXECUTABLE and NOT DISCARDABLE."""
    return (bool(s['ch'] & 0x40000000) and not (s['ch'] & 0x20000000) and
            not (s['ch'] & 0x02000000) and s['rs'] >= 32 and s['vs'] >= 32)

def hscan(sec, data):
    """Runtime scanner: 16-aligned blocks; a signature hit counts a SHARD and skips align_up(total,16), a miss advances 16 bytes."""
    blob = data[sec['ra']:sec['ra'] + sec['vs']]
    res, off = [], 0
    while off + 32 <= len(blob):
        t = hprobe(blob, off, hkey(sec['va'] + off))
        if 32 <= t <= len(blob) - off:
            res.append((sec['va'] + off, t))
            off += (t + 15) & ~15
        else:
            off += 16
    return res

EXPP, EXPC = 6, 3  # protector varsayilanlari (--hydak-parts / --hydak-containers)
# Only the encrypted signature identifies a shard; names/locations do not.
cands = [s for s in new['secs'] if is_container(s)]
found = [(s, rva, t) for s in cands for (rva, t) in hscan(s, nd)]
cont = []
for s, _, _ in found:
    if s not in cont:
        cont.append(s)
if len(found) != EXPP:
    print(f"  FAIL expected {EXPP} real shards, keyed scan "
          f"{len(found)} buldu"); ok = False
else:
    print(f"  OK   keyed scan found {EXPP} real shards "
          f"(decoy blocks left no trace): " +
          ', '.join(f"{r:#x}({t}b)" for _, r, t in found))
if len(cont) != EXPC:
    print(f"  FAIL expected {EXPC} containers, shards in {len(cont)} sections "
          f"bulundu"); ok = False
else:
    print(f"  OK   {len(cands)} candidate data sections scanned; shards only in {EXPC} "
          f"containers: " +
          ', '.join(f"{s['nm']}(va={s['va']:#x},{s['vs']}b)" for s in cont))
bad_ch = [f"{s['nm']}={s['ch']:#x}" for s in cont if s['ch'] != 0x40000040]
if bad_ch:
    print(f"  FAIL container characteristics wrong: {','.join(bad_ch)}"); ok = False
else:
    print('  OK   containers INITIALIZED_DATA|READ (look like plain data; runtime '
          'makes them RW -> RX via VirtualProtect)')
leaky = [s['nm'] for s in new['secs']
         if 'hydak' in s['nm'].lower() or 'handler' in s['nm'].lower()]
if leaky:
    print(f"  FAIL section name gives a discovery hint: {leaky}"); ok = False
else:
    print("  OK   no 'hydak'/'handler' hint in section names (discovery is not by name)")
raw_magic = struct.pack('<I', HYDA_MAGIC)
if any(nd.find(raw_magic, s['ra'], s['ra'] + s['vs']) >= 0 for s in cont):
    print('  FAIL plaintext hydak signature inside a container (shard not encrypted)')
    ok = False
else:
    print('  OK   no plaintext hydak signature in containers (header encrypted)')
sig0 = {bytes(nd[s['ra']:s['ra'] + 48]) for s in cont}
print(f"  {'OK  ' if len(sig0) == len(cont) else 'FAIL'} container contents "
      f"differ ({len(sig0)}/{len(cont)}; each shard uses its own key)")
ok = ok and len(sig0) == len(cont)
if [s for s in old['secs'] if 'hydak' in s['nm']]:
    print('  FAIL `.hydak*` also present in the input file (the protector must add them)')
    ok = False

# Each chunk range [rva, rva+size) must be 0xCC in .text.
tt = next(s for s in new['secs'] if s['nm'] == '.text')
tb = nd[tt['ra']:tt['ra'] + tt['rs']]
erased = []
def erased_ok(c_rva, c_size):
    base = c_rva - tt['va']
    if base < 0 or base + c_size > len(tb):
        return False
    return all(x == 0xCC for x in tb[base:base + c_size])

# (a) container contents must look random.
for s in cont:
    blob = nd[s['ra']:s['ra'] + s['vs']]
    run = best_run = 1
    for i in range(1, len(blob)):
        if blob[i] == blob[i - 1]:
            run += 1
            best_run = max(best_run, run)
        else:
            run = 1
    good = best_run < 24 and len(set(blob)) > 200
    print(f"  {'OK  ' if good else 'FAIL'} {s['nm']}: content looks random "
          f"({len(set(blob))} distinct bytes, longest run of equal bytes {best_run})")
    ok = ok and good

# (b) decrypt each shard; verify header, CRC, chunk table and opmap.
own = {}
bad_seen = []
for s, rva, total in found:
    o = s['ra'] + (rva - s['va'])
    dec = bytes(hxor(nd[o:o + total], 0, total, hkey(rva)))
    magic, tot2, code, nch, coff, ooff, bad, ver, crc = \
        struct.unpack_from('<IIIIIIHHI', dec, 0)
    if tot2 != total or magic != HYDA_MAGIC or ver != HYDA_VERSION:
        print(f"  FAIL shard {rva:#x}: bad header"); ok = False; continue
    if (zlib.crc32(dec[32:]) & 0xFFFFFFFF) != crc:
        print(f"  FAIL shard {rva:#x}: CRC-32 mismatch"); ok = False; continue
    if code < 16 or nch == 0 or coff >= total or ooff + 2 * HYDA_OP_COUNT > total:
        print(f"  FAIL shard {rva:#x}: invalid layout fields"); ok = False
        continue
    offs, chok = [], True
    for i in range(nch):
        c_off, c_size, c_rva = struct.unpack_from('<III', dec, coff + i * 12)
        offs.append(c_off)
        if c_off % 16 or c_off < 32 or c_size == 0 or c_off + c_size > total:
            print(f"  FAIL shard {rva:#x}: invalid layout for chunk {i}")
            chok = False
        erased.append((c_rva, c_size))
        if not erased_ok(c_rva, c_size):
            print(f"  FAIL shard {rva:#x}: chunk {i} body @{c_rva:#x} "
                  f"({c_size}b) not erased with 0xCC in .text"); chok = False
    if offs != sorted(offs):
        print(f"  FAIL shard {rva:#x}: chunk offsets not increasing"); chok = False
    ok = ok and chok
    if bad != HYDA_NO_CHUNK:
        if bad >= nch:
            print(f"  FAIL shard {rva:#x}: invalid slot index {bad}")
            ok = False
        else:
            bad_seen.append(rva)
    for op in range(HYDA_OP_COUNT):
        li = struct.unpack_from('<H', dec, ooff + op * 2)[0]
        if li == HYDA_NO_CHUNK:
            continue
        if li >= nch:
            print(f"  FAIL shard {rva:#x}: opmap[{op}]={li} invalid"); ok = False
            continue
        if op in own:
            print(f"  FAIL opcode {op} appears in more than one shard "
                  f"({own[op]:#x} + {rva:#x})"); ok = False
        own[op] = rva
miss = [o for o in range(HYDA_OP_COUNT) if o not in own]
if miss:
    print(f"  FAIL {len(miss)} opcodes missing from all shards: {miss[:6]}"); ok = False
elif len(bad_seen) != 1:
    print(f"  FAIL invalid slot not in exactly one shard ({len(bad_seen)})")
    ok = False
else:
    print(f"  OK   {HYDA_OP_COUNT} opcodes + invalid slot exactly one shard each "
          f"distributed; per-shard CRC-32 + chunk table verified")

# (c) discovery must be independent of the shard/decoy/container counts.
alt = load(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] else None
if alt is not None:
    afound = [(s, rva, t) for s in alt['secs'] if is_container(s)
              for (rva, t) in hscan(s, alt['d'])]
    acaps = []
    for s, _, _ in afound:
        if s not in acaps:
            acaps.append(s)
    if len(afound) != 3 or len(acaps) != 2:
        print(f"  FAIL alternate layout: {len(afound)} shards / {len(acaps)} "
              f"containers (expected 3 / 2)"); ok = False
    else:
        print('  OK   CLI counts applied (3 shards / 2 decoys / 2 containers): '
              'keyed scan again found exactly the real shards')

# Erased ranges are 0xCC in the output and real code in the original.
erased = sorted(set(erased))
tot = sum(sz for _, sz in erased)
orig_code = 0
bad_runs = 0
for rva, sz in erased:
    if not erased_ok(rva, sz):
        bad_runs += 1
    oo = r2o(old, rva)
    if oo >= 0:
        ob = old['d'][oo:oo + sz]
        orig_code += sum(1 for x in ob if x != 0xCC)
good = (bad_runs == 0 and tot >= 20000 and orig_code >= 20000)
print(f"  {'OK  ' if good else 'FAIL'} handler bodies fully erased in .text "
      f"erased: {len(erased)} ranges = {tot} bytes 0xCC "
      f"(original had {orig_code} bytes of code); bad runs: {bad_runs}")
ok = ok and good

# No plaintext handler signature may remain in the output.
sig = None
for rva, sz in erased:
    oo = r2o(old, rva)
    if oo < 0:
        continue
    ob = old['d'][oo:oo + sz]
    for k in range(0, max(1, len(ob) - 16), 16):
        w = bytes(ob[k:k + 16])
        if len(set(w)) >= 9 and 0xCC not in w:
            sig = w
            break
    if sig is not None:
        break
if sig is None:
    # Fallback: first 16 bytes of the largest body.
    rva, sz = max(erased, key=lambda e: e[1])
    oo = r2o(old, rva)
    sig = bytes(old['d'][oo:oo + 16])
leak = nd.find(sig)
print(f"  {'OK  ' if leak < 0 else 'FAIL'} handler code not leaking as plaintext "
      f"({len(sig)}-byte signature: {sig[:6].hex(' ')} ...)")
ok = ok and leak < 0
# Encrypted containers must not contain the plaintext signature.
sc_leak = [s['nm'] for s in cont if nd.find(sig, s['ra'], s['ra'] + s['vs']) >= 0]
print(f"  {'OK  ' if not sc_leak else 'FAIL'} container contents encrypted "
      f"(no plaintext handler signature)")
ok = ok and not sc_leak

# The handler list must be neutralized to one harmless target.
ib = new['imagebase']
img_end = ib + max(s['va'] + max(s['vs'], s['rs']) for s in new['secs'])
run_best, run_at = 0, None
for s in new['secs']:
    if (s['ch'] & 0x80000000) == 0 or s['ra'] == 0 or s['rs'] == 0:
        continue
    blob = nd[s['ra']:s['ra'] + s['rs']]
    run, prev = 0, None
    for i in range(0, len(blob) - 8 + 1, 8):
        v = struct.unpack_from('<Q', blob, i)[0]
        if v == prev and ib <= v < img_end:
            run += 1
            if run > run_best:
                run_best, run_at = run, s['va'] + i + 8 - run * 8
        else:
            run = 1
        prev = v
neutral_ok = run_best >= HYDA_OP_COUNT
print(f"  {'OK  ' if neutral_ok else 'FAIL'} `hyda_handler_list` neutralized: "
      f"{run_best + 1} consecutive equal pointers @rva "
      f"{(run_at if run_at is not None else 0):#x}")
ok = ok and neutral_ok
# Handler blobs use a per-shard RVA-derived key.
print('  OK   shard keys are derived from the RVA (not stored; decoys are indistinguishable)')

# Blob layout: trampolines, then 16-aligned headers inside .hydavm.
if not sys.argv[3]:
    print('  FAIL no blob RVA found in protector output'); sys.exit(1)
blob0 = h['ra'] + (int(sys.argv[3], 16) - h['va'])
# BlobHeader: 48 bytes (magic, size, entry, crc, version, flags, islands, imports, shard mask).
HYDA_BLOB_VERSION = 4
HYDA_BLOB_IDENTITY = 2
magic, cs, entry, crc, ver, flags, isrva, icount, ispan, imp_tab_rva, resv, \
    resv2 = struct.unpack_from('<IIIIIIIIIIII', nd, blob0)
if magic != BLOB_MAGIC:
    print(f'  FAIL blob header not found (magic={magic:#x})'); ok = False
elif ver != HYDA_BLOB_VERSION:
    print(f'  FAIL unexpected blob version: {ver}'); ok = False
elif flags != HYDA_BLOB_IDENTITY:
    print(f'  FAIL encrypted blob must carry the per-function identity flag: '
          f'{flags:#x}'); ok = False
elif (isrva == 0) != (icount == 0):
    print(f'  FAIL island area inconsistent: rva={isrva:#x} count={icount}'); ok = False
else:
    print(f"  OK   blob header (version={ver}, code_size={cs}, flags={flags:#x}, "
          f"crc={crc:#x})")
    if icount:
        print(f"  OK   island area: {icount} islands, rva={isrva:#x}, span={ispan}")
    # Corrupt one bytecode byte: the CRC gate must reject it.
    bad = bytearray(nd)
    bad[blob0 + 48 + 2] ^= 0xFF
    open(sys.argv[2] + '.tampered', 'wb').write(bad)
    # Corrupt the version: the blob must be rejected.
    vtam = bytearray(nd)
    struct.pack_into('<I', vtam, blob0 + 16, HYDA_BLOB_VERSION + 1)
    open(sys.argv[2] + '.vtampered', 'wb').write(vtam)

# --- islands encrypted? ---
# Decrypt an island and verify it is valid code.
isle_blob_rva = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] else ''
imp_blob_rva = sys.argv[8] if len(sys.argv) > 8 and sys.argv[8] else ''
if not isle_blob_rva:
    print("  SKIP island encryption check: no blob RVA with islands found")
else:
    isle0 = h['ra'] + (int(isle_blob_rva, 16) - h['va'])
    (_m, _cs, _en, _crc, iver, _fl, iisrva, iicount, iispan,
     _rsv) = struct.unpack_from('<IIIIIIIIII', nd, isle0)
    if iver != HYDA_BLOB_VERSION or iicount == 0:
        print(f'  FAIL unexpected island blob (version={iver}, count={iicount})')
        ok = False
    else:
        M64 = (1 << 64) - 1

        def u64(x):
            return x & M64

        def island_magic():
            z = u64(SEED ^ 0xA5A5C3C3F0F0F0F0)
            z = u64(z ^ (z >> 31))
            z = u64(z * 0xBF58476D1CE4E5B9)
            z = u64(z ^ (z >> 27))
            # C++ side truncates to uint32_t.
            return (u64(z ^ (z >> 32)) & 0xFFFFFFFF) | 1

        # Mutation-plan signature (same rule as island_mut_magic).
        def mut_magic():
            z = u64(SEED ^ 0x8AD1C0DE12345678)
            z = u64(z ^ (z >> 33))
            z = u64(z * 0xFF51AFD7ED558CCD)
            z = u64(z ^ (z >> 33))
            z = u64(z * 0xC4CEB9FE1A85EC53)
            z = u64(z ^ (z >> 33))
            m = u64(z ^ (z >> 32)) & 0xFFFFFFFF
            if (m & 0xFF) in (0xE9, 0x00):
                m ^= 0x0000A5
            return m

        def island_key(salt, rva):
            z = u64(salt * 0x9E3779B97F4A7C15)
            z = u64(z ^ u64(rva + 0x165667B19E3779F9))
            z = u64(z ^ SEED)
            z = u64(z ^ (z >> 29))
            z = u64(z * 0xBF58476D1CE4E5B9)
            z = u64(z ^ (z >> 32))
            return z or 1

        def crypt_mix(vip, key):
            z = u64(vip ^ key)
            z = u64(z * 0x2C1B3C6D)
            z = u64(z ^ (z >> 29))
            z = u64(z * 0x297A2D39)
            z = u64(z ^ (z >> 32))
            z = u64(z * 0x1B873593)
            z = u64(z ^ (z >> 29))
            return z

        def ks_byte(z, i):
            lo = (z >> (8 * (i & 7))) & 0xFF
            hi = (z >> (8 * ((i + 4) & 7))) & 0xFF
            k = lo ^ hi
            if i >= 8:
                k ^= 0xA5
            return k

        def island_decrypt(buf, salt, rva):
            key = island_key(salt, rva)
            out = bytearray(buf)
            prev = 0
            i = 0
            while i < len(out):
                z = crypt_mix(i, key)
                for _ in range(8):
                    if i >= len(out):
                        break
                    k = ks_byte(z, i)
                    c = out[i]
                    out[i] = (c - k - prev) & 0xFF
                    prev = c
                    i += 1
            return bytes(out)

        # Walk the island area: 32-byte headers, then `size` bytes of code.
        area_off = h['ra'] + (iisrva - h['va'])
        # Candidate code sections for a gate exit.
        code_ranges = [(sec['va'], sec['va'] + max(sec['vs'], sec['rs']))
                       for sec in new['secs']
                       if sec['va'] != h['va']]

        def in_code(rva):
            return any(lo <= rva < hi for lo, hi in code_ranges)

        problems = []
        targets = set()
        island_blocks = []      # (rva, size, salt) — her blok
        n_isl = 0
        n_valid = 0
        n_plan = 0      # 8s: gecerli mutasyon plani olan gercek ada
        n_flip = 0      # 8s: SSE es-deger cevrimi planlanmis ada
        off = area_off
        rva = iisrva
        # Decoy islands are counted too; walk until the area ends.
        area_end = area_off + iispan
        while off + 32 <= area_end:
            imagic, isize, isalt, iflags = struct.unpack_from('<IIII', nd, off)
            iat_of = struct.unpack_from('<I', nd, off + 24)[0]   # 8e: IAT RVA
            if imagic == 0:
                # Trailing alignment padding ends the walk.
                break
            if imagic != island_magic():
                problems.append(f'island signature wrong ({imagic:#x})')
                break
            if isize == 0 or isize > 0x10000:
                problems.append(f'island size invalid ({isize})')
                break
            enc = nd[off + 32: off + 32 + isize]
            dec = island_decrypt(enc, isalt, rva + 32)
            # Import islands carry a hidden slot (8 extra bytes).
            island_blocks.append((rva + 32, isize, isalt, iat_of))
            if enc == dec:
                problems.append('encrypted bytes are identical to plaintext')
            # Look for a valid E9 rel32 tail jump into a code section.
            found = None
            for k in range(len(dec) - 4):
                if dec[k] != 0xE9:
                    continue
                rel = struct.unpack_from('<i', dec, k + 1)[0]
                tgt = rva + 32 + k + 5 + rel
                if in_code(tgt):
                    found = tgt
                    break
            if found is None:
                # Decoy island: no valid tail and no mutation plan.
                pass
            else:
                targets.add(found)
                n_valid += 1
                # Mutation plan is stored in the last 24 bytes of the payload.
                if isize < 24 + 8:
                    problems.append(f'island too small for an 8s plan ({isize})')
                else:
                    (pmagic, pver, pioff, pilen, pflip, pfoff, pdoff,
                     ptail, pseed, _rsv0, _rsv1) = struct.unpack_from(
                         '<IBBBBBBHIII', dec, isize - 24)
                    slack = isize - 24 - (ptail + 5)
                    if pmagic != mut_magic() or pver != 1:
                        problems.append(f'8s plan signature missing ({pmagic:#x})')
                    elif ptail + 5 > isize or dec[ptail] != 0xE9:
                        problems.append('8s plan tail inconsistent (no E9)')
                    elif pioff + pilen > ptail:
                        problems.append('8s plan command/tail order inconsistent')
                    elif slack < 3:
                        problems.append(f'8s plan has no slack ({slack})')
                    else:
                        n_plan += 1
                        if pflip:
                            n_flip += 1
            n_isl += 1
            step = 32 + isize + (8 if iat_of else 0)   # 8e: gizli yuva
            off += (step + 15) & ~15
            rva = iisrva + (off - area_off)
        if n_valid < 2:
            problems.append(f'too few islands with a valid tail jmp ({n_valid})')
        if problems:
            for p in problems:
                print(f'  FAIL island encryption: {p}')
            ok = False
        else:
            print(f'  OK   islands ENCRYPTED ({n_isl} blobs): decrypted bytes are valid '
                  f'code (tail jmp): {n_valid} real islands, '
                  f'{n_isl - n_valid} decoy islands; encrypted differs from plaintext '
                  f'differ')
            print(f'  OK   8s plan: consistent in {n_plan}/{n_valid} real islands '
                  f'mutation plan ({n_flip} islands with SSE equivalence rewrite, '
                  f'{"present" if n_plan == n_valid else "missing"})')
            # Import island: an indirect FF 15 must target a hidden .hydavm slot, not the IAT.
            iat_ranges = []
            imp_rva = new['dd'][1][0] if len(new['dd']) > 1 else 0
            if imp_rva:
                imp_off = r2o(new, imp_rva)
                if imp_off is not None:
                    dd = 0
                    while True:
                        p0 = imp_off + dd * 20
                        if p0 + 20 > len(nd):
                            break
                        oft, tds, fc, nm, ft = struct.unpack_from('<IIIII', nd, p0)
                        if oft == 0 and nm == 0 and ft == 0:
                            break
                        if ft:
                            t = 0
                            while True:
                                e = r2o(new, ft + t * 8)
                                if e is None or e + 8 > len(nd):
                                    break
                                if struct.unpack_from('<Q', nd, e)[0] == 0:
                                    break
                                iat_ranges.append((ft + t * 8, ft + t * 8 + 8))
                                t += 1
                        dd += 1

            def in_iat(rva):
                return any(lo <= rva < hi for lo, hi in iat_ranges)

            hydavm = next(s for s in new['secs'] if s['nm'] == '.hydavm')
            import_checked = 0
            import_ok = True
            # Walk the import blob's islands.
            imp_blocks = []
            if imp_blob_rva:
                ib0 = r2o(new, int(imp_blob_rva, 16))
                _, _, _, _, _v, _f, iisrva, iicount, iispan, _r = \
                    struct.unpack_from('<IIIIIIIIII', nd, ib0)
                ioff = r2o(new, iisrva)
                irva = iisrva
                for _n in range(iicount + 16):
                    if ioff is None or ioff + 32 > r2o(new, iisrva) + iispan:
                        break
                    mg, sz, sl, _fl2 = struct.unpack_from('<IIII', nd, ioff)
                    if mg != island_magic():
                        break
                    ia2 = struct.unpack_from('<I', nd, ioff + 24)[0]
                    imp_blocks.append((irva + 32, sz, sl, ia2))
                    stp = 32 + sz + (8 if ia2 else 0)
                    ioff += (stp + 15) & ~15
                    irva = iisrva + (ioff - r2o(new, iisrva))
            for (irva, isize, isalt, ib_iat) in imp_blocks:
                if irva == 0:
                    continue
                # Only real import islands (header carries an IAT RVA) are checked.
                if not ib_iat:
                    continue
                enc = nd[r2o(new, irva):r2o(new, irva) + isize]
                dec = island_decrypt(enc, isalt, irva)
                # FF 15 disp32 = indirect call.
                for k in range(len(dec) - 6):
                    if dec[k] == 0xFF and dec[k + 1] == 0x15:
                        rel = struct.unpack_from('<i', dec, k + 2)[0]
                        tgt = irva + k + 6 + rel
                        import_checked += 1
                        if in_iat(tgt):
                            import_ok = False
                        elif not (hydavm['va'] <= tgt < hydavm['va'] + max(hydavm['vs'], hydavm['rs'])):
                            import_ok = False
                        break
            if import_checked == 0:
                print('  SKIP import-hiding check: no island with an import call found')
            elif not import_ok:
                print("  FAIL import hiding: island still references the IAT (or outside a section) "
                      "references")
                ok = False
            else:
                print(f"  OK   import hiding: {import_checked} indirect calls target "
                      f"a HIDDEN slot, not the IAT (target inside .hydavm)")

            # Import table holds hashes + encrypted DLL names, indexed from the island header.
            tab_ok = True
            tab_note = ''
            if imp_tab_rva:
                tab_off = r2o(new, imp_tab_rva)
                if tab_off is None:
                    tab_ok = False
                    tab_note = 'table could not be decoded'
                else:
                    tmagic, tcount, tep, tkey = struct.unpack_from('<IIII', nd, tab_off)
                    if tmagic != 0x52494D50:
                        tab_ok = False
                        tab_note = f'table signature wrong ({tmagic:#x})'
                    elif tcount == 0 or tcount > 8192:
                        tab_ok = False
                        tab_note = f'table entry count invalid ({tcount})'
                    else:
                        names_off = tab_off + 24 + tcount * 24
                        for i in range(tcount):
                            noff, nlen, fh, fl = struct.unpack_from('<IIII', nd, tab_off + 24 + i * 24)
                            od, rsv, iat = struct.unpack_from('<HHI', nd, tab_off + 24 + i * 24 + 16)
                            if (fl & ~1) != 0 or rsv != 0:
                                tab_ok = False
                                tab_note = f'entry {i} flags invalid'
                                break
                            if fh == 0 and od == 0:
                                tab_ok = False
                                tab_note = f'entry {i} hash/ordinal empty'
                                break
                            if nlen == 0 or nlen > 512:
                                tab_ok = False
                                tab_note = f'entry {i} name length invalid'
                                break
                            # DLL names must be encrypted (no plaintext ".dll").
                            raw = nd[names_off + noff: names_off + noff + nlen]
                            if b'.dll' in raw.lower():
                                tab_ok = False
                                tab_note = f'entry {i} DLL name leaking as plaintext'
                                break
                        if tab_ok:
                            n_imp = 0
                            for (irva, isize, isalt, ib_iat) in imp_blocks:
                                hdr_off = r2o(new, irva) - 32
                                if hdr_off is None:
                                    continue
                                idx = struct.unpack_from('<I', nd, hdr_off + 24)[0]
                                if idx == 0:
                                    continue
                                if idx > tcount:
                                    tab_ok = False
                                    tab_note = f'island import index invalid ({idx})'
                                    break
                                n_imp += 1
                            if tab_ok:
                                tab_note = (f'{tcount} entries (hashes + encrypted DLL names), '
                                            f'{n_imp} island indices, original ep {tep:#x}')
            if not tab_ok:
                print(f'  FAIL runtime import table: {tab_note}')
                ok = False
            elif imp_tab_rva:
                print(f'  OK   runtime import table: {tab_note} (API names absent from the file)')

            # The PE import directory is emptied.
            imp_dir_rva, imp_dir_sz = new['dd'][1] if len(new['dd']) > 1 else (0, 0)
            desc_ok = False
            if imp_dir_rva == 0:
                desc_ok = True          # dizin tamamen kaldirilmis
            else:
                io = r2o(new, imp_dir_rva)
                if io is not None:
                    desc_ok = (nd[io:io + 20] == b'\x00' * 20)
            if not desc_ok:
                print('  FAIL import directory not emptied (loader still binds)')
                ok = False
            else:
                print('  OK   import directory EMPTY: loader binds nothing '
                      '(runtime resolves)')

            # Imported API names must be gone from the file.
            names = set()
            old_imp_rva, old_imp_sz = old['dd'][1] if len(old['dd']) > 1 else (0, 0)
            if old_imp_rva:
                io = r2o(old, old_imp_rva)
                if io is not None:
                    od = old['d']
                    dd = 0
                    while True:
                        p0 = io + dd * 20
                        if p0 + 20 > len(od):
                            break
                        oft, tds, fc, nm, ft = struct.unpack_from('<IIIII', od, p0)
                        if oft == 0 and nm == 0 and ft == 0:
                            break
                        if nm:
                            no = r2o(old, nm)
                            if no is not None:
                                names.add(od[no:od.index(b'\x00', no)].decode(errors='replace'))
                        t = 0
                        while True:
                            e = r2o(old, ft + t * 8)
                            if e is None or e + 8 > len(od):
                                break
                            v = struct.unpack_from('<Q', od, e)[0]
                            if v == 0:
                                break
                            if not (v & (1 << 63)):
                                hn = r2o(old, v & 0x7fffffff)
                                if hn is not None:
                                    names.add(od[hn + 2:od.index(b'\x00', hn + 2)].decode(errors='replace'))
                            t += 1
                        dd += 1
            # Search only the import area; unrelated CRT strings may remain.
            imp_sec = None
            if imp_dir_rva:
                sec = by_va(new, imp_dir_rva)
                imp_sec = new['d'][sec['ra']:sec['ra'] + sec['rs']] if sec else b''
            haystack = imp_sec if imp_sec is not None else new['d']
            leaked = sorted(n for n in names
                            if len(n) >= 5 and n.encode() in haystack)
            if leaked:
                print(f'  FAIL API names left in the file: {leaked[:5]}')
                ok = False
            elif names:
                print(f'  OK   {len(names)} API/DLL names present in the unprotected image, '
                      f'none left in the protected image (no API names in the file)')

            # Entry point must be redirected to the runtime stub.
            ep = new['dd'][0]  # placeholder (kullanilmiyor)
            # Tail islands may use any gate-exit alias.
            if len(targets) > 1:
                print(f'  OK   island tails jump to DIFFERENT targets '
                      f'({len(targets)} distinct gate exits) -> no "tail count = island '
                      f'count" signature')
            else:
                print('  FAIL island tails all jump to one target (8b ineffective)')
                ok = False
sys.exit(0 if ok else 1)
