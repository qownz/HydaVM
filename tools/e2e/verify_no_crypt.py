import struct, sys

def load(path):
    return open(path, 'rb').read()

def hydavm_sec(d):
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    st = pe + 24 + optsz
    for i in range(nsec):
        off = st + i * 40
        nm = d[off:off + 8].rstrip(b'\0').decode('latin1')
        if nm == '.hydavm':
            _, va, _, ra = struct.unpack_from('<IIII', d, off + 8)
            return va, ra
    return None

# BlobHeader is 48 bytes (see hyda/codec/blob.hpp).
BLOB_HDR = 48

def blob(d, sec, rva):
    va, ra = sec
    off = ra + (rva - va)
    f = struct.unpack_from('<IIIIII', d, off)
    return f, d[off + BLOB_HDR:off + BLOB_HDR + f[1]]

e = load(sys.argv[1]); n = load(sys.argv[2])
sec_e = hydavm_sec(e); sec_n = hydavm_sec(n)
if sec_e is None or sec_n is None:
    print('  FAIL .hydavm section not found'); sys.exit(1)

he_s, cb_s = blob(e, sec_e, int(sys.argv[3], 16))
hn_s, cn_s = blob(n, sec_n, int(sys.argv[5], 16))
he_m, cb_m = blob(e, sec_e, int(sys.argv[4], 16))
hn_m, cn_m = blob(n, sec_n, int(sys.argv[6], 16))

ok = True
# Exempt blob: flag set; its encrypted twin shares almost no bytes.
if hn_s[5] != 1:
    print(f'  FAIL exempt blob flag wrong: {hn_s[5]:#x}'); ok = False
elif he_s[5] != 2:
    print(f'  FAIL non-exempt blob must carry the identity flag: {he_s[5]:#x}')
    ok = False
elif hn_s[1] != he_s[1]:
    print('  FAIL exempt blob size differs from the encrypted image'); ok = False
else:
    cs = he_s[1]
    same = sum(1 for a, b in zip(cb_s, cn_s) if a == b)
    frac = 100.0 * same / cs
    if frac <= 10.0:
        print(f"  OK   exempt blob (hydafn_sse) plaintext: flag={hn_s[5]:#x}, "
              f"encrypted copy differs from plaintext ({same}/{cs} = "
              f"%{frac:.1f} shared; 8p: opcode + operand stream; "
              f"CRC {he_s[3]:#x} -> {hn_s[3]:#x})")
    else:
        print(f'  FAIL 8p opcode stream ineffective: encrypted and plaintext '
              f'%{frac:.1f} shared bytes'); ok = False

# (c) non-exempt blobs are byte-identical in both images.
if cb_m != cn_m or he_m != hn_m:
    print('  FAIL --no-crypt should affect only the selected blob '
          '(hydafn_muladd changed)'); ok = False
else:
    print(f"  OK   --no-crypt affected only the selected blob: hydafn_muladd "
          f"byte-identical in both images ({len(cb_m)} bytes, flag={he_m[5]:#x})")
sys.exit(0 if ok else 1)
