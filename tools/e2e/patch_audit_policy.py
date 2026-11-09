import struct, sys
d = bytearray(open(sys.argv[1], 'rb').read())
pe = struct.unpack_from('<I', d, 0x3c)[0]
cof = pe + 4; opt = cof + 20
optsz = struct.unpack_from('<H', d, cof + 16)[0]
nsec = struct.unpack_from('<H', d, cof + 2)[0]
so = opt + optsz
rva = int(sys.argv[3], 16)
for i in range(nsec):
    s = so + i * 40
    vs, va, rs, ra = struct.unpack_from('<IIII', d, s + 8)
    if va <= rva < va + max(vs, rs):
        struct.pack_into('<I', d, ra + (rva - va), 0)  # period = 0
        open(sys.argv[2], 'wb').write(d)
        sys.exit(0)
sys.exit(1)
