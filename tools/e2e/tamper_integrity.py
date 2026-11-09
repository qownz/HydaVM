import struct, sys
d = bytearray(open(sys.argv[1], 'rb').read())
pe = struct.unpack_from('<I', d, 0x3c)[0]
cof = pe + 4; opt = cof + 20
optsz = struct.unpack_from('<H', d, cof + 16)[0]
nsec = struct.unpack_from('<H', d, cof + 2)[0]
so = opt + optsz
for i in range(nsec):
    s = so + i * 40
    nm = d[s:s+8].rstrip(b'\0').decode('latin1')
    vs, va, rs, ra = struct.unpack_from('<IIII', d, s + 8)
    # Find a string in .rdata and corrupt one byte.
    if nm == '.rdata':
        j = bytes(d[ra:ra + rs]).find(b'PE target')
        if j >= 0:
            d[ra + j] = ord('X')
            open(sys.argv[2], 'wb').write(bytes(d))
            print(f'  (bozulan yer: raw {ra + j:#x})')
            sys.exit(0)
print('  (target string not found)'); sys.exit(1)
