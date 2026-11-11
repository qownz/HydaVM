import struct
import sys

if len(sys.argv) != 4:
    print("usage: shrink_section.py <in.exe> <out.exe> <section>")
    sys.exit(2)

data = bytearray(open(sys.argv[1], 'rb').read())
pe = struct.unpack_from('<I', data, 0x3c)[0]
cof = pe + 4
opt = cof + 20
optsz = struct.unpack_from('<H', data, cof + 16)[0]
nsec = struct.unpack_from('<H', data, cof + 2)[0]
table = opt + optsz
nsym = struct.unpack_from('<I', data, cof + 12)[0]
symtab = struct.unpack_from('<I', data, cof + 8)[0]
strtab = symtab + nsym * 18


def section_name(at):
    raw = data[at:at + 8].rstrip(b'\0').decode('latin1')
    if not raw.startswith('/'):
        return raw
    off = int(raw[1:])
    end = data.index(b'\0', strtab + off)
    return data[strtab + off:end].decode('latin1')


want = sys.argv[3]
hits = 0
for i in range(nsec):
    at = table + i * 40
    name = section_name(at)
    if want == '*':
        if not name.startswith('hydafn_'):
            continue
    elif name != want:
        continue
    struct.pack_into('<I', data, at + 8, 4)
    hits += 1

if hits == 0:
    print("section not found: " + want)
    sys.exit(1)
open(sys.argv[2], 'wb').write(bytes(data))