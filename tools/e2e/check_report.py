import json
import struct
import sys

report = json.load(open(sys.argv[1]))
exe = open(sys.argv[2], 'rb').read()
mode = sys.argv[3]

pe = struct.unpack_from('<I', exe, 0x3c)[0]
cof = pe + 4
opt = cof + 20
optsz = struct.unpack_from('<H', exe, cof + 16)[0]
nsec = struct.unpack_from('<H', exe, cof + 2)[0]
table = opt + optsz
nsym = struct.unpack_from('<I', exe, cof + 12)[0]
symtab = struct.unpack_from('<I', exe, cof + 8)[0]
strtab = symtab + nsym * 18


def section_name(at):
    raw = exe[at:at + 8].rstrip(b'\0').decode('latin1')
    if not raw.startswith('/'):
        return raw
    off = int(raw[1:])
    end = exe.index(b'\0', strtab + off)
    return exe[strtab + off:end].decode('latin1')


names = set()
for i in range(nsec):
    at = table + i * 40
    name = section_name(at)
    if name.startswith('hydafn_'):
        names.add(name)

protected = {f['name'] for f in report['functions']}
skipped = {s['name'] for s in report['skipped']}

if report['totals']['protected'] != len(report['functions']):
    sys.exit("totals.protected disagrees with the function list")
if report['totals']['skipped'] != len(report['skipped']):
    sys.exit("totals.skipped disagrees with the skip list")
if protected & skipped:
    sys.exit("a function is both protected and skipped")

if mode == 'protected':
    if protected | skipped != names:
        sys.exit("report does not cover every hydafn_* section")
    if report.get('identities', 0) != len(protected):
        sys.exit("every encrypted function needs its own dispatch identity")
    if protected != names - skipped:
        sys.exit("protected set %s != sections %s" % (sorted(protected), sorted(names)))
    for f in report['functions']:
        if f['x86_bytes'] == 0 or f['bytecode_bytes'] == 0:
            sys.exit("empty size for " + f['name'])
        if f['opcodes'] == 0 or not f['encrypted']:
            sys.exit("missing opcode/encryption data for " + f['name'])
elif mode == 'eh':
    for want in ('hydafn_throw', 'hydafn_catch'):
        if want not in skipped:
            sys.exit(want + " should have been skipped (C++ exceptions)")
        if want in protected:
            sys.exit(want + " was virtualized despite using exceptions")
    reasons = {s['name']: s['reason'] for s in report['skipped']}
    for name in ('hydafn_throw', 'hydafn_catch'):
        low = reasons[name].lower()
        if 'exception' not in low and 'throw' not in low:
            sys.exit("skip reason for %s does not mention exceptions: %s"
                     % (name, reasons[name]))
    if not names - skipped:
        sys.exit("nothing left to protect")
elif mode == 'skipped':
    if 'hydafn_mix32' not in skipped:
        sys.exit("hydafn_mix32 not reported as skipped")
    if 'hydafn_mix32' in protected:
        sys.exit("hydafn_mix32 was protected despite being unprotectable")
    if not names - skipped:
        sys.exit("nothing left to protect")
else:
    sys.exit("unknown mode " + mode)
