#!/bin/sh
# Lifts every function of HydaVM's own sources (built for Windows) and reports
# which instructions stay native islands, so coverage work follows real code.
#
# Usage: tools/lift_real.sh <host-build-dir> [cc] [opt-level]
set -eu

build=${1:?usage: lift_real.sh <build-dir> [cc] [opt]}
cc=${2:-x86_64-w64-mingw32-g++}
opt=${3:-O2}

lifter=$build/hyda_lifter
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

[ -x "$lifter" ] || { echo "error: $lifter is not built" >&2; exit 1; }

: >"$work/islands.txt"
: >"$work/funcs.txt"
: >"$work/failed.txt"

for src in $(find "$root/src" -name '*.cpp' | sort); do
  obj=$work/fn.o
  bin=$work/fn.bin
  if ! "$cc" "-$opt" -ffunction-sections -fno-ipa-cp-clone \
       -I"$root/include" -c "$src" -o "$obj" 2>/dev/null; then
    echo "$src (compile skipped)" >>"$work/failed.txt"
    continue
  fi

  for sec in $(x86_64-w64-mingw32-objdump -h "$obj" |
               awk '$2 ~ /^\.text\$/ {print $2}'); do
    x86_64-w64-mingw32-objcopy -O binary --only-section="$sec" "$obj" "$bin"
    [ -s "$bin" ] || continue
    name=$(printf '%s' "${sec}" | sed 's/^\.text\$//' | c++filt |
             sed 's/(.*//; s/ /_/g')
    out=$work/lift.txt

    if ! "$lifter" "$bin" 0x140001000 >"$out" 2>&1; then
      echo "$opt $name" >>"$work/failed.txt"
      continue
    fi

    insns=$(sed -n 's/^decoded    : //p' "$out")
    islands=$(sed -n 's/^islands    : //p' "$out")
    echo "$opt $name $insns $islands" >>"$work/funcs.txt"
    sed -n '/^islands    : /,/^bytecode   :/p' "$out" |
      sed -n 's/^    0x[0-9a-f]*  *\([a-z0-9]*\) \(.*\)$/\1\t\2/p' |
      sed "s|^|$opt\t$name\t|" >>"$work/islands.txt"
  done
done

n=$(grep -c . "$work/funcs.txt" || true)
bad=$(grep -c . "$work/failed.txt" || true)
islands=$(grep -c . "$work/islands.txt" || true)
insns=$(awk '{s += $3} END {print s + 0}' "$work/funcs.txt")

echo "corpus      : HydaVM src/*.cpp at -$opt"
echo "functions   : $n lifted, $bad not liftable"
echo "instructions: $insns"
echo "islands     : $islands ($(awk -v i="$islands" -v n="$insns" 'BEGIN{printf "%.2f", (n ? 100*i/n : 0)}')% of instructions)"
if [ "$islands" -eq 0 ]; then
  exit 0
fi

echo
echo "islanded mnemonics:"
cut -f3 "$work/islands.txt" | sort | uniq -c | sort -rn | head -20

echo
echo "most common islanded instructions:"
cut -f3,4 "$work/islands.txt" | sort | uniq -c | sort -rn | head -12 | sed 's/^/  /'

echo
echo "functions with the most islands:"
awk '$4 > 0 {printf "%s %s\n", $4, $2}' "$work/funcs.txt" |
  sort -rn | head -12 | sed 's/^/  /'