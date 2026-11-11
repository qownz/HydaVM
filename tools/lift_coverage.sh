#!/bin/sh
# Lifts a corpus of realistic functions and reports how many instructions end
# up as native islands instead of VM bytecode.
#
# Usage: tools/lift_coverage.sh <host-build-dir> [cc] [verbose]
set -eu

build=${1:?usage: lift_coverage.sh <build-dir> [cc] [verbose]}
cc=${2:-x86_64-w64-mingw32-gcc}
verbose=${3:-}

lifter=$build/hyda_lifter
root=$(cd "$(dirname "$0")/.." && pwd)
corpus=$root/tests/coverage_corpus.c
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

[ -x "$lifter" ] || { echo "error: $lifter is not built" >&2; exit 1; }

: >"$work/islands.txt"
: >"$work/funcs.txt"
: >"$work/failed.txt"

for opt in O0 O1 O2 O3 Os; do
  obj=$work/corpus-$opt.o
  "$cc" -"$opt" -fno-ipa-cp-clone -c "$corpus" -o "$obj"

  for sec in $(x86_64-w64-mingw32-objdump -h "$obj" |
               awk '$2 ~ /^hydafn_/ {print $2}'); do
    bin=$work/$sec-$opt.bin
    out=$work/lift.txt
    x86_64-w64-mingw32-objcopy -O binary --only-section="$sec" "$obj" "$bin"

    if ! "$lifter" "$bin" 0x140001000 >"$out" 2>&1; then
      echo "$opt ${sec#hydafn_}" >>"$work/failed.txt"
      continue
    fi

    insns=$(sed -n 's/^decoded    : //p' "$out")
    islands=$(sed -n 's/^islands    : //p' "$out")
    echo "$opt ${sec#hydafn_} $insns $islands" >>"$work/funcs.txt"
    if [ -n "$verbose" ]; then
      printf '%-3s %-24s %4s x86 -> %2s islands\n' \
        "$opt" "${sec#hydafn_}" "$insns" "$islands"
    fi

    sed -n '/^islands    : /,/^bytecode   :/p' "$out" |
      sed -n 's/^    0x[0-9a-f]*  *\([a-z0-9]*\) .*$/\1/p' |
      sed "s/^/$opt\t${sec#hydafn_}\t/" >>"$work/islands.txt"
  done
done

nfuncs=$(grep -c . "$work/funcs.txt" || true)
nislands=$(grep -c . "$work/islands.txt" || true)
ninsns=$(awk '{s += $3} END {print s + 0}' "$work/funcs.txt")

if [ -s "$work/failed.txt" ]; then
  echo "lift failures:"
  sed 's/^/  /' "$work/failed.txt"
  echo
fi

echo "corpus: $nfuncs lift(s), $ninsns instructions, $nislands islands"
if [ "$nislands" -eq 0 ]; then
  echo "every corpus instruction compiles to VM bytecode"
  exit 0
fi

echo
echo "islanded mnemonics:"
cut -f3 "$work/islands.txt" | sort | uniq -c | sort -rn

echo
echo "functions with islands:"
awk '$4 > 0 {printf "  %-3s %-24s %s\n", $1, $2, $4}' "$work/funcs.txt"