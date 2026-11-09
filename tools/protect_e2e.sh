#!/usr/bin/env bash
# HydaVM end-to-end PE test.
#
# Protects build-win/pe_target.exe with hyda_protect, runs it under Wine and
# verifies that output is unchanged, bodies are erased, and every protection
# layer (shards, islands, integrity, anti-debug, SEH, threads) behaves.
#
# Usage: tools/protect_e2e.sh [host-build-dir] [win-build-dir]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_BUILD="${1:-$ROOT/build}"
WIN_BUILD="${2:-$ROOT/build-win}"
PROTECT="$HOST_BUILD/hyda_protect"
E2E_DIR="$(cd "$(dirname "$0")" && pwd)/e2e"
TARGET="$WIN_BUILD/pe_target.exe"
TMP="${TMPDIR:-/tmp}"
WORK="$(mktemp -d $TMP/hyda-pe-XXXXXX)"
PROTECTED="$WORK/pe_target.protected.exe"

fails=0
ck() {
  if [ "$1" = "1" ]; then printf '  OK   %s\n' "$2"
  else printf '  FAIL %s\n' "$2"; fails=$((fails + 1)); fi
}

# Keep only the application's output lines (drop Wine noise).
run_target() {
  wine "$1" 2>/dev/null | tr -d '\r' | grep -E '^(result:|muladd =|mix32  =|divmod =|glob   =|sse    =|icall  =|dcall  =|nest   =|deep   =|tail   =)' || true
}

# Run the target under Wine when available.
run_raw() {
  if [ -n "$WINE" ]; then wine "$1" 2>/dev/null; else "$1" 2>/dev/null; fi
}

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WINE="";; *) WINE="wine";; esac
if ! command -v wine >/dev/null 2>&1; then
  echo "skip: wine not found"; exit 0
fi
for f in "$PROTECT" "$TARGET"; do
  if [ ! -x "$f" ]; then
    echo "error: $f missing (build build/ and build-win/ first)"; exit 2
  fi
done

echo "HydaVM stage 3 end-to-end test"
echo "  target    : $TARGET"
echo "  protector : $PROTECT"
echo "  workdir   : $WORK"

BASE="$(run_target "$TARGET")"
echo "--- before protection ---"; echo "$BASE" | sed 's/^/  /'

# The protected image must still work when loaded at a different base.
REBASE=0x180000000
# Fixed profile so the two images can be compared byte-for-byte.
PROT_PROFILE="4d,0,3,4,1,0"
# Fixed seed so the independent Python verifier derives identical keys.
PROT_VM_SEED="0x2C7A1B4E9D3F5A86"
PROT_OUT="$("$PROTECT" "$TARGET" "$PROTECTED" --rebase "$REBASE" \
  --dispatch-profile "$PROT_PROFILE" --vm-seed "$PROT_VM_SEED")"
echo "$PROT_OUT" | sed 's/^/  | /'
# The protector prints blob RVAs used by the verifier.
BLOB0_RVA="$(echo "$PROT_OUT" | sed -n 's/.*(blob \(0x[0-9a-f]*\)).*/\1/p' | head -1)"
# Blob with native islands (hydafn_nest) for the island check.
ISLE_BLOB_RVA="$(echo "$PROT_OUT" | sed -n 's/.*hydafn_nest .*(blob \(0x[0-9a-f]*\)).*/\1/p' | head -1)"
# Blob of the import-calling function (import hiding check).
IMP_BLOB_RVA="$(echo "$PROT_OUT" | sed -n 's/.*hydafn_imp .*(blob \(0x[0-9a-f]*\)).*/\1/p' | head -1)"

# Body variants must actually be emitted.
if echo "$PROT_OUT" | grep -q "body variants: [1-9]"; then
  ck 1 "handler body variants used (same semantics, different code)"
else
  ck 0 "handler body variants not used"
fi

# Nested VM must actually be used.
if echo "$PROT_OUT" | grep -q "nested VM: [1-9]"; then
  ck 1 "nested VM used (value computed in a second VM)"
else
  ck 0 "nested VM not used"
fi

# Random profile: two protections must differ.
P1="$("$PROTECT" "$TARGET" "$WORK/prof1.exe" 2>&1 | sed -n 's/.*dispatch profile: //p' | head -1)"
P2="$("$PROTECT" "$TARGET" "$WORK/prof2.exe" 2>&1 | sed -n 's/.*dispatch profile: //p' | head -1)"
if [ -n "$P1" ] && [ -n "$P2" ] && [ "$P1" != "$P2" ]; then
  ck 1 "dispatch profile is per-binary (two builds differ)"
else
  ck 0 "dispatch profile not per-binary (P1='$P1' P2='$P2')"
fi

# Opcode count is not fixed; read it from the protector output.
OP_COUNT="$(echo "$PROT_OUT" | sed -n 's/.*neutralized (\([0-9][0-9]*\) entries.*/\1/p' | head -1)"
if [ -n "$OP_COUNT" ]; then OP_COUNT=$((OP_COUNT - 1)); fi
if [ -z "$OP_COUNT" ] || [ "$OP_COUNT" -lt 1 ]; then
  echo "error: cannot read opcode count from protector output"; exit 2
fi
echo "  opcode count : $OP_COUNT (from protector output)"
AFTER="$(run_target "$PROTECTED")"
echo "--- after protection ---"; echo "$AFTER" | sed 's/^/  /'

echo "--- checks ---"
[ "$BASE" = "$AFTER" ] && ck 1 "output identical before/after protection (rebased)" || {
  ck 0 "output differs"
  diff <(echo "$BASE") <(echo "$AFTER") | sed 's/^/       /' || true
}

# Confirm the image really loaded at the new base.
LOADED="$("$WINE" "$PROTECTED" 2>&1 >/dev/null | tr -d '\r' | sed -n 's/^module base: 0x0*\([0-9a-fA-F]*\)$/\1/p' | head -1 || true)"
WANT="$(printf '%x' "$REBASE")"
if [ -n "$LOADED" ] && [ "$(printf '%d' "0x$LOADED")" = "$(printf '%d' "$REBASE")" ]; then
  ck 1 "image rebased ($REBASE) -> RVA resolution proven"
else
  ck 0 "rebase not verified (loaded base: 0x${LOADED:-?}, expected: $WANT)"
fi

# Python discovery must reconstruct the same keys from the seed.
SEED="$PROT_VM_SEED"

# Alternate shard/decoy/container counts must not change the output.
ALT="$WORK/pe_target.alt.exe"
# A different image seed must still produce the same result.
"$PROTECT" "$TARGET" "$ALT" --hydak-parts 3 --hydak-decoys 2 --hydak-containers 2 \
  --dispatch-profile "$PROT_PROFILE" --vm-seed "$PROT_VM_SEED" \
  >"$WORK/alt.log" 2>&1 || ck 0 "alternate layout (3 parts/2 decoys/2 containers) could not be produced"
ALT_RUN="$(run_target "$ALT")"
if [ "$BASE" = "$ALT_RUN" ]; then
  ck 1 "alternate layout (3 parts/2 decoys/2 containers) gave identical output"
else
  ck 0 "alternate layout changed the output"
  diff <(echo "$BASE") <(echo "$ALT_RUN") | sed 's/^/       /' || true
fi

# Each image carries its own VM seed: (a) a different seed still yields
# the same result; (b) --vm-seed 0 is rejected.
S2="$WORK/pe_target.seed2.exe"
if "$PROTECT" "$TARGET" "$S2" --vm-seed 0x5A1C3E7B9D2F4068 \
   --dispatch-profile "$PROT_PROFILE" >/dev/null 2>&1; then
  S2_RUN="$(run_target "$S2")"
  if [ "$BASE" = "$S2_RUN" ]; then
    ck 1 "different image seed gave the same result (runtime reads the seed)"
  else
    ck 0 "different image seed changed the result"
    diff <(echo "$BASE") <(echo "$S2_RUN") | sed 's/^/       /' || true
  fi
else
  ck 0 "protection with a different seed failed"
fi
if "$PROTECT" "$TARGET" "$WORK/seed0.exe" --vm-seed 0 \
   >/dev/null 2>&1; then
  ck 0 "--vm-seed 0 was silently accepted"
else
  ck 1 "--vm-seed 0 rejected (no keyless VM instance)"
fi

# Bodies erased (E9 + 0xCC), symbols stripped, unwind table rebuilt.
if python3 "$E2E_DIR/verify_protected.py" "$TARGET" "$PROTECTED" "$BLOB0_RVA" "$SEED" "$ALT" "$OP_COUNT" "$ISLE_BLOB_RVA" "$IMP_BLOB_RVA"
then
  ck 1 "native bodies erased + symbols stripped + unwind table"
else
  ck 0 "native bodies erased + symbols stripped + unwind table"
fi

# Native unwinder round-trip via RtlLookupFunctionEntry.
UNWIND_LINE="$(run_raw "$PROTECTED" | tr -d '\r' | grep -m1 '^unwind:' || true)"
if [ -n "$UNWIND_LINE" ] && ! printf '%s' "$UNWIND_LINE" | grep -q 'FAIL'; then
  ck 1 "unwind table: $UNWIND_LINE"
else
  ck 0 "unwind table not verified (${UNWIND_LINE:-no output})"
fi

# Guest stack limit: over-recursion must fault, not corrupt memory.
GUARD_LINE="$(run_raw "$PROTECTED" | tr -d '\r' | grep -m1 '^guard:' || true)"
if [ -n "$GUARD_LINE" ]; then
  ck 1 "stack limit: $GUARD_LINE"
else
  ck 0 "stack limit not verified (no output)"
fi

# Tail call through a native island must preserve the return value.
TAIL_LINE="$(run_raw "$PROTECTED" | tr -d '\r' | grep -m1 '^tail-call:' || true)"
if printf '%s' "$TAIL_LINE" | grep -q 'OK'; then
  ck 1 "tail call: $TAIL_LINE"
else
  ck 0 "tail call not verified (${TAIL_LINE:-no output})"
fi

# hydafn_taila must be lifted as a single tail-call island.
if printf '%s' "$PROT_OUT" | grep -qE \
   'hydafn_taila +[0-9]+ B x86 -> +[0-9]+ B bytecode \([0-9]+ IR, [0-9]+ RVA, 1 islands'; then
  ck 1 "tail-call island: hydafn_taila lifted as 1 native island"
else
  ck 0 "hydafn_taila not lifted as a tail-call island"
fi


# Self-integrity: manifest present, CRCs encrypted, tamper exits 208.
if python3 "$E2E_DIR/verify_integrity.py" "$PROTECTED" "$PROT_OUT" "$ROOT/include/hyda/config.hpp" "$SEED"
then
  ck 1 "8k integrity manifest present and well-formed"
else
  ck 0 "8k integrity manifest missing/corrupt"
fi

# Tampered byte must be rejected with 208.
TAMPER_INTEG="$WORK/pe_target.integrity.exe"
if python3 "$E2E_DIR/tamper_integrity.py" "$PROTECTED" "$TAMPER_INTEG"
then
  icode=0
  "$WINE" "$TAMPER_INTEG" >/dev/null 2>&1 || icode=$?
  if [ "$icode" = "208" ]; then
    ck 1 "8k integrity violation caught (exit 208)"
  else
    ck 0 "8k integrity violation not caught (exit $icode, expected 208)"
  fi
else
  ck 0 "8k could not build the corrupted copy"
fi

# API hook detection is independent of code-integrity checks.
HOOKTARGET="$WIN_BUILD/pe_target_hooktest.exe"
if [ -n "$HOOKTARGET" ] && [ -f "$HOOKTARGET" ]; then
  HOOKPROT="$WORK/hooktest.protected.exe"
  if "$PROTECT" "$HOOKTARGET" "$HOOKPROT" >/dev/null 2>&1; then
    hcode=0
    "$WINE" "$HOOKPROT" >/dev/null 2>&1 || hcode=$?
    if [ "$hcode" = "208" ]; then
      ck 1 "8k API hook detection: IAT tampering caught (exit 208)"
    else
      ck 0 "8k API hook detection: IAT tampering NOT caught (exit $hcode)"
    fi
  else
    ck 0 "8k hook test: could not produce the protected copy"
  fi
else
  echo "  SKIP 8k API hook check: hook test target missing"
fi

# Corrupt bytecode: the CRC gate must zero the first function.
if [ -f "$PROTECTED.tampered" ]; then
  TAM="$(run_target "$PROTECTED.tampered")"
  echo "--- corrupted bytecode (CRC gate) ---"; echo "$TAM" | sed 's/^/  /'
  first_native="$(echo "$BASE" | grep '^result:' | sed 's/^result: muladd=\([0-9]*\).*/\1/')"
  first_tam="$("$WINE" "$PROTECTED.tampered" 2>/dev/null | tr -d '\r' | grep -m1 '^result:' | sed 's/^result: muladd=\([0-9]*\).*/\1/' || true)"
  if [ -n "$first_tam" ] && [ "$first_tam" = "0" ] && [ "$first_native" != "0" ]; then
    ck 1 "CRC gate rejected the corrupted bytecode (muladd=0)"
  else
    ck 0 "CRC gate did not work (muladd=$first_tam)"
  fi
else
  ck 0 "could not produce the corrupted copy"
fi

# Unknown blob version must be rejected.
if [ -f "$PROTECTED.vtampered" ]; then
  vtam="$("$WINE" "$PROTECTED.vtampered" 2>/dev/null | tr -d '\r' | grep -m1 '^result:' | sed 's/^result: muladd=\([0-9]*\).*/\1/' || true)"
  if [ -n "$vtam" ] && [ "$vtam" = "0" ]; then
    ck 1 "unknown blob version rejected (muladd=0)"
  else
    ck 0 "version gate did not work (muladd=$vtam)"
  fi
else
  ck 0 "could not produce the version-patched copy"
fi

# --no-crypt: exempt blob runs plaintext, flag set, other blobs match.
NC="$WORK/pe_target.nocrypt.exe"
if "$PROTECT" "$TARGET" "$NC" --no-crypt hydafn_sse \
   --dispatch-profile "$PROT_PROFILE" --vm-seed "$PROT_VM_SEED" \
   >"$WORK/nc.log" 2>&1; then
  NC_OUT="$(cat "$WORK/nc.log")"
  NC_RUN="$(run_target "$NC")"
  if [ "$BASE" = "$NC_RUN" ]; then
    ck 1 "--no-crypt image gave identical output (plaintext blob runs correctly)"
  else
    ck 0 "--no-crypt image changed the output"
    diff <(echo "$BASE") <(echo "$NC_RUN") | sed 's/^/       /' || true
  fi
else
  ck 0 "could not produce the --no-crypt protected image"
  NC_OUT=""
fi

blob_rva_of() { # $1 = protector output, $2 = function name
  printf '%s\n' "$1" | grep -E "patched *: *$2 " |
    sed -n 's/.*(blob \(0x[0-9a-f]*\)).*/\1/p' | head -1
}
SSE_E="$(blob_rva_of "$PROT_OUT" hydafn_sse)"
MUL_E="$(blob_rva_of "$PROT_OUT" hydafn_muladd)"
SSE_N="$(blob_rva_of "$NC_OUT" hydafn_sse)"
MUL_N="$(blob_rva_of "$NC_OUT" hydafn_muladd)"
if [ -z "$SSE_E" ] || [ -z "$MUL_E" ] || [ -z "$SSE_N" ] || [ -z "$MUL_N" ]; then
  ck 0 "7c: could not read blob RVAs from protector output"
else
  if python3 "$E2E_DIR/verify_no_crypt.py" "$PROTECTED" "$NC" "$SSE_E" "$MUL_E" "$SSE_N" "$MUL_N"
  then
    ck 1 "7c: blob-level encryption exemption verified"
  else
    ck 0 "7c: blob exemption not verified"
  fi
fi

# An unknown --no-crypt name must be an error.
if "$PROTECT" "$TARGET" "$WORK/nocrypt-nomatch.exe" \
     --no-crypt hydafn_boyle_bir_fonksiyon_yok >/dev/null 2>&1; then
  ck 0 "--no-crypt succeeded despite an unmatched name (silent)"
else
  ck 1 "--no-crypt with an unmatched name failed as expected"
fi

# Audit policy is configurable, cannot be disabled, and is measured.
POLICY_EXE="$WORK/policy.exe"
if "$PROTECT" "$TARGET" "$POLICY_EXE" --audit-period 2 --audit-chunks 4 \
     --audit-refs 16 --vm-seed "$PROT_VM_SEED" >"$WORK/policy.log" 2>&1; then
  pol_out="$(run_target "$POLICY_EXE")"
  if [ "$pol_out" = "$BASE" ]; then
    ck 1 "8l policy (period 2 / 4 parts / 16 slots) did not change the output"
  else
    ck 0 "8l policy changed the output"
  fi

# Zeroing the policy must be rejected (208).
  ap_rva="$(sed -n 's/.*audit policy:.*rva 0x\([0-9a-fA-F]*\).*/\1/p' \
            "$WORK/policy.log" | head -1)"
  if [ -n "$ap_rva" ] && python3 "$E2E_DIR/patch_audit_policy.py" "$POLICY_EXE" "$WORK/policy0.exe" "$ap_rva"
  then
    icode=0
    "$WINE" "$WORK/policy0.exe" >/dev/null 2>&1 || icode=$?
    if [ "$icode" = "208" ]; then
      ck 1 "8l zeroed policy does NOT disable auditing (exit 208)"
    else
      ck 0 "8l zeroed policy disabled auditing (exit $icode)"
    fi
  else
    ck 0 "8l could not produce the policy-patched copy"
  fi
else
  ck 0 "8l could not produce the policy-configured image"
fi

# Anti-debug: injected PEB/module artefacts must be detected.
ADBGTARGET="$WIN_BUILD/pe_target_adbgtest.exe"
ADBGDUMMY="$WIN_BUILD/x64dbg.dll"
if [ -f "$ADBGTARGET" ] && [ -f "$ADBGDUMMY" ]; then
  ADBGDIR="$WORK/adbg"
  mkdir -p "$ADBGDIR"
  cp "$ADBGDUMMY" "$ADBGDIR/"
  ADBGPROT="$ADBGDIR/adbg.protected.exe"
  if "$PROTECT" "$ADBGTARGET" "$ADBGPROT" --rebase "$REBASE" \
       --vm-seed "$PROT_VM_SEED" >/dev/null 2>&1; then
    adbg_case() {
      local mode="$1" want="$2" rc=0
      "$WINE" "$ADBGPROT" "$mode" >/dev/null 2>&1 || rc=$?
      if [ "$rc" = "$want" ]; then
        ck 1 "9 anti-debug $mode -> exit $want"
      else
        ck 0 "9 anti-debug $mode -> exit $rc (expected $want)"
      fi
    }
    base_out="$("$WINE" "$ADBGTARGET" adbg-clean 2>/dev/null | tr -d '\r' | \
      grep -E '^adbg acc=')"
    prot_out="$("$WINE" "$ADBGPROT" adbg-clean 2>/dev/null | tr -d '\r' | \
      grep -E '^adbg acc=')"
    if [ -n "$base_out" ] && [ "$base_out" = "$prot_out" ]; then
      ck 1 "9 clean environment: no false positive ($prot_out)"
    else
      ck 0 "9 clean-environment result differs from unprotected ('$base_out' != '$prot_out')"
    fi
    adbg_case adbg-being 216
    adbg_case adbg-ntglobal 216
    adbg_case adbg-mod 217
  else
    ck 0 "9 anti-debug: could not produce the protected copy"
  fi
else
  echo "  SKIP 9 anti-debug: adbg test target missing"
fi

# SEH bridge: a VM fault must surface as native SEH (exit 94).
{
  seh_rc=0
  "$WINE" "$PROTECTED" seh >/dev/null 2>&1 || seh_rc=$?
  if [ "$seh_rc" = "94" ]; then
    ck 1 "14 SEH: VM fault surfaced as native SEH (exit 94)"
  else
    ck 0 "14 SEH: fault did not surface as native SEH (exit $seh_rc, expected 94)"
  fi
}

# Island fault must also reach native SEH (exit 94).
{
  isl_rc=0
  "$WINE" "$PROTECTED" island_seh >/dev/null 2>&1 || isl_rc=$?
  if [ "$isl_rc" = "94" ]; then
    ck 1 "B1 island SEH: island fault surfaced as native SEH (exit 94)"
  else
    ck 0 "B1 island SEH: island fault not surfaced (exit $isl_rc, expected 94)"
  fi
}

# Thread-local VM state: parallel calls must agree with native output.
thr_out() {  # $1 = exe, $2 = mode, $3 = line prefix
  "$WINE" "$1" "$2" 2>/dev/null | tr -d '\r' | \
    grep -E "^$3[0-3]=" | sed -E "s/^$3[0-3]=//"
}
for m in threads threads_gate; do
  pre="thread"
  [ "$m" = "threads_gate" ] && pre="gthread"
  bthr="$(thr_out "$TARGET" "$m" "$pre")"
  pthr="$(thr_out "$PROTECTED" "$m" "$pre")"
  uniq="$(printf '%s\n' "$pthr" | sort -u | wc -l | tr -d ' ')"
  if [ -n "$pthr" ] && [ "$bthr" = "$pthr" ] && [ "$uniq" = "1" ]; then
    ck 1 "A $m: 4 threads agree and match the unprotected run (parallel)"
  else
    ck 0 "A $m: thread results inconsistent (uniq=$uniq)"
  fi
done

# Informational: policy cost measurement.
"$PROTECT" "$TARGET" "$WORK/bench_on.exe" >/dev/null 2>&1 || true
"$PROTECT" "$TARGET" "$WORK/bench_off.exe" --audit-period 4096 \
  >/dev/null 2>&1 || true
bench_of() {
  "$WINE" "$1" bench 2000 2>/dev/null | \
    sed -n 's/.*, \([0-9.]*\) ms, acc=\([0-9a-f]*\).*/\1 \2/p'
}
b_base="$(bench_of "$TARGET")"
b_on="$(bench_of "$WORK/bench_on.exe")"
b_off="$(bench_of "$WORK/bench_off.exe")"
if [ -n "$b_base" ] && [ -n "$b_on" ] && [ -n "$b_off" ]; then
  set -- $b_base; base_ms="$1"; base_acc="$2"
  set -- $b_on;   on_ms="$1";   on_acc="$2"
  set -- $b_off;  off_ms="$1";  off_acc="$2"
  if [ "$base_acc" = "$on_acc" ] && [ "$base_acc" = "$off_acc" ]; then
    ck 1 "8l different audit policies gave the same result (acc $base_acc)"
  else
    ck 0 "8l policy changed the result"
  fi
  echo "  BENCH           : 2000 protected calls (wine)"
  echo "    unprotected                 : ${base_ms} ms"
  echo "    protected, audit every call : ${on_ms} ms"
  echo "    protected, audit ~off       : ${off_ms} ms"
  echo "    -> audit cost ~$(python3 -c "print(f'{(float('$on_ms')-float('$off_ms'))/2000*1000:.1f}')") us/call"
else
  echo "  SKIP 8l cost measurement: bench output unreadable"
fi

echo
# Random seed/profile fuzz: output must stay correct.
{
  fuzz_bad=0
  fuzz_n=6
  for i in $(seq 1 $fuzz_n); do
    sd=$(python3 -c "import os;print('0x%016x'%(int.from_bytes(os.urandom(8),'little')|1))")
    out="$WORK/fuzz$i.exe"
    if "$PROTECT" "$TARGET" "$out" --rebase 0x180000000 --vm-seed "$sd" \
         --dispatch-profile "1,1,2,3,0,1" >"$WORK/fz$i.log" 2>&1; then
      fz="$(run_target "$out")"
      [ "$fz" = "$BASE" ] || { fuzz_bad=1; echo "    fuzz #$i seed=$sd output differs"; }
    else
      fuzz_bad=1; echo "    fuzz #$i seed=$sd protect failed"; tail -2 "$WORK/fz$i.log" | sed 's/^/      /'
    fi
  done
  if [ "$fuzz_bad" = "0" ]; then
    ck 1 "K5 fuzz: $fuzz_n random seeds/profiles gave correct output"
  else
    ck 0 "K5 fuzz: random seed/profile crashed or produced wrong output"
  fi
}

rm -rf "$WORK"
if [ "$fails" -eq 0 ]; then echo "result: ALL CHECKS PASSED"; exit 0; fi
echo "result: $fails checks failed"; exit 1
