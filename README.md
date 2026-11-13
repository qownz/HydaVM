# HydaVM

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

HydaVM is an x86-64 **virtual-machine based code protector** for Windows PE
executables and DLLs, in the spirit of Themida, Code Virtualizer and VMProtect.

It lifts selected functions from native machine code into a compact custom
bytecode and runs them on an embedded, randomized VM. Callers keep calling a
normal function; the body executes inside the VM.

## Features

- **Fail-closed static protection** — protected function bodies are replaced
  with `int3`; only VM bytecode remains.
- **Randomized per build** — opcode mapping, register permutation, handler
  variants and encryption keys all derive from a seed.
- **Per-instruction encrypted bytecode** — operands are decrypted at runtime.
- **Sharded handlers** — handler code is split and scattered across data
  sections, then made executable on demand with page-level refcounting.
- **Integrity and anti-analysis** — section CRC, import guard, periodic audit,
  anti-debug checks and an SEH bridge.
- **Differential-tested** — the VM produces bit-identical results to native
  code.

## Requirements

| Tool | Notes |
|---|---|
| CMake | 3.16+ |
| Ninja | recommended |
| C++17 compiler | g++ or clang++ |
| Capstone | `libcapstone-dev` + `pkg-config` (lifter/protector only) |
| mingw-w64 | `x86_64-w64-mingw32-g++` for the Windows target |
| Wine | to run Windows tests on Linux |

Debian/Ubuntu:

```bash
sudo apt install cmake ninja-build g++ pkg-config libcapstone-dev \
                 g++-mingw-w64-x86-64 wine
```

## Quick start

### Host (Linux)

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DHYDA_BUILD_LIFTER=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### Windows target (mingw + Wine)

```bash
cmake -S . -B build-win -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-x86_64.cmake \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
ctest --test-dir build-win --output-on-failure   # runs under Wine
```

The lifter and the runtime must be built with the same seed. The default is
`0x8F3A5C71D2E6B904`; override it with `-DHYDA_VM_SEED=<hex>` for both builds.

## Usage

HydaVM protects **your own** functions. Put each sensitive function in its own
section named `hydafn_*`:

```cpp
#define HYDA_PROTECT(name) \
  __attribute__((noinline, section("hydafn_" #name), aligned(16)))

HYDA_PROTECT(license_check)
int license_check(const char* key) { /* ... */ return 1; }
```

Build the target for Windows x64 with mingw, linking the `hyda_vm` library and
`runtime/win/hyda_vm_entry.cpp`. Use the same flags as the bundled `pe_target`
CMake target (`-fno-ipa-cp-clone`, `-Wl,--file-alignment,0x1000`). Then protect
it:

```bash
./build/hyda_protect app.exe app_protected.exe --vm-seed 0x1122334455667788
wine app_protected.exe        # output must match the unprotected build
```

Useful commands:

```bash
./build/hyda_protect list app.exe       # list protectable sections
./build/hyda_protect inspect app.exe    # show discovered handler bodies
./build/hyda_protect --help
```

`list`/`inspect` are aliases for the legacy `--list`/`--list-handlers`
flags; the classic `hyda_protect <in> <out> [options]` form is unchanged.

A function that cannot be lifted is skipped and left native by default; the
rest is still protected. `--strict` restores stop-on-first-error, and
`--report` records what happened:

```bash
./build/hyda_protect app.exe app_protected.exe --report build/report.json
./build/hyda_protect app.exe --dry-run --report build/report.json
```

The report lists every protected function with its x86 and bytecode size,
native island count, fused/variant/dead-flag counters and whether operand
encryption is on, plus a `skipped` array with the reason per function. It is
plain JSON, so CI can gate on `totals.skipped == 0`.

Common options:

| Option | Purpose |
|---|---|
| `--vm-seed <hex>` | Seed for opcode map, keys and handler variants (random if omitted). |
| `--rebase <hex>` | Change the output image base. |
| `--report <file>` | Write a JSON report (per-function sizes, islands, skips). |
| `--dry-run` | Analyze and report, write nothing; output path optional. |
| `--strict` | Fail on the first function that cannot be protected. |
| `--no-crypt <fn>` | Disable operand encryption for one blob (debugging). |
| `--hydak-parts <n>` | Number of handler shards (default 6). |
| `--hydak-containers <n>` | Number of data sections used to scatter shards. |
| `--audit-period <n>` | Run an integrity audit every N VM calls. |
| `--no-mutate` | Disable the mutation engine (debugging only). |

## How it works

```text
native x86-64 ──capstone──▶ IR ──codegen──▶ encrypted VM bytecode
                                                   │
                                       embedded VM runtime
                                     (randomized handlers)
```

1. The protector finds `hydafn_*` sections and lifts each function to IR.
2. IR is compiled to slot-based bytecode; operands are encrypted per
   instruction.
3. Each function gets its own dispatch identity: slot numbering, crypt
   variant and call style are derived from that blob's key, so nothing about
   one function's dialect is stored for another's.
4. Handler code is split into shards and hidden inside data sections.
5. At load time the entry stub installs the handler table, verifies sections
   and decrypts bytecode on demand.
6. A fault bridge maps VM faults back into native SEH, preserving normal
   exception semantics.

## Project layout

```text
include/hyda/
  core/     build/VM configuration, registers, opcodes, context, threading
  codec/    bytecode codec, encryption, blob and container formats
  ir/       intermediate representation and x86 -> IR -> bytecode codegen
  vm/       VM loop, handlers, dispatcher, native gate, SSE/FP state
  native/   native islands and island mutation
  guard/    integrity, anti-debug, audit, hook guard, API hashing
  mutate/   IR-level mutation, fusion and obfuscation
src/        implementations mirroring the include/hyda module tree
lifter/     x86-64 -> IR -> bytecode lifter (library + CLI)
runtime/win/  Windows entry stub and self-test
tools/protect/  hyda_protect (CLI, PE reader, handler analysis, layout, pipeline)
tools/e2e/      Python verifiers used by the end-to-end test
tools/          protect_e2e.sh and lift_coverage.sh
tests/      host, lifter, lifting-coverage corpus and Windows PE tests
```

## Testing

| Suite | Checks |
|---|---|
| `test_vm` (host differential) | 92,801 |
| `test_lifter` | 389 |
| `vm_selftest` (Windows) | 73 |
| `pe_e2e` | full protect → run → compare |

All suites pass on Linux, and the Windows suites pass under Wine.

`test_vm` and `test_lifter` share a small harness (`tests/harness/`): every
case is a registered class with a suite, a name and a one-line description, so
a run names what failed and cases can be selected:

```bash
./build/test_vm --list                    # suite, name, description
./build/test_vm --filter=Flags            # one suite
./build/test_lifter --filter=DoubleShift.mutation_seeds
```

### Lifting coverage

Two scripts measure how much of a corpus reaches the VM as bytecode instead of
falling back to a native island:

```bash
./tools/lift_coverage.sh build              # synthetic corpus, all -O levels
./tools/lift_real.sh build x86_64-w64-mingw32-g++ O2   # HydaVM's own sources
```

The synthetic corpus (`tests/coverage_corpus.c`, 190 lifts, 3,615
instructions) lifts down to 20 islands, all of them atomic: 15 `lock xadd` /
`lock cmpxchg` and 5 memory `xchg`. Lock semantics cannot be reproduced by the
VM, so those stay native on purpose.

Real code is measured by lifting every function of `src/*.cpp` built for
Windows. At `-O2` that is 455 functions, 36,051 instructions and 64 islands
(0.18%). What is left is mostly instructions where an island is the right
answer: `cpuid`, `rdtsc`, `xgetbv`, `pause`, `fxsave`/`fxrstor` (the
protector's own host-side helpers), `lock`-prefixed atomics, indirect `call`,
and a few SSE forms such as `movhps`/`movhlps` and 32-bit `bt`/`bts`.

## Benchmark

`hyda_bench` runs a native body and its virtualized twin on the host and
reports the best of five rounds:

| Body | Native | VM | Ratio | VM ops | Per op |
|---|---|---|---|---|---|
| ALU loop, 64 iterations | 41 ns | 23.9 µs | ~580× | 1,672 | 14.3 ns |
| Straight line, 64 ops | 11 ns | 6.4 µs | ~580× | 439 | 14.5 ns |
| Island gate round trip | — | 330 ns | — | — | — |

Intel i3-1005G1, g++ 13.3, `-O3`. The VM op count includes the mutation
engine's junk and noise, which the protector emits by default.

Each body is also measured with ciphertext slots and operands, which is the
configuration the protector emits: the table above is the plain one, and the
ciphertext run costs ~2.1× the plain dispatch (`~2.35×` before the slot mixer
became a 256-byte table). That premium is measured in-process against the
plain row, so it does not move with CPU frequency.

```bash
cmake --build build --target hyda_bench && ./build/hyda_bench
```

The end-to-end test prints the same kind of measurement for a protected binary
under Wine (unprotected, audit every call, audit amortized), together with the
audit cost per call.

## Limitations

- Windows x64 only; MSVC is not supported yet.
- Only the x86-64 subset understood by the lifter is virtualized. Anything
  else runs through the native gate as an island, or is reported if it cannot
  be relocated — instructions are never silently miscompiled.
- An island runs its original instruction natively, so those bytes stay in the
  image (encrypted, but unvirtualized). Flag writes are carried back into the
  VM flag register; a function that cannot be lifted is skipped and reported
  rather than patched.
- C++ exceptions cannot cross a virtualized body, because its landing pads and
  cleanup live in the body's own bytecode. Functions whose unwind info declares
  a handler, or that call `__cxa_throw` / `_CxxThrowException`, are left native
  and reported as skipped.
- Not a generic packer: only functions compiled into `hydafn_*` sections are
  protected.
- The project is under active development; APIs may change.

## License

GPL-3.0-or-later. Copyright (C) 2026 qownz — see [LICENSE](LICENSE).

## Responsible use

HydaVM is meant to protect software you own or are authorized to protect.
Do not use it to conceal malware or evade security controls.
