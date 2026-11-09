# HydaVM

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

Common options:

| Option | Purpose |
|---|---|
| `--vm-seed <hex>` | Seed for opcode map, keys and handler variants (random if omitted). |
| `--rebase <hex>` | Change the output image base. |
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
3. Handler code is split into shards and hidden inside data sections.
4. At load time the entry stub installs the handler table, verifies sections
   and decrypts bytecode on demand.
5. A fault bridge maps VM faults back into native SEH, preserving normal
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
tools/          protect_e2e.sh orchestration
tests/      host, lifter and Windows PE tests
```

## Testing

| Suite | Checks |
|---|---|
| `test_vm` (host differential) | 92,797 |
| `test_lifter` | 297 |
| `vm_selftest` (Windows) | 73 |
| `pe_e2e` | full protect → run → compare |

All suites pass on Linux, and the Windows suites pass under Wine.

## Limitations

- Windows x64 only; MSVC is not supported yet.
- Only the x86-64 subset understood by the lifter can be virtualized.
  Unsupported instructions are reported instead of silently miscompiled.
- Not a generic packer: only functions compiled into `hydafn_*` sections are
  protected.
- The project is under active development; APIs may change.

## License

MIT — see [LICENSE](LICENSE).

## Responsible use

HydaVM is meant to protect software you own or are authorized to protect.
Do not use it to conceal malware or evade security controls.
