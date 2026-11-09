// HydaVM - tests/adbg_dummy.cxx
//
// Fake "x64dbg.dll" module for the Stage 9 e2e test. The protected binary
// loads it in `adbg-mod` mode; the runtime's PEB.Ldr scan matches the module
// name hash and exits 217 after 8 hits.
extern "C" __declspec(dllexport) int hyda_dummy_probe(void) { return 42; }
