#include "hyda/codec/blob.hpp"
#include "hyda/core/context.hpp"
#include "hyda/vm/vm.hpp"
#include "hyda/guard/antidbg.hpp"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#endif

extern "C" uint64_t hyda_vm_dispatch(uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);

#if defined(_WIN32)

static LONG WINAPI seh_uef(PEXCEPTION_POINTERS ep) {
  if (ep != nullptr && ep->ExceptionRecord != nullptr &&
      ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    ExitProcess(0x5Eu);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
#endif

__attribute__((noinline, section("hydafn_muladd"), aligned(16)))
uint64_t fn_muladd(uint64_t a, uint64_t b) {
  uint64_t r = 0;
  for (uint64_t k = 0; k < b; ++k) {
    r = r * 3 + a;
  }
  return r;
}

__attribute__((noinline, section("hydafn_mix32"), aligned(16)))
uint64_t fn_mix32(uint64_t x) {
  uint32_t v = static_cast<uint32_t>(x);
  v ^= v >> 13;
  v *= 0x9E3779B1u;
  v = (v << 7) | (v >> 25);
  v += static_cast<uint32_t>(x >> 32) * 5u;
  return v;
}

__attribute__((noinline, section("hydafn_divmod"), aligned(16)))
uint64_t fn_divmod(uint64_t a, uint64_t b) {
  const uint32_t x = static_cast<uint32_t>(a) + 7u;
  const uint32_t y = static_cast<uint32_t>(b) | 1u;
  const uint32_t q = x / y;
  const uint32_t rem = x % y;
  const int32_t s = static_cast<int32_t>(x) - static_cast<int32_t>(y);
  return static_cast<uint32_t>(q * 1000u + rem * 10u) +
         static_cast<uint64_t>(s > 0 ? 1u : 0u);
}

static uint64_t g_state = 100;

__attribute__((noinline, section("hydafn_glob"), aligned(16)))
uint64_t fn_glob(uint64_t x) {
  g_state = g_state * 7 + x;
  return g_state ^ 0xA5A5A5A5A5A5A5A5ull;
}

__attribute__((noinline, section("hydafn_sse"), aligned(16)))
uint64_t fn_sse(uint64_t x) {
  float f = static_cast<float>(x & 0xffffu) * 1.5f;
  f = (f + 3.25f) * f;
  return static_cast<uint64_t>(static_cast<int64_t>(f));
}

static uint64_t gate_adder(uint64_t a, uint64_t b) { return a * 3u + b; }
static uint64_t (*volatile g_adder_ptr)(uint64_t, uint64_t) = gate_adder;

__attribute__((noinline, section("hydafn_icall"), aligned(16)))
uint64_t fn_icall(uint64_t a, uint64_t b) { return g_adder_ptr(a, b) + 11u; }

extern "C" __attribute__((naked, noinline)) uint64_t hyda_align_probe(void) {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rsp\n"
          "and eax, 15\n"
          "ret\n"
          ".att_syntax prefix\n");
}

__attribute__((noinline, section("hydafn_dcall"), aligned(16)))
uint64_t fn_dcall(uint64_t a) {
  return hyda_align_probe() * 100u + (a & 0xffu);
}

__attribute__((noinline, section("hydafn_leaf"), aligned(16)))
uint64_t fn_leaf(uint64_t a) {
  return (a ^ 0x9E3779B97F4A7C15ull) * 3u + 1u;
}

__attribute__((noinline, section("hydafn_mid"), aligned(16)))
uint64_t fn_mid(uint64_t a) {
  return fn_leaf(a + 7u) ^ 0x5A5A5A5Aull;
}

__attribute__((noinline, section("hydafn_switch"), aligned(16)))
uint64_t fn_switch(uint64_t a) {
  switch (a & 3u) {
    case 0: return a + 1u;
    case 1: return a * 3u;
    case 2: return a ^ 0x55u;
    default: return ~a;
  }
}

__attribute__((noinline, section("hydafn_load"), aligned(16)))
uint64_t fn_load(const uint64_t* p) {
  return p[0];
}

__attribute__((noinline, section("hydafn_throw"), aligned(16)))
int fn_throw(int v) {
  if (v > 0) throw v;
  return 0;
}

__attribute__((noinline, section("hydafn_catch"), aligned(16)))
int fn_catch(int v) {
  try {
    return fn_throw(v) + 1;
  } catch (int e) {
    return -e;
  }
}

__attribute__((noinline, section("hydafn_nest"), aligned(16)))
uint64_t fn_nest(uint64_t a) {
  const uint64_t m = fn_mid(a);
  return m + fn_leaf(a ^ m);
}

extern "C" __attribute__((naked, noinline, section("hydafn_deep"), aligned(16)))
uint64_t fn_deep(uint64_t) {
  __asm__(".intel_syntax noprefix\n"
          "sub rsp, 8\n"
          "test rcx, rcx\n"
          "jz 1f\n"
          "dec rcx\n"
          "call fn_deep\n"
          "add rsp, 8\n"
          "ret\n"
          "1:\n"
          "mov eax, 1\n"
          "add rsp, 8\n"
          "ret\n"
          ".att_syntax prefix\n");
}

__attribute__((noinline, section("hydafn_tailb"), aligned(16)))
uint64_t fn_tailb(uint64_t a, uint64_t b) {
  return (a * 3u + b) ^ 0x0123456789ABCDEFull;
}

__attribute__((noinline, section("hydafn_taila"), aligned(16)))
uint64_t fn_taila(uint64_t a, uint64_t b) {
  return fn_tailb(a + 5u, b);
}

__attribute__((noinline, section("hydafn_imp"), aligned(16)))
uint64_t fn_import(uint64_t x) {
  return static_cast<uint64_t>(lstrlenA("hyda")) + x;
}

#if defined(_WIN32)
struct HydaRtf {
  uint32_t begin;
  uint32_t end;
  uint32_t unwind;
};

typedef HydaRtf* (*HydaLookupFn)(uint64_t control_pc, uint64_t* image_base,
                                 void* history);
typedef void* (*HydaVirtUnwindFn)(uint32_t handler_type, uint64_t image_base,
                                  uint64_t control_pc, HydaRtf* fn_entry,
                                  void* context, void** handler_data,
                                  uint64_t* establisher, void* ctx_ptrs);

static uint64_t tramp_of(const void* fn) {
  const uint8_t* p = static_cast<const uint8_t*>(fn);
  if (p[0] != 0xE9) return 0;
  int32_t rel = 0;
  std::memcpy(&rel, p + 1, 4);
  return reinterpret_cast<uint64_t>(p + 5 + rel);
}

static int check_unwind(const char* name, const void* fn, HydaLookupFn lookup,
                        HydaVirtUnwindFn vunwind) {
  const uint64_t tramp = tramp_of(fn);
  if (tramp == 0) return 0;

  uint64_t image_base = 0;
  HydaRtf* rtf = lookup(tramp + 8, &image_base, nullptr);
  if (rtf == nullptr) {
    std::printf("  FAIL %s: trampoline (%#llx) missing from exception table\n", name,
                static_cast<unsigned long long>(tramp));
    return -1;
  }

  const uint64_t begin = image_base + rtf->begin;
  const uint64_t end = image_base + rtf->end;
  if (begin != tramp || end <= begin) {
    std::printf("  FAIL %s: wrong input range (%#llx..%#llx, trampoline %#llx)\n",
                name, static_cast<unsigned long long>(begin),
                static_cast<unsigned long long>(end),
                static_cast<unsigned long long>(tramp));
    return -1;
  }

  uint64_t fake[64];
  for (int i = 0; i < 64; ++i) fake[i] = 0xA000000000000000ull + static_cast<uint64_t>(i);
  CONTEXT c;
  std::memset(&c, 0, sizeof(c));
  c.ContextFlags = CONTEXT_FULL;
  c.Rip = tramp + 8;
  c.Rsp = reinterpret_cast<uint64_t>(&fake[0]);
  uint64_t establisher = 0;
  vunwind(0 , image_base, tramp + 8, rtf, &c, nullptr,
          &establisher, nullptr);

  const uint64_t frame = c.Rsp - reinterpret_cast<uint64_t>(&fake[0]);
  const bool frame_ok = (frame >= 8) && (frame % 8) == 0;
  const bool ret_ok = frame_ok && (c.Rip >= 0xA000000000000000ull) &&
                      (c.Rip < 0xA000000000000000ull + 64) &&
                      (c.Rip == fake[frame / 8 - 1]);
  const uint64_t prolog_frame = frame - 8;
  const bool ok = ret_ok && prolog_frame >= 0x28 && prolog_frame <= 0x68;
  if (!ok) {
    const uint8_t* ui = reinterpret_cast<const uint8_t*>(image_base + rtf->unwind);
    std::printf("  FAIL %s: cannot unwind frame (frame=%llu rip=%#llx) "
                "unwind@%#x = %02x %02x %02x %02x %02x %02x\n",
                name, static_cast<unsigned long long>(prolog_frame),
                static_cast<unsigned long long>(c.Rip), rtf->unwind, ui[0], ui[1],
                ui[2], ui[3], ui[4], ui[5]);
    return -1;
  }
  return 1;
}
#endif

#if defined(HYDA_HOOKTEST) && defined(_WIN32)

static uint64_t* find_iat_slot() {
  unsigned char* base = reinterpret_cast<unsigned char*>(
      GetModuleHandleA(nullptr));
  if (base == nullptr) return nullptr;
  const unsigned char* nt = base + *reinterpret_cast<const unsigned long*>(
      base + 0x3C);
  const unsigned char* opt = nt + 24;
  const unsigned long iat_rva = *reinterpret_cast<const unsigned long*>(
      opt + 112 + 12 * 8);
  if (iat_rva == 0) return nullptr;
  return reinterpret_cast<uint64_t*>(base + iat_rva);
}

__attribute__((noinline)) void hook_iat() {
  uint64_t* slot = find_iat_slot();
  if (slot == nullptr) return;

  *slot = 0xDEADBEEFDEADBEEFull;
}
#endif

#if defined(_WIN32)
extern "C" uint64_t hyda_adbg_read(uint32_t sel, uint32_t arg);
#endif

#if defined(HYDA_ADBGTEST) && defined(_WIN32)

static void adbg_inject(const char* mode) {
  uint64_t peb = 0;
  __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
  if (peb < 0x10000) return;
  volatile uint8_t* b = reinterpret_cast<volatile uint8_t*>(peb);
  if (std::strcmp(mode, "adbg-being") == 0) {
    b[0x02] = 1;
  } else if (std::strcmp(mode, "adbg-ntglobal") == 0) {
    reinterpret_cast<volatile uint32_t*>(peb + 0xBC)[0] |= 0x70u;
  } else if (std::strcmp(mode, "adbg-mod") == 0) {

    if (LoadLibraryA("x64dbg.dll") == nullptr) {
      std::fprintf(stderr, "adbg-mod: cannot load sentinel module\n");
    }
  }
}
#endif

#if defined(_WIN32)

struct ThreadArg {
  uint64_t seed;
  uint64_t out;
};
static DWORD WINAPI thread_proc(void* p) {
  ThreadArg* a = static_cast<ThreadArg*>(p);
  uint64_t acc = a->seed;
  for (unsigned i = 0; i < 1500; ++i) {
    const uint64_t x = acc + i;
    acc = fn_muladd(acc + x, 3) ^ fn_mix32(x) ^ fn_leaf(x);
  }
  a->out = acc;
  return 0;
}
static DWORD WINAPI thread_proc_gate(void* p) {
  ThreadArg* a = static_cast<ThreadArg*>(p);
  uint64_t acc = a->seed;
  for (unsigned i = 0; i < 400; ++i) {
    acc = fn_sse(acc + i) ^ fn_import(acc + 7u);
  }
  a->out = acc;
  return 0;
}
#endif

int main(int argc, char** argv) {
#if defined(_WIN32)

  if (argc > 1 && std::strcmp(argv[1], "adbg") == 0) {
    for (uint32_t sel = 0; sel < hyda::HYDA_ADBG_CHECK_COUNT; ++sel) {
      const uint32_t sub = hyda::adbg_sub_count(sel);
      for (uint32_t a = 0; a < sub; ++a) {
        const uint64_t obs = hyda_adbg_read(sel, a);
        std::printf("adbg sel=%u arg=%u obs=%016llx %s\n", sel, a,
                    static_cast<unsigned long long>(obs),
                    hyda::adbg_eval(sel, a, obs) == 0 ? "CLEAN"
                                                      : "DIRTY");
      }
    }
    return 0;
  }
#endif
#if defined(HYDA_ADBGTEST) && defined(_WIN32)

  if (argc > 1 && std::strncmp(argv[1], "adbg-", 5) == 0) {
    if (std::strcmp(argv[1], "adbg-clean") != 0) adbg_inject(argv[1]);

    volatile uint64_t b = 3;
    uint64_t acc = 0;
    for (unsigned i = 0; i < 256; ++i) acc = fn_muladd(acc + i, b);

    std::printf("adbg acc=%llu\n", static_cast<unsigned long long>(acc));
    return 0;
  }
#endif
#if defined(_WIN32)

  if (argc > 1 && std::strcmp(argv[1], "seh") == 0) {
    SetUnhandledExceptionFilter(seh_uef);
    static volatile uintptr_t g_bad_addr = 0xDEAD0000ull;
    const uint64_t* bad = reinterpret_cast<const uint64_t*>(g_bad_addr);
    volatile uint64_t sink = fn_load(bad);
    (void)sink;
    std::printf("seh: returned without fault\n");
    return 0;
  }

  if (argc > 1 && std::strcmp(argv[1], "eh") == 0) {
    int a = 0;
    try {
      a = fn_throw(7);
      std::printf("eh: no_throw=%d\n", a);
    } catch (int e) {
      std::printf("eh: caught=%d\n", e);
    }
    try {
      a = fn_throw(0);
      std::printf("eh: value=%d\n", a);
    } catch (int e) {
      std::printf("eh: unexpected=%d\n", e);
    }
    std::printf("eh: inner=%d\n", fn_catch(5));
    std::printf("eh: inner0=%d\n", fn_catch(0));
    std::printf("eh: done\n");
    return 0;
  }

  if (argc > 1 && std::strcmp(argv[1], "island_seh") == 0) {
    SetUnhandledExceptionFilter(seh_uef);
    g_adder_ptr = nullptr;
    volatile uint64_t sink = fn_icall(1, 2);
    (void)sink;
    std::printf("island_seh: returned without fault\n");
    return 0;
  }
#endif
#if defined(_WIN32)
  if (argc > 1 && std::strcmp(argv[1], "threads") == 0) {
    enum { N = 4 };
    ThreadArg args[N];
    HANDLE th[N];
    for (int i = 0; i < N; ++i) {
      args[i].seed = 0x1234567890abcdefull;
      args[i].out = 0;
      th[i] = CreateThread(nullptr, 0, thread_proc, &args[i], 0, nullptr);
    }
    const DWORD wr = WaitForMultipleObjects(N, th, TRUE, 60000);
    for (int i = 0; i < N; ++i) {
      if (th[i] != nullptr) CloseHandle(th[i]);
    }
    for (int i = 0; i < N; ++i) {
      std::printf("thread%d=%llu\n", i,
                  static_cast<unsigned long long>(args[i].out));
    }
    std::printf("threads_wr=%lu\n", static_cast<unsigned long>(wr));
    return 0;
  }
#endif
#if defined(_WIN32)
  if (argc > 1 && std::strcmp(argv[1], "threads_gate") == 0) {
    enum { N = 4 };
    ThreadArg args[N];
    HANDLE th[N];
    for (int i = 0; i < N; ++i) {
      args[i].seed = 0x0BADF00DCAFEBABEull;
      args[i].out = 0;
      th[i] = CreateThread(nullptr, 0, thread_proc_gate, &args[i], 0, nullptr);
    }
    const DWORD wr = WaitForMultipleObjects(N, th, TRUE, 120000);
    for (int i = 0; i < N; ++i) {
      if (th[i] != nullptr) CloseHandle(th[i]);
    }
    for (int i = 0; i < N; ++i) {
      std::printf("gthread%d=%llu\n", i,
                  static_cast<unsigned long long>(args[i].out));
    }
    std::printf("threads_gate_wr=%lu\n", static_cast<unsigned long>(wr));
    return 0;
  }
#endif
  if (argc > 1 && std::strcmp(argv[1], "bench") == 0) {    uint64_t n = 20000;
    if (argc > 2) n = std::strtoull(argv[2], nullptr, 0);
    if (n == 0) n = 1;

    unsigned fn = 0;
    if (argc > 3) fn = static_cast<unsigned>(std::strtoul(argv[3], nullptr, 0));
    uint64_t acc = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < n; ++i) {
      const uint64_t a = i * 0x9E3779B97F4A7C15ull + 1u;
      switch (fn) {
        case 1: acc += fn_leaf(a); break;
        case 2: acc += fn_muladd(a, 1); break;
        case 3: acc += fn_divmod(a, a | 1u); break;
        default: acc += fn_mix32(a); break;
      }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::printf("bench: %llu calls, %.3f ms, acc=%016llx\n",
                static_cast<unsigned long long>(n), ms,
                static_cast<unsigned long long>(acc));
    return 0;
  }

#if defined(_WIN32)

  std::fprintf(stderr, "module base: 0x%llx\n",
               static_cast<unsigned long long>(
                   reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr))));
#endif
  std::printf("HydaVM PE target (x64)\n");

#if defined(HYDA_HOOKTEST) && defined(_WIN32)

  hook_iat();

  std::printf("hook: after muladd=%llu\n",
               static_cast<unsigned long long>(fn_muladd(2, 3)));
#endif

  const uint64_t m1 = fn_muladd(7, 40);
  const uint64_t m2 = fn_mix32(0x0123456789ABCDEFull);
  const uint64_t m3 = fn_divmod(0x0000000B12345678ull, 0x19);
  uint64_t m4 = 0;
  for (uint64_t k = 0; k < 5; ++k) m4 = fn_glob(k + 3);

  uint64_t g1 = 0;
  for (uint64_t k = 0; k < 7; ++k) g1 = fn_sse(0x4321u + k * 977u);
  const uint64_t g2 = fn_icall(0x12345678ull, 0x9ABCDEFull);
  const uint64_t g3 = fn_dcall(0x55AAull);

  const uint64_t g4 = fn_nest(0x1234u);

  const uint64_t g5 = fn_deep(16);

  const uint64_t g6 = fn_taila(0x4321u, 0x9ABCDEFull);

  const uint64_t g7 = fn_import(0x100u);

  const uint64_t g8 = fn_sse(0x4321u) + fn_import(0x100u) - g7;

  std::printf("muladd = %llu\n", (unsigned long long)m1);
  std::printf("mix32  = %llu\n", (unsigned long long)m2);
  std::printf("divmod = %llu\n", (unsigned long long)m3);
  std::printf("glob   = %llu\n", (unsigned long long)m4);
  std::printf("sse    = %llu\n", (unsigned long long)g1);
  std::printf("icall  = %llu\n", (unsigned long long)g2);
  std::printf("dcall  = %llu\n", (unsigned long long)g3);
  std::printf("nest   = %llu\n", (unsigned long long)g4);
  std::printf("deep   = %llu\n", (unsigned long long)g5);
  std::printf("tail   = %llu\n", (unsigned long long)g6);
  std::printf("import = %llu\n", (unsigned long long)g7);
  std::printf("import2 = %llu\n", (unsigned long long)g8);

  uint64_t swacc = 0;
  for (uint64_t k = 0; k < 8; ++k) swacc = swacc * 131u + fn_switch(k);
  swacc = swacc * 131u + fn_switch(0x1234u);
  std::printf("result: muladd=%llu mix32=%llu divmod=%llu glob=%llu sse=%llu "
              "icall=%llu dcall=%llu nest=%llu deep=%llu tail=%llu import=%llu "
              "switch=%llu\n",
              (unsigned long long)m1, (unsigned long long)m2,
              (unsigned long long)m3, (unsigned long long)m4,
              (unsigned long long)g1, (unsigned long long)g2,
              (unsigned long long)g3, (unsigned long long)g4,
              (unsigned long long)g5, (unsigned long long)g6,
              (unsigned long long)g7, (unsigned long long)swacc);

#if defined(_WIN32)

  {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HydaLookupFn lookup = ntdll ? reinterpret_cast<HydaLookupFn>(
                                      reinterpret_cast<void*>(GetProcAddress(
                                          ntdll, "RtlLookupFunctionEntry")))
                                : nullptr;
    HydaVirtUnwindFn vunwind =
        ntdll ? reinterpret_cast<HydaVirtUnwindFn>(reinterpret_cast<void*>(
                    GetProcAddress(ntdll, "RtlVirtualUnwind")))
              : nullptr;
    if (lookup != nullptr && vunwind != nullptr) {
      struct Entry {
        const char* name;
        const void* fn;
      };
      const Entry fns[] = {
          {"muladd", reinterpret_cast<const void*>(&fn_muladd)},
          {"mix32", reinterpret_cast<const void*>(&fn_mix32)},
          {"divmod", reinterpret_cast<const void*>(&fn_divmod)},
          {"glob", reinterpret_cast<const void*>(&fn_glob)},
          {"sse", reinterpret_cast<const void*>(&fn_sse)},
          {"icall", reinterpret_cast<const void*>(&fn_icall)},
          {"dcall", reinterpret_cast<const void*>(&fn_dcall)},
          {"leaf", reinterpret_cast<const void*>(&fn_leaf)},
          {"mid", reinterpret_cast<const void*>(&fn_mid)},
          {"nest", reinterpret_cast<const void*>(&fn_nest)},
          {"deep", reinterpret_cast<const void*>(&fn_deep)},
          {"taila", reinterpret_cast<const void*>(&fn_taila)},
          {"tailb", reinterpret_cast<const void*>(&fn_tailb)},
          {"import", reinterpret_cast<const void*>(&fn_import)},
      };
      int checked = 0, bad = 0;
      for (const Entry& e : fns) {
        const int r = check_unwind(e.name, e.fn, lookup, vunwind);
        if (r > 0) ++checked;
        if (r < 0) ++bad;
      }
      if (checked > 0) {
        std::printf("unwind: %d/%d trampoline entries OK (frame "
                    "unwound)\n",
                    checked, static_cast<int>(sizeof(fns) / sizeof(fns[0])));
      }
      if (bad != 0) std::printf("unwind: %d FAIL\n", bad);
    }
  }

  if (tramp_of(reinterpret_cast<const void*>(&fn_deep)) != 0) {
    const uint64_t r = fn_deep(1u << 20);
    std::printf("guard: guest stack limit hit, no crash/corruption "
                " (result=%llu)\n",
                static_cast<unsigned long long>(r));
  }

  if (tramp_of(reinterpret_cast<const void*>(&fn_taila)) != 0) {
    const uint64_t got = fn_taila(0x4321u, 0x9ABCDEFull);
    const uint64_t want = fn_tailb(0x4321u + 5u, 0x9ABCDEFull);
    std::printf("tail-call: %s (got=%llu want=%llu)\n",
                got == want ? "OK" : "BAD",
                static_cast<unsigned long long>(got),
                static_cast<unsigned long long>(want));
  }
#endif
  return 0;
}
