#include "hyda/codec/blob.hpp"
#include "hyda/core/context.hpp"
#include "hyda/codec/crypt.hpp"
#include "hyda/core/export.hpp"
#include "hyda/vm/gate.hpp"
#include "hyda/guard/apihash.hpp"
#include "hyda/codec/hydak.hpp"
#include "hyda/guard/integrity.hpp"
#include "hyda/native/island.hpp"
#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif
#include "hyda/core/thread.hpp"
#include "hyda/vm/vm.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace {

constexpr uint32_t kHostPage = 0x1000u;
constexpr uint32_t kMaxShardPages = 16384u;
static uintptr_t g_page_base = 0;
static uint32_t g_page_total = 0;
static uint16_t g_page_refs[kMaxShardPages] = {};

constexpr uint64_t kMaxSteps = 200000000ull;

extern "C" void* hyda_kernel32_api_hash(uint32_t func_hash);

#if defined(_WIN32)
constexpr uint32_t kHashVirtualProtect = 0x7851C633u;
using VirtualProtectFn = BOOL(WINAPI*)(void*, SIZE_T, DWORD, DWORD*);
VirtualProtectFn vprotect() {
  static VirtualProtectFn fn = nullptr;
  if (fn == nullptr) {
    fn = reinterpret_cast<VirtualProtectFn>(
        hyda_kernel32_api_hash(kHashVirtualProtect));
  }
  return fn;
}
#else
using VirtualProtectFn = void (*)(void*, size_t, unsigned long, unsigned long*);
VirtualProtectFn vprotect() { return nullptr; }
#endif

constexpr unsigned kMaxThreadSlots = 64;
constexpr size_t kVmStackBytes = size_t(1) << 20;

struct ThreadVmSlot {
  uint64_t key;
  uint8_t* stacks;
};
ThreadVmSlot g_thread_slots[kMaxThreadSlots];
std::atomic<uint32_t> g_thread_lock{0};

uint8_t* thread_vm_stacks() {
  const uint64_t key = hyda::thread_key();
  if (key == 0) return nullptr;
  for (unsigned i = 0; i < kMaxThreadSlots; ++i) {
    if (g_thread_slots[i].key == key) return g_thread_slots[i].stacks;
  }
  while (g_thread_lock.exchange(1, std::memory_order_acquire) != 0) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#endif
  }
  uint8_t* out = nullptr;
  for (unsigned i = 0; i < kMaxThreadSlots; ++i) {
    if (g_thread_slots[i].key == key) {
      out = g_thread_slots[i].stacks;
      break;
    }
  }
  if (out == nullptr) {
    for (unsigned i = 0; i < kMaxThreadSlots; ++i) {
      if (g_thread_slots[i].key != 0) continue;
      using AllocFn = void*(__stdcall*)(void*, size_t, uint32_t, uint32_t);
      void* fn = hyda_kernel32_api_hash(hyda::api_hash_c("VirtualAlloc"));
      uint8_t* mem = nullptr;
      if (fn != nullptr) {
        mem = static_cast<uint8_t*>(reinterpret_cast<AllocFn>(fn)(
            nullptr, hyda::kMaxVmDepth * kVmStackBytes, 0x3000u, 0x04u));
      }
      if (mem == nullptr) break;
      g_thread_slots[i].stacks = mem;
      g_thread_slots[i].key = key;
      out = mem;
      break;
    }
  }
  g_thread_lock.store(0, std::memory_order_release);
  return out;
}

constexpr unsigned kMaxHydakParts = hyda::HYDA_HYDAK_MAX_PARTS;

std::atomic<int> g_hydak_state{0};
uint32_t g_hydak_err = 0;

#if defined(_WIN32)

bool is_container_candidate(const IMAGE_SECTION_HEADER* s) {
  const DWORD ch = s->Characteristics;
  if ((ch & IMAGE_SCN_MEM_READ) == 0) return false;
  if ((ch & IMAGE_SCN_MEM_EXECUTE) != 0) return false;
  if ((ch & IMAGE_SCN_MEM_DISCARDABLE) != 0) return false;
  if (s->SizeOfRawData < sizeof(hyda::HydakHeader)) return false;
  if (s->Misc.VirtualSize < sizeof(hyda::HydakHeader)) return false;
  if (s->Misc.VirtualSize > (64u << 20)) return false;
  return true;
}

hyda::HandlerShardDesc g_hydak_shards[kMaxHydakParts];
unsigned g_hydak_nshards = 0;

static uint8_t g_shard_plain[kMaxHydakParts] = {};
static uint16_t g_shard_refs[kMaxHydakParts] = {};

bool do_install_hydak(const uint8_t* base) {
  const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    g_hydak_err = 0xFFFFFFFEu;
    return false;
  }
  const IMAGE_NT_HEADERS64* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    g_hydak_err = 0xFFFFFFFEu;
    return false;
  }

  hyda::HandlerShardDesc descs[kMaxHydakParts];

  struct Hit {
    uint8_t* ptr;
    uint32_t size;
  };
  Hit hits[hyda::HYDA_HYDAK_MAX_PARTS];
  unsigned nhit = 0;
  unsigned n = 0;

  VirtualProtectFn vprot = vprotect();
  if (vprot == nullptr) {
    g_hydak_err = 0xFFFFFFFFu;
    return false;
  }

  const IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
  for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++s) {
    if (!is_container_candidate(s)) continue;
    uint8_t* ptr = const_cast<uint8_t*>(base) + s->VirtualAddress;
    const uint32_t vs = s->Misc.VirtualSize;
    DWORD oldp = 0, dummy = 0;
    if (!vprot(ptr, vs, PAGE_READWRITE, &oldp)) {
      g_hydak_err = 0xFFFFFFFFu;
      return false;
    }
    uint32_t serr = hyda::HYDAK_OK;
    const unsigned before = n;
    n += hyda::hydak_scan_parts(ptr, vs, s->VirtualAddress, descs + n,
                                kMaxHydakParts - n, &serr);
    if (serr != hyda::HYDAK_OK) {
      vprot(ptr, vs, oldp, &dummy);
      g_hydak_err = serr;
      return false;
    }
    if (n == before) {
      vprot(ptr, vs, oldp, &dummy);
      continue;
    }

    hits[nhit].ptr = ptr;
    hits[nhit].size = vs;
    ++nhit;
  }

  if (n == 0) return true;

  const uint32_t err = hyda::install_handler_shards(descs, n);
  if (err != hyda::HYDAK_OK) {

    for (unsigned i = 0; i < nhit; ++i) {
      DWORD dummy = 0;
      vprot(hits[i].ptr, hits[i].size, PAGE_READONLY, &dummy);
    }
    g_hydak_err = err;
    return false;
  }
  for (unsigned i = 0; i < nhit; ++i) {
    DWORD dummy = 0;

    if (!vprot(hits[i].ptr, hits[i].size, PAGE_EXECUTE_READWRITE, &dummy)) {
      g_hydak_err = 0xFFFFFFFFu;
      return false;
    }
  }

  for (unsigned i = 0; i < n; ++i) {
    g_hydak_shards[i].ptr = descs[i].ptr;
    g_hydak_shards[i].size = descs[i].size;
    g_hydak_shards[i].rva = descs[i].rva;
  }
  g_hydak_nshards = n;

  {
    uintptr_t lo = ~static_cast<uintptr_t>(0), hi = 0;
    for (unsigned i = 0; i < n; ++i) {
      const uintptr_t p = reinterpret_cast<uintptr_t>(g_hydak_shards[i].ptr);
      if (p < lo) lo = p;
      if (p + g_hydak_shards[i].size > hi) hi = p + g_hydak_shards[i].size;
    }
    g_page_base = lo & ~static_cast<uintptr_t>(kHostPage - 1);
    const uintptr_t span = hi - g_page_base;
    uint32_t pages = static_cast<uint32_t>((span + kHostPage - 1) / kHostPage);
    if (pages > kMaxShardPages) pages = kMaxShardPages;
    g_page_total = pages;
  }

  for (unsigned i = 0; i < n; ++i) {
    hyda::hydak_xor(g_hydak_shards[i].ptr, g_hydak_shards[i].size,
                    hyda::hydak_key_for(g_hydak_shards[i].rva));
    g_shard_plain[i] = 0;
    g_shard_refs[i] = 0;
  }

  for (unsigned i = 0; i < nhit; ++i) {
    DWORD dummy = 0;
    vprot(hits[i].ptr, hits[i].size, PAGE_NOACCESS, &dummy);
  }
  return true;
}
#endif

static std::atomic<int> g_shards_lock{0};

void shards_lock() {
  for (;;) {
    int expected = 0;
    if (g_shards_lock.compare_exchange_weak(expected, 1,
                                          std::memory_order_acquire,
                                          std::memory_order_relaxed)) {
      return;
    }
    for (int i = 0; i < 16; ++i) {
#if defined(__x86_64__) || defined(__i386__)
      __builtin_ia32_pause();
#endif
    }
  }
}

void shards_unlock() { g_shards_lock.store(0, std::memory_order_release); }

bool ensure_handler_shard(const uint8_t* base) {
#if defined(_WIN32)
  for (;;) {
    const int st = g_hydak_state.load(std::memory_order_acquire);
    if (st == 1) return true;
    if (st == -1) return false;
    if (st == 0) {
      int expected = 0;
      if (g_hydak_state.compare_exchange_strong(expected, 2,
                                                std::memory_order_acq_rel)) {
        const bool ok = do_install_hydak(base);
        g_hydak_state.store(ok ? 1 : -1, std::memory_order_release);
        return ok;
      }
    }

  }
#else
  (void)base;
  return true;
#endif
}

}

void shard_crypt(unsigned i, DWORD final_prot) {
  VirtualProtectFn vprot = vprotect();
  DWORD old = 0;
  if (vprot != nullptr) {
    vprot(g_hydak_shards[i].ptr, g_hydak_shards[i].size,
          PAGE_EXECUTE_READWRITE, &old);
  }
  hyda::hydak_xor(g_hydak_shards[i].ptr, g_hydak_shards[i].size,
                  hyda::hydak_key_for(g_hydak_shards[i].rva));
  if (vprot != nullptr) {
    vprot(g_hydak_shards[i].ptr, g_hydak_shards[i].size, final_prot, &old);
  }
}

void shards_acquire(uint64_t mask) {
  shards_lock();
  for (unsigned i = 0; i < g_hydak_nshards; ++i) {
    if (mask != 0 && ((mask >> i) & 1u) == 0) continue;
    if (g_shard_refs[i]++ == 0 && g_shard_plain[i] == 0) {
      shard_crypt(i, PAGE_EXECUTE_READ);
      g_shard_plain[i] = 1;
    }
    VirtualProtectFn vp = vprotect();
    const uintptr_t start =
        reinterpret_cast<uintptr_t>(g_hydak_shards[i].ptr);
    const uintptr_t end = start + g_hydak_shards[i].size;
    for (uintptr_t pg = start & ~static_cast<uintptr_t>(kHostPage - 1);
         pg < end; pg += kHostPage) {
      if (pg < g_page_base) continue;
      const uint32_t s = static_cast<uint32_t>((pg - g_page_base) >> 12);
      if (s >= g_page_total) continue;
      ++g_page_refs[s];
      if (vp != nullptr) {
        DWORD old = 0;
        vp(reinterpret_cast<void*>(pg), kHostPage, PAGE_EXECUTE_READ, &old);
      }
    }
  }
  shards_unlock();
}

void shards_release(uint64_t mask) {
  shards_lock();
  for (unsigned i = 0; i < g_hydak_nshards; ++i) {
    if (mask != 0 && ((mask >> i) & 1u) == 0) continue;
    if (g_shard_refs[i] == 0) continue;
    if (--g_shard_refs[i] == 0 && g_shard_plain[i] != 0) {
      shard_crypt(i, PAGE_EXECUTE_READ);
      g_shard_plain[i] = 0;
    }
    VirtualProtectFn vp = vprotect();
    const uintptr_t start =
        reinterpret_cast<uintptr_t>(g_hydak_shards[i].ptr);
    const uintptr_t end = start + g_hydak_shards[i].size;
    for (uintptr_t pg = start & ~static_cast<uintptr_t>(kHostPage - 1);
         pg < end; pg += kHostPage) {
      if (pg < g_page_base) continue;
      const uint32_t s = static_cast<uint32_t>((pg - g_page_base) >> 12);
      if (s >= g_page_total || g_page_refs[s] == 0) continue;
      --g_page_refs[s];
      if (vp != nullptr) {
        DWORD old = 0;
        vp(reinterpret_cast<void*>(pg), kHostPage,
           g_page_refs[s] == 0 ? PAGE_NOACCESS : PAGE_EXECUTE_READ, &old);
      }
    }
  }
  shards_unlock();
}

extern "C" int hyda_vm_init_imports(uint32_t vault_rva);
extern "C" int hyda_vm_check_integrity_step(void);
extern "C" int hyda_vm_check_hookrefs_step(void);
extern "C" void hyda_vm_audit_set_base(const uint8_t* base);
extern "C" void* hyda_image_base(void);
extern "C" void* hyda_kernel32_api(const char* name);
extern "C" void* hyda_kernel32_api_hash(uint32_t func_hash);
extern "C" __attribute__((noreturn)) void hyda_vm_fail(uint32_t code);
extern "C" __attribute__((noreturn)) void hyda_vm_jump_to_entry(void);

HYDA_ENTRY __attribute__((naked, noinline)) void hyda_vm_entry_stub(void) {

  __asm__(".intel_syntax noprefix\n"
          "push rbx\n"
          "mov rbx, rsp\n"
          "and rsp, -16\n"
          "sub rsp, 32\n"
          "mov ecx, 0\n"
          "call hyda_vm_init_imports\n"
          "add rsp, 32\n"
          "mov rsp, rbx\n"
          "pop rbx\n"
          "test eax, eax\n"
          "jnz 1f\n"
          "jmp hyda_vm_jump_to_entry\n"

          "1:\n"

          "and rsp, -16\n"
          "mov ecx, eax\n"
          "call hyda_vm_fail\n"
          ".att_syntax prefix\n");
}

std::atomic<int> g_audit_busy{0};

#if defined(_WIN32)

extern "C" void* hyda_ntdll_api_hash(uint32_t func_hash);
extern "C" void hyda_vm_gate_abort(void);

extern "C" int hyda_vm_gate_fault_ctx(uint64_t* rip, uint64_t* rsp);

static void* g_seh_veh = nullptr;
static std::atomic<int> g_seh_install{0};

static uint64_t g_fault_masks[hyda::kMaxThreads][hyda::kMaxVmDepth];
static unsigned g_fault_depth[hyda::kMaxThreads];
static int g_fault_armed[hyda::kMaxThreads];

using AddVehFn = void*(__stdcall*)(uint32_t,
                                   LONG(__stdcall*)(EXCEPTION_POINTERS*));

static LONG __stdcall hyda_seh_veh(EXCEPTION_POINTERS* ep) {
  const unsigned ti = hyda::thread_index();
  if (ti >= hyda::kMaxThreads) return EXCEPTION_CONTINUE_SEARCH;
  if (g_fault_armed[ti] == 0 || ep == nullptr) return EXCEPTION_CONTINUE_SEARCH;
  const DWORD code = ep->ExceptionRecord->ExceptionCode;
  if (code == EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

  uint64_t fr = 0, fs = 0;
  const int island_fault = hyda_vm_gate_fault_ctx(&fr, &fs);
  g_fault_armed[ti] = 0;
  for (unsigned i = 0; i < g_fault_depth[ti]; ++i) {
    shards_release(g_fault_masks[ti][i]);
  }
  g_fault_depth[ti] = 0;
  hyda_vm_gate_abort();
#if defined(_M_X64) || defined(__x86_64__)
  if (island_fault && ep->ContextRecord != nullptr) {
    ep->ContextRecord->Rip = fr;
    ep->ContextRecord->Rsp = fs;
  }
#endif
  return EXCEPTION_CONTINUE_SEARCH;
}

static void hyda_seh_install(void) {
  if (g_seh_veh != nullptr) return;
  if (g_seh_install.exchange(1, std::memory_order_acq_rel) != 0) {
    while (g_seh_veh == nullptr) {
#if defined(__x86_64__) || defined(__i386__)
      __builtin_ia32_pause();
#endif
    }
    return;
  }
  void* add =
      hyda_ntdll_api_hash(hyda::api_hash_c("RtlAddVectoredExceptionHandler"));
  if (add != nullptr) {
    g_seh_veh = reinterpret_cast<AddVehFn>(add)(1u, &hyda_seh_veh);
  }
  g_seh_install.store(0, std::memory_order_release);
}
#endif

#if defined(_WIN32)
static std::atomic<uint32_t> g_adbg_spot{0};

extern "C" uint32_t hyda_vm_run_asm(hyda::VMContext*, const uint8_t*, size_t,
                                     uint64_t);
extern "C" void hyda_vm_save_simd(void);
extern "C" void hyda_vm_restore_simd(void);
extern "C" void hyda_vm_gate_leave(void);
extern "C" void hyda_vm_gate_enter(hyda::VMContext*, const void*);
HYDA_ENTRY uint64_t hyda_vm_dispatch(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint32_t);

static uint64_t hyda_code_hash(const void* p, size_t n) {
  const uint8_t* b = static_cast<const uint8_t*>(p);
  uint64_t h = 0x9E3779B97F4A7C15ull;
  for (size_t i = 0; i < n; ++i) h = (h ^ b[i]) * 0x100000001B3ull;
  return h;
}
static const size_t kHydaCgLen = 64;
static uintptr_t g_cg_ptr[6];
static uint64_t g_cg_hash[6];
static int g_cg_n = 0;
static int g_cg_ready = 0;
static void hyda_code_guard_init(void) {
  if (g_cg_ready) return;
  g_cg_ready = 1;
  const void* ps[6] = {
      reinterpret_cast<const void*>(&hyda_vm_dispatch),
      reinterpret_cast<const void*>(&hyda_vm_run_asm),
      reinterpret_cast<const void*>(&hyda_vm_gate_enter),
      reinterpret_cast<const void*>(&hyda_vm_gate_leave),
      reinterpret_cast<const void*>(&hyda_vm_save_simd),
      reinterpret_cast<const void*>(&hyda_vm_restore_simd)};
  g_cg_n = 6;
  for (int i = 0; i < g_cg_n; ++i) {
    g_cg_ptr[i] = reinterpret_cast<uintptr_t>(ps[i]);
    g_cg_hash[i] = hyda_code_hash(ps[i], kHydaCgLen);
  }
}
static void hyda_code_guard_check(void) {
  hyda_code_guard_init();
  for (int i = 0; i < g_cg_n; ++i) {
    if (hyda_code_hash(reinterpret_cast<const void*>(g_cg_ptr[i]),
                       kHydaCgLen) != g_cg_hash[i]) {
      hyda_vm_fail(0xD3u);
    }
  }
}
__attribute__((constructor)) static void hyda_code_guard_ctor(void) {
  hyda_code_guard_init();
}

static void hyda_debug_object_check(void) {
  using NtQipFn = long(__stdcall*)(void*, unsigned long, void*, unsigned long,
                                   unsigned long*);
  void* fn = hyda_ntdll_api_hash(hyda::api_hash_c("NtQueryInformationProcess"));
  if (fn == nullptr) return;
  NtQipFn q = reinterpret_cast<NtQipFn>(fn);
  unsigned long v = 0, ret = 0;
  const void* proc = reinterpret_cast<const void*>(static_cast<intptr_t>(-1));
  if (q(const_cast<void*>(proc), 7u , &v, sizeof(v), &ret) == 0 &&
      v != 0) {
    hyda_vm_fail(0xD4u);
  }
  v = 0;
  if (q(const_cast<void*>(proc), 0x1Eu , &v, sizeof(v),
        &ret) == 0 &&
      v != 0) {
    hyda_vm_fail(0xD4u);
  }
}

static void hyda_antidump_spot(void) {
  if ((g_adbg_spot.fetch_add(1, std::memory_order_relaxed) & 63u) != 0) return;
  uintptr_t peb = 0;
  __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
  const bool dbg = peb != 0 && *reinterpret_cast<const uint8_t*>(peb + 2) != 0;

  const uint32_t ntg =
      peb != 0 ? *reinterpret_cast<const uint32_t*>(peb + 0xBC) : 0;
  uint64_t flags = 0;
  __asm__ volatile("pushfq; pop %0" : "=r"(flags));
  hyda_code_guard_check();
  hyda_debug_object_check();
  if (dbg || (ntg & 0x70u) != 0 || (flags & 0x100u) != 0) {
    hyda_vm_fail(0xD1u);
  }
}

static void hyda_antiemu_spot(void) {
  static int done = 0;
  if (done) return;
  done = 1;
  unsigned a = 0, b = 0, c = 0, d = 0;

  if (!__get_cpuid(0, &a, &b, &c, &d) || a < 1) hyda_vm_fail(0xD2u);

  if (!__get_cpuid(0x80000000u, &a, &b, &c, &d) || a < 0x80000001u) {
    hyda_vm_fail(0xD2u);
  }

  if (__get_cpuid(0x40000000u, &a, &b, &c, &d) && a >= 0x40000000u) {
    if (b == 0x54474354u  || b == 0x68636F42u ) {
      hyda_vm_fail(0xD2u);
    }
  }

  unsigned lo1 = 0, hi1 = 0, lo2 = 0, hi2 = 0;
  __asm__ volatile("rdtsc" : "=a"(lo1), "=d"(hi1));
  __asm__ volatile("lfence" ::: "memory");
  volatile uint64_t x = 1;
  for (int i = 0; i < 4096; ++i) x = x * 6364136223846793005ull + 1;
  __asm__ volatile("lfence" ::: "memory");
  __asm__ volatile("rdtsc" : "=a"(lo2), "=d"(hi2));
  const uint64_t t1 = (static_cast<uint64_t>(hi1) << 32) | lo1;
  const uint64_t t2 = (static_cast<uint64_t>(hi2) << 32) | lo2;
  if (t2 <= t1) hyda_vm_fail(0xD2u);

  uint64_t best = ~0ull;
  for (int rep = 0; rep < 3; ++rep) {
    unsigned l1 = 0, h1 = 0, l2 = 0, h2 = 0;
    __asm__ volatile("lfence; rdtsc" : "=a"(l1), "=d"(h1));
    volatile uint64_t acc = 1;
    for (int i = 0; i < 20000; ++i) acc = acc * 6364136223846793005ull + 1;
    __asm__ volatile("lfence; rdtsc" : "=a"(l2), "=d"(h2));
    const uint64_t d = ((static_cast<uint64_t>(h2) << 32) | l2) -
                       ((static_cast<uint64_t>(h1) << 32) | l1);
    if (d < best) best = d;
  }
  if (best / 20000ull > 100ull) hyda_vm_fail(0xD2u);
}
#endif

HYDA_ENTRY uint64_t hyda_vm_dispatch(uint64_t a0, uint64_t a1, uint64_t a2,
                                     uint64_t a3, uint32_t blob_rva) {
#if defined(_WIN32)

  hyda_antidump_spot();

  hyda_antiemu_spot();

  const uint8_t* base = reinterpret_cast<const uint8_t*>(hyda_image_base());
  if (base == nullptr) return 0;
#else
  extern const uint8_t __ImageBase;
  const uint8_t* base = reinterpret_cast<const uint8_t*>(&__ImageBase);
#endif

  if (!ensure_handler_shard(base)) return 0;

  if (g_audit_busy.exchange(1, std::memory_order_acq_rel) == 0) {
    hyda_vm_audit_set_base(base);
    const int rc = hyda_vm_check_integrity_step();
    g_audit_busy.store(0, std::memory_order_release);
    if (rc != 0) {
      hyda_vm_fail(hyda::HYDA_INTEGRITY_FAIL_CODE);
    }
  }

  const hyda::BlobHeader* h =
      reinterpret_cast<const hyda::BlobHeader*>(base + blob_rva);

  if (!hyda::blob_header_check(*h)) return 0;

  const uint8_t* code = reinterpret_cast<const uint8_t*>(h + 1);
  if (hyda::crc32(code, h->code_size) != h->code_crc32) return 0;

  hyda::g_import_table_rva = h->import_tab_rva;

#if defined(_WIN32)
  if (h->island_count != 0) {

    static uint32_t g_patched[4] = {0, 0, 0, 0};
    bool done = false;
    for (int i = 0; i < 4; ++i) {
      if (g_patched[i] == h->islands_rva) { done = true; break; }
    }
    if (!done) {
      void* va = const_cast<uint8_t*>(base + h->islands_rva);
      const SIZE_T len = static_cast<SIZE_T>(h->island_span);

      VirtualProtectFn vprot = vprotect();
      if (vprot == nullptr) return 0;
      DWORD old_prot = 0;
      if (!vprot(va, len, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return 0;
      }
      for (int i = 0; i < 4; ++i) {
        if (g_patched[i] == 0) { g_patched[i] = h->islands_rva; break; }
      }
    }
  }
#endif

  hyda::VMContext ctx;

  const unsigned depth = hyda::vm_gate_depth();
  if (depth >= hyda::kMaxVmDepth) return 0;
  uint8_t* const stacks = thread_vm_stacks();
  if (stacks == nullptr) return 0;
  uint8_t* const layer = stacks + static_cast<size_t>(depth) * kVmStackBytes;
  const uint64_t top = reinterpret_cast<uint64_t>(layer) + kVmStackBytes - 64;
  hyda::vm_init(ctx, top);

  hyda::vm_set_stack(ctx, reinterpret_cast<uint64_t>(layer),
                     reinterpret_cast<uint64_t>(layer) + kVmStackBytes);
  ctx.max_steps = kMaxSteps;

  ctx.image_base = reinterpret_cast<uint64_t>(base);

  ctx.r[hyda::vsl(hyda::REG_RCX)] = a0;
  ctx.r[hyda::vsl(hyda::REG_RDX)] = a1;
  ctx.r[hyda::vsl(hyda::REG_R8)] = a2;
  ctx.r[hyda::vsl(hyda::REG_R9)] = a3;

  hyda::vm_set_entry(ctx, h->entry_offset);

  const uint64_t crypt_key =
      hyda::blob_no_crypt(*h) ? 0 : hyda::crypt_key_for(blob_rva);

  const uint64_t shard_mask = h->shard_mask;
  shards_acquire(shard_mask);
#if defined(_WIN32)
  hyda_seh_install();
  const unsigned fti = hyda::thread_index();
  if (fti < hyda::kMaxThreads) {
    if (g_fault_depth[fti] < hyda::kMaxVmDepth) {
      g_fault_masks[fti][g_fault_depth[fti]++] = shard_mask;
    }
    g_fault_armed[fti] = 1;
  }
#endif
  hyda::vm_exec(ctx, code, h->code_size, crypt_key);
#if defined(_WIN32)
  if (fti < hyda::kMaxThreads) {
    if (g_fault_depth[fti] > 0) --g_fault_depth[fti];
    g_fault_armed[fti] = g_fault_depth[fti] != 0 ? 1 : 0;
  }
#endif
  shards_release(shard_mask);
  return ctx.r[hyda::vsl(hyda::REG_RAX)];
}
