#include "hyda/guard/apihash.hpp"
#include "hyda/core/export.hpp"
#include "hyda/guard/antidbg.hpp"
#include "hyda/guard/audit.hpp"
#include "hyda/codec/datblob.hpp"
#include "hyda/guard/imports.hpp"
#include "hyda/guard/hookguard.hpp"
#include "hyda/guard/integrity.hpp"

extern "C" {
uint32_t hyda::hyda_g_integrity_rva = 0;
uint64_t g_adbg_ntdll_baseline[hyda::HYDA_ADBG_NTDLL_WINDOWS] = {0};
}

#if defined(_WIN32)

#include <cstdint>
#include <cstring>

namespace {

struct ListEntry {
  uint8_t* Flink;
  uint8_t* Blink;
};

struct UnicodeString {
  uint16_t Length;
  uint16_t MaximumLength;
  wchar_t* Buffer;
};

inline uint8_t* peb() {
  uint64_t p = 0;
  __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
  return reinterpret_cast<uint8_t*>(p);
}

inline uint32_t rd32(const void* p) {
  const uint8_t* b = static_cast<const uint8_t*>(p);
  return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
         (static_cast<uint32_t>(b[2]) << 16) |
         (static_cast<uint32_t>(b[3]) << 24);
}

inline uint16_t rd16(const void* p) {
  const uint8_t* b = static_cast<const uint8_t*>(p);
  return static_cast<uint16_t>(static_cast<uint16_t>(b[0]) |
                               (static_cast<uint16_t>(b[1]) << 8));
}

inline uint64_t rd64(const void* p) {
  const uint8_t* b = static_cast<const uint8_t*>(p);
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) v = (v << 8) | b[i];
  return v;
}

inline void wr64(void* p, uint64_t v) {
  uint8_t* b = static_cast<uint8_t*>(p);
  for (int i = 0; i < 8; ++i) {
    b[i] = static_cast<uint8_t>(v & 0xFF);
    v >>= 8;
  }
}

inline size_t cstr_len(const char* s) {
  size_t n = 0;
  while (s[n] != '\0') ++n;
  return n;
}

inline void cstr_copy(char* dst, const void* src, size_t n) {
  const uint8_t* s = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < n; ++i) dst[i] = static_cast<char>(s[i]);
}

inline void mem_copy(void* dst, const void* src, size_t n) {
  uint8_t* d = static_cast<uint8_t*>(dst);
  const uint8_t* s = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < n; ++i) d[i] = s[i];
}

inline bool cstr_eq(const char* a, const char* b) {
  size_t i = 0;
  while (a[i] != '\0' && a[i] == b[i]) ++i;
  return a[i] == b[i];
}

static void* resolve_forwarder(uint8_t* base, uint32_t frva,
                               uint32_t exp_rva, uint32_t exp_size, int depth);

static void* find_export_fwd(uint8_t* base, const char* name,
                             uint32_t func_hash, uint16_t ordinal,
                             uint32_t flags, int depth);

void* find_export(uint8_t* base, const char* name, uint32_t func_hash,
                  uint16_t ordinal, uint32_t flags) {
  return find_export_fwd(base, name, func_hash, ordinal, flags, 0);
}

static void* find_export_fwd(uint8_t* base, const char* name,
                              uint32_t func_hash, uint16_t ordinal,
                              uint32_t flags, int depth) {
  if (depth > 3) return nullptr;
  const uint32_t e_lfanew = rd32(base + 0x3C);
  const uint8_t* nt = base + e_lfanew;
  if (rd32(nt) != 0x00004550u) return nullptr;
  const uint8_t* opt = nt + 24;
  if (rd16(opt) != 0x20B) return nullptr;
  const uint32_t exp_rva = rd32(opt + 112);
  const uint32_t exp_size = rd32(opt + 112 + 4);
  if (exp_rva == 0 || exp_size == 0) return nullptr;
  const uint8_t* exp = base + exp_rva;

  const uint32_t nfuncs = rd32(exp + 20);
  const uint32_t nnames = rd32(exp + 24);
  const uint32_t afuncs = rd32(exp + 28);
  const uint32_t anames = rd32(exp + 32);
  const uint32_t aords = rd32(exp + 36);
  const uint32_t ord_base = rd32(exp + 16);
  if (nfuncs == 0 || nnames == 0) return nullptr;

  if ((flags & hyda::HYDA_IMPENT_ORDINAL) != 0) {
    if (ordinal < ord_base) return nullptr;
    const uint32_t idx = ordinal - ord_base;
    if (idx >= nfuncs) return nullptr;
    const uint32_t frva = rd32(base + afuncs + idx * 4);
    if (frva == 0) return nullptr;
    if (frva >= exp_rva && frva < exp_rva + exp_size) {
      return resolve_forwarder(base, frva, exp_rva, exp_size, depth);
    }
    return base + frva;
  }

  const uint8_t* names = base + anames;
  const uint8_t* ords = base + aords;
  const uint8_t* funcs = base + afuncs;
  for (uint32_t i = 0; i < nnames; ++i) {
    const uint32_t name_rva = rd32(names + i * 4);
    if (name_rva == 0 || name_rva >= 0x10000000u) continue;
    const char* nm = reinterpret_cast<const char*>(base + name_rva);
    size_t len = 0;
    while (len < 256 && nm[len] != '\0') ++len;
    if (len == 0 || len >= 256) continue;
    const bool hit = (name != nullptr)
                         ? cstr_eq(nm, name)
                         : (hyda::api_name_hash(nm) == func_hash);
    if (!hit) continue;
    const uint16_t ord = rd16(ords + i * 2);
    if (ord >= nfuncs) continue;
    const uint32_t frva = rd32(funcs + ord * 4);
    if (frva == 0) return nullptr;
    if (frva >= exp_rva && frva < exp_rva + exp_size) {
      return resolve_forwarder(base, frva, exp_rva, exp_size, depth);
    }
    return base + frva;
  }
  return nullptr;
}

static uint8_t* find_module(uint32_t dll_hash, const void* want_base);

extern "C" void* hyda_load_dll(const char* name_utf8);

static void* resolve_forwarder(uint8_t* base, uint32_t frva,
                               uint32_t exp_rva, uint32_t exp_size, int depth) {
  (void)exp_size;
  if (depth > 3) return nullptr;
  const char* fwd = reinterpret_cast<const char*>(base + frva);
  char dll[128];
  size_t n = 0;
  while (n + 1 < sizeof(dll) && fwd[n] && fwd[n] != '.') {
    dll[n] = fwd[n];
    ++n;
  }
  dll[n] = '\0';
  if (n == 0 || fwd[n] != '.') return nullptr;
  const char* sym = fwd + n + 1;

  uint8_t* tmod = find_module(hyda::api_name_hash(dll), nullptr);
  if (tmod == nullptr) {
    void* loaded = hyda_load_dll(dll);
    if (loaded == nullptr) return nullptr;
    tmod = reinterpret_cast<uint8_t*>(loaded);
  }

  if (sym[0] == '#') {
    uint32_t o = 0;
    for (const char* p = sym + 1; *p >= '0' && *p <= '9'; ++p) {
      o = o * 10 + static_cast<uint32_t>(*p - '0');
    }
    return find_export_fwd(tmod, nullptr, 0, static_cast<uint16_t>(o),
                            hyda::HYDA_IMPENT_ORDINAL, depth + 1);
  }
  return find_export_fwd(tmod, sym, 0, 0, 0, depth + 1);
}

uint8_t* find_module(uint32_t dll_hash, const void* want_base) {
  uint8_t* p = peb();
  if (p == nullptr) return nullptr;
  uint8_t* ldr = reinterpret_cast<uint8_t*>(rd64(p + 0x18));
  if (ldr == nullptr) return nullptr;
  uint8_t* head = ldr + 0x20;
  uint8_t* link = reinterpret_cast<ListEntry*>(head)->Flink;
  for (int guard = 0; guard < 512; ++guard) {
    if (link == nullptr || link == head) break;
    uint8_t* entry = link - 0x10;
    const uint64_t mod_base = rd64(entry + 0x30);
    const uint8_t* uname = entry + 0x58;
    const uint16_t ulen = rd16(uname);
    const uint64_t ubuf = rd64(uname + 8);
    if (mod_base != 0) {
      if (want_base != nullptr) {
        const uint64_t a = reinterpret_cast<uint64_t>(want_base);
        if (a >= mod_base && a < mod_base + 0x01000000ull) {
          return reinterpret_cast<uint8_t*>(mod_base);
        }
      } else if (dll_hash == 0) {
        return reinterpret_cast<uint8_t*>(mod_base);
      } else if (ubuf != 0 && ulen != 0 && (ulen % 2) == 0) {
        const uint16_t* w = reinterpret_cast<const uint16_t*>(ubuf);
        if (hyda::api_name_hash16(w, ulen / 2) == dll_hash) {
          return reinterpret_cast<uint8_t*>(mod_base);
        }
      }
    }
    link = reinterpret_cast<ListEntry*>(link)->Flink;
    if (link == nullptr) break;
  }
  return nullptr;
}

using LoadLibraryAFn = void*(__stdcall*)(const char*);

[[maybe_unused]] size_t to_wide(const char* in, size_t n, wchar_t* out,
                                size_t out_cap) {
  size_t k = 0;
  for (size_t i = 0; i < n && k + 1 < out_cap; ++i) {
    out[k++] = static_cast<wchar_t>(static_cast<unsigned char>(in[i]));
  }
  return k;
}

const uint8_t* image_dir(uint8_t* image_base, size_t* dir_len) {
  uint8_t* p = peb();
  if (p == nullptr) return nullptr;
  const uint64_t params = rd64(p + 0x20);
  if (params == 0) return nullptr;
  const uint8_t* up = reinterpret_cast<const uint8_t*>(params);
  const uint16_t len = rd16(up + 0x60);
  const uint64_t buf = rd64(up + 0x68);
  if (buf == 0 || len == 0) return nullptr;
  const uint16_t* w = reinterpret_cast<const uint16_t*>(buf);
  size_t k = len / 2;
  while (k > 0 && w[k - 1] != L'\\' && w[k - 1] != L'/') --k;
  *dir_len = k;
  return reinterpret_cast<const uint8_t*>(w);
}

}

extern "C" void* hyda_resolve_import(uint32_t dll_hash, uint32_t func_hash,
                                     uint16_t ordinal, uint32_t flags) {
  uint8_t* base = find_module(dll_hash, nullptr);
  if (base == nullptr) return nullptr;
  return find_export(base, nullptr, func_hash, ordinal, flags);
}

extern "C" void* hyda_kernel32_api(const char* name) {
  uint8_t* k32 = find_module(hyda::api_name_hash("kernel32.dll"), nullptr);
  if (k32 == nullptr) {
    void* m = hyda_load_dll("kernel32.dll");
    if (m == nullptr) return nullptr;
    k32 = reinterpret_cast<uint8_t*>(m);
  }
  return find_export(k32, name, 0, 0, 0);
}

extern "C" void* hyda_kernel32_api_hash(uint32_t func_hash) {
  uint8_t* k32 = find_module(hyda::api_name_hash("kernel32.dll"), nullptr);
  if (k32 == nullptr) {
    void* m = hyda_load_dll("kernel32.dll");
    if (m == nullptr) return nullptr;
    k32 = reinterpret_cast<uint8_t*>(m);
  }
  return find_export(k32, nullptr, func_hash, 0, 0);
}

extern "C" void* hyda_ntdll_api_hash(uint32_t func_hash) {
  uint8_t* nt = find_module(hyda::api_name_hash("ntdll.dll"), nullptr);
  if (nt == nullptr) {
    void* m = hyda_load_dll("ntdll.dll");
    if (m == nullptr) return nullptr;
    nt = reinterpret_cast<uint8_t*>(m);
  }
  return find_export(nt, nullptr, func_hash, 0, 0);
}

struct alignas(16) AdContext64 {
  uint8_t p1[0x30];
  uint32_t ContextFlags;
  uint8_t p2[0x44 - 0x34];
  uint32_t EFlags;
  uint64_t dr[4];
  uint64_t dr6;
  uint64_t dr7;
  uint8_t rest[0x4D0 - 0x78];
};
static_assert(sizeof(AdContext64) == 0x4D0, "x64 CONTEXT must be 1232 bytes");

constexpr uint32_t kHashNtQip        = hyda::api_hash_c("NtQueryInformationProcess");
constexpr uint32_t kHashNtGetCtx     = hyda::api_hash_c("NtGetContextThread");
constexpr uint32_t kHashNtQuerySys   = hyda::api_hash_c("NtQuerySystemInformation");
constexpr uint32_t kHashNtQueryVirt  = hyda::api_hash_c("NtQueryVirtualMemory");
constexpr uint32_t kHashRtlAddVEH    = hyda::api_hash_c("RtlAddVectoredExceptionHandler");

constexpr uint32_t kNtdllWinHashes[hyda::HYDA_ADBG_NTDLL_WINDOWS] = {
    kHashNtQip, kHashNtGetCtx, kHashNtQuerySys, kHashNtQueryVirt};
constexpr uint32_t kNtdllWinSize = 128u;

static uint8_t* g_adbg_nt = nullptr;

static uint8_t* adbg_nt() {
  if (g_adbg_nt == nullptr) {
    g_adbg_nt = find_module(hyda::api_name_hash("ntdll.dll"), nullptr);
  }
  return g_adbg_nt;
}

static void* adbg_nt_api(uint32_t func_hash) {
  uint8_t* nt = adbg_nt();
  if (nt == nullptr) return nullptr;
  return find_export(nt, nullptr, func_hash, 0, 0);
}

extern "C" __attribute__((naked, noinline, noclone)) void adbg_trap_site(void) {
  __asm__(".intel_syntax noprefix\n"
          "int3\n"
          "ret\n"
          ".att_syntax prefix\n");
}

static volatile uint32_t g_adbg_trap_state = 0;

static void* g_adbg_veh = nullptr;

using AdAddVEHFn = void*(__stdcall*)(uint32_t, int32_t(__stdcall*)(void*));

static int32_t __stdcall adbg_veh(void* ep) {
  if (g_adbg_trap_state != 1) return 0;
  if (ep == nullptr) return 0;

  const auto* epb = static_cast<const uint8_t*>(ep);
  const uint64_t rec = rd64(epb);
  const uint64_t ctx = rd64(epb + 8);
  if (rec == 0 || ctx == 0) return 0;

  if (rd32(reinterpret_cast<const void*>(rec + 0)) != 0x80000003u) return 0;
  const uint64_t a = rd64(reinterpret_cast<const void*>(rec + 0x10));
  const uint64_t site = reinterpret_cast<uint64_t>(&adbg_trap_site);

  if (a != site && a != site + 1) return 0;

  const uint8_t* p0 = reinterpret_cast<const uint8_t*>(site);
  const uint64_t resume = (p0[0] == 0xCC) ? site + 1 : site;

  wr64(reinterpret_cast<void*>(ctx + 0xF8), resume);
  g_adbg_trap_state = 2;
  return -1;
}

static bool adbg_veh_install(void) {
  if (g_adbg_veh != nullptr) return true;
  void* add = adbg_nt_api(kHashRtlAddVEH);
  if (add == nullptr) return false;
  g_adbg_veh = reinterpret_cast<AdAddVEHFn>(add)(1u, &adbg_veh);
  return g_adbg_veh != nullptr;
}

static uint64_t adbg_peb_being(void) {
  const uint8_t* b = peb();
  if (b == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  return static_cast<uint64_t>(
      *reinterpret_cast<const volatile uint8_t*>(b + 0x02));
}

static uint64_t adbg_ntglobal(void) {
  const uint8_t* b = peb();
  if (b == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  return static_cast<uint64_t>(rd32(b + 0xBC));
}

static uint64_t adbg_heap_force(void) {
  const uint8_t* b = peb();
  if (b == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  const uint64_t heap = rd64(b + 0x30);
  if (heap < 0x10000) return hyda::HYDA_ADBG_SENTINEL;

  return static_cast<uint64_t>(
      rd32(reinterpret_cast<const void*>(heap + 0x74)));
}

static uint64_t adbg_qip(uint32_t cls, uint32_t len) {
  using NtQipFn = long(__stdcall*)(void*, uint32_t, void*, uint32_t,
                                    uint32_t*);
  void* fn = adbg_nt_api(kHashNtQip);
  if (fn == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  uint64_t out = 0;
  uint32_t ret = 0;

  const long st = reinterpret_cast<NtQipFn>(fn)(
      reinterpret_cast<void*>(0xFFFFFFFFFFFFFFFFull), cls, &out, len, &ret);
  if (st != 0) return hyda::HYDA_ADBG_SENTINEL;
  return out;
}

static uint64_t adbg_dr(uint32_t arg) {
  using NtGetCtxFn = long(__stdcall*)(void*, void*);
  void* fn = adbg_nt_api(kHashNtGetCtx);
  if (fn == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  AdContext64 c;
  uint8_t* cb = reinterpret_cast<uint8_t*>(&c);
  for (unsigned i = 0; i < sizeof(c); ++i) cb[i] = 0;
  c.ContextFlags = 0x00100010u;

  const long st = reinterpret_cast<NtGetCtxFn>(fn)(
      reinterpret_cast<void*>(0xFFFFFFFFFFFFFFFEull), &c);
  if (st != 0) return hyda::HYDA_ADBG_SENTINEL;
  if (arg == 0) return c.dr[0] | (c.dr[1] << 32);
  if (arg == 1) return c.dr[2] | (c.dr[3] << 32);
  if (arg == 2) return c.dr7;
  return hyda::HYDA_ADBG_SENTINEL;
}

static uint64_t adbg_tf(void) {
  uint64_t f = 0;
  __asm__ volatile("pushfq\n\tpopq %0" : "=r"(f));
  return (f >> 8) & 1u;
}

static uint64_t adbg_int3(void) {
  if (!adbg_veh_install()) return hyda::HYDA_ADBG_SENTINEL;
  g_adbg_trap_state = 1;
  adbg_trap_site();
  const uint32_t st = g_adbg_trap_state;
  g_adbg_trap_state = 0;
  return (st == 2) ? 1u : 0u;
}

static uint64_t adbg_ntdll_crc(uint32_t arg) {
  if (arg >= hyda::HYDA_ADBG_NTDLL_WINDOWS) return hyda::HYDA_ADBG_SENTINEL;
  void* fn = adbg_nt_api(kNtdllWinHashes[arg]);
  if (fn == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  const uint32_t crc = hyda::integrity_crc32(
      reinterpret_cast<const uint8_t*>(fn), kNtdllWinSize);
  if (g_adbg_ntdll_baseline[arg] == 0) {
    g_adbg_ntdll_baseline[arg] =
        static_cast<uint64_t>(crc) ^ hyda::adbg_state_mask(0x10 + arg);
  }
  return static_cast<uint64_t>(crc);
}

constexpr uint32_t kDebugModuleHashes[] = {
    hyda::api_hash_c("x64dbg.exe"),  hyda::api_hash_c("x64dbg.dll"),
    hyda::api_hash_c("x32dbg.exe"),  hyda::api_hash_c("x32dbg.dll"),
    hyda::api_hash_c("x96dbg.exe"),
    hyda::api_hash_c("ollydbg.exe"), hyda::api_hash_c("ollydbg.dll"),
    hyda::api_hash_c("windbg.exe"),
    hyda::api_hash_c("ida.exe"),     hyda::api_hash_c("ida64.exe"),
    hyda::api_hash_c("idaq.exe"),    hyda::api_hash_c("idaq64.exe"),
    hyda::api_hash_c("immunitydebugger.exe"),
    hyda::api_hash_c("cheatengine-x86_64.exe"),
    hyda::api_hash_c("cheatengine-i386.exe"),
    hyda::api_hash_c("vehdebug.dll"),
    hyda::api_hash_c("vehdebug-x86_64.dll"),
    hyda::api_hash_c("vehdebug-i386.dll"),
};
constexpr uint32_t kDebugModuleHashCount =
    sizeof(kDebugModuleHashes) / sizeof(kDebugModuleHashes[0]);

static uint64_t adbg_modules_scan(void) {
  uint8_t* p = peb();
  if (p == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  uint8_t* ldr = reinterpret_cast<uint8_t*>(rd64(p + 0x18));
  if (ldr == nullptr) return hyda::HYDA_ADBG_SENTINEL;
  uint8_t* head = ldr + 0x20;
  uint8_t* link = reinterpret_cast<ListEntry*>(head)->Flink;
  uint64_t hits = 0;
  for (int guard = 0; guard < 512; ++guard) {
    if (link == nullptr || link == head) break;
    uint8_t* entry = link - 0x10;
    const uint8_t* uname = entry + 0x58;
    const uint16_t ulen = rd16(uname);
    const uint64_t ubuf = rd64(uname + 8);
    if (ubuf != 0 && ulen != 0 && (ulen % 2) == 0) {
      const uint32_t h = hyda::api_name_hash16(
          reinterpret_cast<const uint16_t*>(ubuf), ulen / 2);
      for (uint32_t i = 0; i < kDebugModuleHashCount; ++i) {
        if (h == kDebugModuleHashes[i]) { ++hits; break; }
      }
    }
    link = reinterpret_cast<ListEntry*>(link)->Flink;
    if (link == nullptr) break;
  }
  return hits;
}

extern "C" __attribute__((noinline, noclone))
uint64_t hyda_adbg_read(uint32_t sel, uint32_t arg) {
  switch (sel) {
    case hyda::ADBG_PEB_BEING:   return adbg_peb_being();
    case hyda::ADBG_NTGLOBAL:    return adbg_ntglobal();
    case hyda::ADBG_HEAP_FORCE:  return adbg_heap_force();
    case hyda::ADBG_DEBUG_PORT:  return adbg_qip(7u, 8u);
    case hyda::ADBG_DEBUG_OBJ:   return adbg_qip(30u, 8u);
    case hyda::ADBG_DEBUG_FLAGS: return adbg_qip(31u, 4u);
    case hyda::ADBG_DR:          return adbg_dr(arg);
    case hyda::ADBG_TF:          return adbg_tf();
    case hyda::ADBG_INT3:        return adbg_int3();
    case hyda::ADBG_NTDLL_CRC:   return adbg_ntdll_crc(arg);
    case hyda::ADBG_MODULE_SCAN: return adbg_modules_scan();
    default:                     return hyda::HYDA_ADBG_SENTINEL;
  }
}

static constexpr uint32_t kHashExitProcess = 0x52A4CF3Au;

extern "C" __attribute__((noreturn)) void hyda_vm_fail(uint32_t code) {
  using ExitProcessFn = void(__stdcall*)(uint32_t);
  uint8_t* k32 = find_module(hyda::api_name_hash("kernel32.dll"), nullptr);
  if (k32 != nullptr) {
    void* ep = find_export(k32, nullptr, kHashExitProcess, 0, 0);
    if (ep != nullptr) {
      reinterpret_cast<ExitProcessFn>(ep)(code);
    }
  }

  __builtin_trap();
}

extern "C" void* hyda_image_base() {
  return find_module(0, reinterpret_cast<const void*>(&hyda_image_base));
}

extern "C" void* hyda_load_dll(const char* name_utf8) {
  if (name_utf8 == nullptr) return nullptr;
  uint8_t* k32 = find_module(hyda::api_name_hash("kernel32.dll"), nullptr);
  if (k32 == nullptr) return nullptr;
  LoadLibraryAFn load = reinterpret_cast<LoadLibraryAFn>(
      find_export(k32, "LoadLibraryA", 0, 0, 0));
  if (load == nullptr) return nullptr;

  uint8_t* self = find_module(0, reinterpret_cast<const void*>(&hyda_image_base));
  size_t dir_len = 0;
  const uint8_t* dir = image_dir(self, &dir_len);
  if (dir != nullptr && dir_len > 0) {
    char full[640];
    size_t k = 0;
    for (size_t i = 0; i < dir_len && k + 2 < sizeof(full); ++i) {
      full[k++] = static_cast<char>(dir[i] < 128 ? dir[i] : '?');
    }
    const size_t n = cstr_len(name_utf8);
    for (size_t i = 0; i < n && k + 2 < sizeof(full); ++i) full[k++] = name_utf8[i];
    full[k] = '\0';
    void* h = load(full);
    if (h != nullptr) return h;
  }
  return load(name_utf8);
}

static uint8_t* g_audit_base = nullptr;

extern "C" {
HYDA_ENTRY_DATA hyda::AuditPolicy g_audit_policy = {1u, 1u,
                                                    hyda::HYDA_HOOKREF_BATCH, 0u};
}

static uint32_t g_audit_tick = 0;

static bool audit_protect(void* p, uint32_t n, uint32_t prot) {
  using VirtualProtectFn = int(__stdcall*)(void*, size_t, uint32_t, uint32_t*);
  VirtualProtectFn vp = reinterpret_cast<VirtualProtectFn>(
      hyda_kernel32_api_hash(0x7851C633u));
  if (vp == nullptr || p == nullptr || n == 0) return false;
  uint32_t old = 0;
  return vp(p, static_cast<size_t>(n), prot, &old) != 0;
}
static bool audit_make_writable(void* p, uint32_t n) {
  return audit_protect(p, n, 0x04u );
}

static uint32_t g_audit_image_size = 0;

static hyda::IntegrityChunk g_audit_chunks[hyda::HYDA_INTEGRITY_MAX_CHUNKS];
static uint32_t g_audit_chunk_count = 0;

static uint32_t g_audit_cursor = 0;

static uint32_t g_adbg_cursor = 0;
static uint64_t g_adbg_poison = 0;

static hyda::HookRef g_audit_hookrefs[hyda::HYDA_HOOKREF_MAX];
static uint32_t g_audit_hookref_n = 0;
static uint32_t g_audit_hookref_cursor = 0;

extern "C" __attribute__((noinline, noclone))
uint32_t hyda_audit_crc32(const uint8_t* p, uint32_t n) {
  return hyda::integrity_crc32(p, n);
}

extern "C" __attribute__((noinline, noclone))
void hyda_audit_fail(uint32_t code) {
  void (*volatile fp)(uint32_t) = hyda_vm_fail;
  fp(code);
}

extern "C" __attribute__((section("hydafn_audit"), noinline, noclone, used))
uint32_t hyda_audit_run(uint32_t chunk_count, uint32_t hook_count,
                         uint32_t period, uint32_t adbg_batch) {

  if (period == 0 || period > hyda::HYDA_AUDIT_PERIOD_MAX ||
      chunk_count == 0 || chunk_count > hyda::HYDA_INTEGRITY_MAX_CHUNKS ||
      hook_count > hyda::HYDA_AUDIT_REFS_MAX ||
      adbg_batch > hyda::HYDA_ADBG_BATCH_MAX) {
    hyda_audit_fail(hyda::HYDA_INTEGRITY_FAIL_CODE);
    return hyda::HYDA_AUDIT_BAD;
  }
  const uint8_t* base = g_audit_base;
  const uint32_t total = g_audit_chunk_count;
  if (base != nullptr && total != 0) {
    uint32_t cur = g_audit_cursor;
    if (cur >= total) cur = 0;
    for (uint32_t i = 0; i < chunk_count; ++i) {
      const hyda::IntegrityChunk* c = &g_audit_chunks[cur];

      const hyda::AuditMask mk = hyda::audit_mask_for(cur);
      const uint32_t rva = c->rva ^ mk.rva;
      const uint32_t size = c->size ^ mk.size;
      const uint32_t want = c->crc32 ^ mk.crc;

      const uint32_t img = g_audit_image_size;
      if (size > hyda::HYDA_INTEGRITY_WINDOW || img == 0 || rva > img ||
          size > img - rva) {
        hyda_audit_fail(hyda::HYDA_INTEGRITY_FAIL_CODE);
        return hyda::HYDA_AUDIT_BAD;
      }
      if (size != 0) {
        const uint8_t* p = base + rva;
        const uint32_t got = hyda_audit_crc32(p, size);
        if (got != want) {
          hyda_audit_fail(hyda::HYDA_INTEGRITY_FAIL_CODE);
          return hyda::HYDA_AUDIT_BAD;
        }
      }
      ++cur;
      if (cur >= total) cur = 0;
    }
    g_audit_cursor = cur;
  }

  const uint32_t hn = g_audit_hookref_n;
  if (base != nullptr && hn != 0) {
    uint32_t hc = g_audit_hookref_cursor;
    if (hc >= hn) hc = 0;
    for (uint32_t i = 0; i < hook_count; ++i) {
      const hyda::HookRef* r = &g_audit_hookrefs[hc];

      const uint64_t mk = hyda::audit_hookref_mask_for(hc);
      const uint32_t iat_rva = r->iat_rva ^ static_cast<uint32_t>(mk);
      const uint64_t resolved = r->resolved ^ mk;
      const uint64_t now =
          *reinterpret_cast<const uint64_t*>(base + iat_rva);
      if (now != resolved) {
        hyda_audit_fail(hyda::HYDA_INTEGRITY_FAIL_CODE);
        return hyda::HYDA_AUDIT_BAD;
      }
      ++hc;
      if (hc >= hn) hc = 0;
    }
    g_audit_hookref_cursor = hc;
  }

  const uint32_t sanction = hyda::audit_adbg_phase(
      [](uint32_t sel, uint32_t arg) { return hyda_adbg_read(sel, arg); },
      adbg_batch, g_adbg_cursor, g_adbg_poison);
  if (sanction != 0) {
    hyda_audit_fail(sanction);
    return hyda::HYDA_AUDIT_BAD;
  }
  return hyda::HYDA_AUDIT_OK;
}

static void audit_read_image_size(const uint8_t* base) {
  if (g_audit_image_size != 0 || base == nullptr) return;
  const uint32_t lfanew = *reinterpret_cast<const uint32_t*>(base + 0x3Cu);

  g_audit_image_size =
      *reinterpret_cast<const uint32_t*>(base + lfanew + 24u + 0x38u);
}

extern "C" void hyda_vm_audit_set_base(const uint8_t* base) {
  g_audit_base = const_cast<uint8_t*>(base);
  audit_read_image_size(base);
}

extern "C" int hyda_vm_verify_integrity(uint32_t manifest_rva) {
  if (manifest_rva == 0) return 0;
  uint8_t* base = find_module(0, reinterpret_cast<const void*>(&hyda_vm_verify_integrity));
  if (base == nullptr) return 1;
  audit_read_image_size(base);
  const hyda::IntegrityManifest* m =
      reinterpret_cast<const hyda::IntegrityManifest*>(base + manifest_rva);
  if (m->magic != hyda::integrity_magic() ||
      m->version != hyda::HYDA_INTEGRITY_VERSION || m->count == 0 ||
      m->count > hyda::HYDA_INTEGRITY_MAX_CHUNKS || m->chunks_rva == 0) {
    return 1;
  }

  uint8_t* dat = base + m->chunks_rva;
  const uint32_t dat_bytes =
      static_cast<uint32_t>(sizeof(hyda::DatHeader)) +
      m->count * static_cast<uint32_t>(sizeof(hyda::IntegrityChunk));
  if (!audit_make_writable(dat, dat_bytes)) return 1;
  const uint64_t dat_key = hyda::dat_key_for(m->chunks_rva);
  hyda::DatHeader dh;
  if (!hyda::dat_open(dat, dat_bytes, dat_key, &dh)) return 1;

  if (dh.count != m->count || dh.salt != m->salt ||
      dh.self_crc32 != m->self_crc32) {
    hyda::dat_close(dat, dh.total_size, dat_key);
    return 1;
  }

  const uint8_t* payload = dat + sizeof(hyda::DatHeader);
  const uint64_t crypt_key = hyda::integrity_key_for(m->salt, manifest_rva);
  uint32_t n = 0;
  uint32_t running = 0;
  for (uint32_t i = 0; i < m->count; ++i) {
    const uint32_t off = i * static_cast<uint32_t>(sizeof(hyda::IntegrityChunk));
    hyda::IntegrityChunk c;
    hyda::integrity_crypt_range(payload, off,
                                static_cast<uint32_t>(sizeof(c)), crypt_key,
                                reinterpret_cast<uint8_t*>(&c));
    running = hyda::integrity_crc32(reinterpret_cast<const uint8_t*>(&c),
                                    sizeof(c), running);
    const hyda::AuditMask mk = hyda::audit_mask_for(i);
    hyda::IntegrityChunk& dst = g_audit_chunks[n++];
    dst.rva = c.rva ^ mk.rva;
    dst.size = c.size ^ mk.size;
    dst.crc32 = c.crc32 ^ mk.crc;
    dst.flags = 0;
  }
  hyda::dat_close(dat, dh.total_size, dat_key);

  audit_protect(dat, dat_bytes, 0x02u );
  if (running != m->self_crc32 || running != dh.self_crc32) return 1;
  g_audit_chunk_count = n;
  g_audit_cursor = 0;
  g_audit_base = base;

  g_adbg_cursor = hyda::adbg_cursor_mask();
  g_adbg_poison = hyda::adbg_poison_mask();

  if (hyda_audit_run(m->count, 0, 1, hyda::HYDA_ADBG_CHECK_COUNT) !=
      hyda::HYDA_AUDIT_OK) {
    return 1;
  }
  return 0;
}

extern "C" int hyda_vm_check_integrity_step(void) {
  if (g_audit_base == nullptr) return 0;
  const uint32_t period = g_audit_policy.period;

  if (period == 0 || period > hyda::HYDA_AUDIT_PERIOD_MAX) return 1;
  if (++g_audit_tick < period) return 0;
  g_audit_tick = 0;

  if (hyda_audit_run(g_audit_policy.chunks, g_audit_policy.refs, period,
                     hyda::HYDA_ADBG_TICK_BATCH) != hyda::HYDA_AUDIT_OK) {
    return 1;
  }
  return 0;
}

static uint32_t g_orig_entry_rva = 0;

extern "C" {
uint8_t* g_orig_entry_va = nullptr;
}

extern "C" int hyda_vm_init_imports(uint32_t table_rva) {
  uint8_t* base = find_module(0, reinterpret_cast<const void*>(&hyda_vm_init_imports));
  if (base == nullptr) return 1;
  const hyda::RuntimeImportTable* t =
      reinterpret_cast<const hyda::RuntimeImportTable*>(base + table_rva);
  if (t->magic != hyda::HYDA_RIMPTAB_MAGIC) return 1;
  if (t->count > 8192) return 1;

  hyda::hyda_g_integrity_rva = t->integrity_rva;
  if (hyda_vm_verify_integrity(t->integrity_rva) != 0) {
    return static_cast<int>(hyda::HYDA_INTEGRITY_FAIL_CODE);
  }

  g_orig_entry_rva = t->orig_entry_rva;
  {
    uint8_t* b2 = find_module(0, reinterpret_cast<const void*>(&hyda_vm_init_imports));
    g_orig_entry_va = b2 ? (b2 + g_orig_entry_rva) : nullptr;
  }
  const uint8_t* entries = reinterpret_cast<const uint8_t*>(t) + 24;
  const uint8_t* names = entries + static_cast<size_t>(t->count) * 24;

  for (uint32_t i = 0; i < t->count; ++i) {
    hyda::RuntimeImportEntry e;
    mem_copy(&e, entries + static_cast<size_t>(i) * 24, sizeof(e));
    if (e.dll_name_len == 0 || e.dll_name_len > 512) return 1;
    char name[520];
    cstr_copy(name, names + e.dll_name_off, e.dll_name_len);
    name[e.dll_name_len] = '\0';
    hyda::runtime_import_name_crypt(reinterpret_cast<uint8_t*>(name),
                                    e.dll_name_len, t->name_key);
    name[e.dll_name_len] = '\0';

    uint8_t* mod = find_module(hyda::api_name_hash(name), nullptr);
    if (mod == nullptr) {
      void* loaded = hyda_load_dll(name);
      if (loaded == nullptr) return 1;
      mod = reinterpret_cast<uint8_t*>(loaded);
    }
    void* fn = find_export(mod, nullptr, e.func_hash, e.ordinal, e.flags);
    if (fn == nullptr) {

      fn = find_export(mod, nullptr, 0, 0, 0);
      if (fn == nullptr) return 1;
    }

    wr64(base + e.iat_rva, reinterpret_cast<uint64_t>(fn));

    if (g_audit_hookref_n < hyda::HYDA_HOOKREF_MAX) {
      const uint32_t idx = g_audit_hookref_n++;
      const uint64_t mk = hyda::audit_hookref_mask_for(idx);
      hyda::HookRef& r = g_audit_hookrefs[idx];
      r.iat_rva = e.iat_rva ^ static_cast<uint32_t>(mk);
      r.resolved = reinterpret_cast<uint64_t>(fn) ^ mk;
      r.dll_hash = hyda::api_name_hash(name);
    }
  }
  return 0;
}

extern "C" void* hyda_resolve_table_entry(const hyda::RuntimeImportTable* tab,
                                          uint32_t index) {
  if (tab == nullptr || index == 0 || index > tab->count) return nullptr;
  const hyda::RuntimeImportEntry& e = tab->entries[index - 1];
  if (e.dll_name_len == 0 || e.dll_name_len > 512) return nullptr;
  const uint8_t* entries = reinterpret_cast<const uint8_t*>(tab) + 24;
  const uint8_t* names = entries + static_cast<size_t>(tab->count) * 24;
  char name[520];
  cstr_copy(name, names + e.dll_name_off, e.dll_name_len);
  name[e.dll_name_len] = '\0';
  hyda::runtime_import_name_crypt(reinterpret_cast<uint8_t*>(name),
                                  e.dll_name_len, tab->name_key);
  name[e.dll_name_len] = '\0';
  uint8_t* mod = find_module(hyda::api_name_hash(name), nullptr);
  if (mod == nullptr) {
    void* loaded = hyda_load_dll(name);
    if (loaded == nullptr) return nullptr;
    mod = reinterpret_cast<uint8_t*>(loaded);
  }
  return find_export(mod, nullptr, e.func_hash, e.ordinal, e.flags);
}

extern "C" __attribute__((naked, noinline)) void hyda_vm_jump_to_entry(void) {
  __asm__(".intel_syntax noprefix\n"
          "mov r11, qword ptr [rip + g_orig_entry_va]\n"
          "jmp r11\n"
          ".att_syntax prefix\n");
}

#else

extern "C" void* hyda_resolve_import(uint32_t, uint32_t, uint16_t, uint32_t) {
  return nullptr;
}
extern "C" void* hyda_image_base() { return nullptr; }
extern "C" void* hyda_kernel32_api(const char*) { return nullptr; }
extern "C" int hyda_vm_verify_integrity(uint32_t) { return 0; }
extern "C" int hyda_vm_check_integrity_step(void) { return 0; }
extern "C" int hyda_vm_check_hookrefs_step(void) { return 0; }

extern "C" void hyda_vm_audit_set_base(const uint8_t*) {}
extern "C" uint32_t hyda_audit_run(uint32_t, uint32_t, uint32_t, uint32_t) {
  return hyda::HYDA_AUDIT_OK;
}
extern "C" __attribute__((noreturn)) void hyda_vm_fail(uint32_t) {
  __builtin_trap();
}
extern "C" void* hyda_resolve_table_entry(const hyda::RuntimeImportTable*,
                                          uint32_t) {
  return nullptr;
}
extern "C" void* hyda_load_dll(const char*) { return nullptr; }
extern "C" int hyda_vm_init_imports(uint32_t) { return 1; }
extern "C" __attribute__((noreturn)) void hyda_vm_jump_to_entry(void) {
  __builtin_unreachable();
}

#endif
