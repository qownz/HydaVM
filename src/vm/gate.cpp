#include "hyda/vm/gate.hpp"

#include "hyda/vm/fpstate.hpp"
#include "hyda/core/thread.hpp"

#include "hyda/guard/apihash.hpp"
#include "hyda/guard/imports.hpp"
#include "hyda/native/island.hpp"
#include "hyda/native/island_mut.hpp"
#include "hyda/vm/vm.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

#define HYDA_OFF_RSP 32
#define HYDA_OFF_FLAGS 136

#define HYDA_S2(x) #x
#define HYDA_S(x) HYDA_S2(x)

static_assert(hyda::kFpYmmOff == 576, "YMM high-half offset changed");
static_assert(offsetof(hyda::VMContext, r) == 0, "VMContext.r must be at offset 0");
static_assert(hyda::REG_RSP * 8 == HYDA_OFF_RSP, "REG_RSP offset changed");
static_assert(hyda::REG_RFLAGS * 8 == HYDA_OFF_FLAGS, "REG_RFLAGS offset changed");

}

struct HydaGateSlot {
  void* ctx;
  void* island;
  void* rsp;
};

#define HYDA_SLOT_SIZE 24
#define HYDA_SLOT_CTX 0
#define HYDA_SLOT_ISLAND 8
#define HYDA_SLOT_RSP 16

static_assert(sizeof(HydaGateSlot) == HYDA_SLOT_SIZE, "gate slot size");
static_assert(offsetof(HydaGateSlot, ctx) == HYDA_SLOT_CTX, "slot.ctx offset");
static_assert(offsetof(HydaGateSlot, island) == HYDA_SLOT_ISLAND,
              "slot.island offset");
static_assert(offsetof(HydaGateSlot, rsp) == HYDA_SLOT_RSP, "slot.rsp offset");

extern "C" {

__attribute__((used)) HYDA_INTERNAL hyda::HydaFpState* hyda_gate_fp_ptr = nullptr;

__attribute__((used)) HYDA_INTERNAL uint8_t hyda_gate_avx = 0;

__attribute__((used)) HYDA_INTERNAL HydaGateSlot hyda_gate_slots[hyda::kMaxVmDepth];
__attribute__((used)) HYDA_INTERNAL uint64_t hyda_gate_depth = 0;
__attribute__((used)) HYDA_INTERNAL void* hyda_gate_ctx = nullptr;
__attribute__((used)) HYDA_INTERNAL void* hyda_gate_island = nullptr;
__attribute__((used)) HYDA_INTERNAL void* hyda_gate_rsp = nullptr;
}

namespace hyda {

unsigned vm_gate_depth() { return static_cast<unsigned>(hyda_gate_depth); }

uint32_t g_import_table_rva = 0;

}

extern "C" void* hyda_resolve_table_entry(const hyda::RuntimeImportTable* tab,
                                          uint32_t index);

namespace {

std::atomic<uint32_t> g_island_lock{0};

void island_lock() {
  for (;;) {
    uint32_t expected = 0;
    if (g_island_lock.compare_exchange_weak(expected, 1u,
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

void island_unlock() { g_island_lock.store(0u, std::memory_order_release); }

inline hyda::IslandHeader* island_header_of(const void* island) {
  const uint8_t* addr = static_cast<const uint8_t*>(island);
  if (addr == nullptr) return nullptr;
  if (reinterpret_cast<uintptr_t>(addr) < sizeof(hyda::IslandHeader)) {
    return nullptr;
  }
  hyda::IslandHeader* h = const_cast<hyda::IslandHeader*>(
      reinterpret_cast<const hyda::IslandHeader*>(
          addr - sizeof(hyda::IslandHeader)));
  if (!hyda::island_header_check(*h)) return nullptr;
  return h;
}

std::atomic<uint32_t> g_island_mut_epoch{0};

uint32_t island_mut_key(const void* island) {
  const uint32_t forced = hyda_g_island_mut_k;
  if (forced != 0xFFFFFFFFu) return forced;
  uint64_t z = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(island)) ^
               (static_cast<uint64_t>(g_island_mut_epoch.fetch_add(
                    1u, std::memory_order_relaxed) + 1u) *
                0x9E3779B97F4A7C15ull);
  z ^= z >> 30;
  z *= 0xBF58476D1CE4E5B9ull;
  z ^= z >> 27;
  z *= 0x94D049BB133111EBull;
  z ^= z >> 31;
  return static_cast<uint32_t>(z ^ (z >> 32));
}

bool island_acquire(hyda::VMContext* ctx, const void* island) {
  hyda::IslandHeader* h = island_header_of(island);
  if (h == nullptr) return false;
  const uint32_t rva = static_cast<uint32_t>(
      reinterpret_cast<uintptr_t>(island) - ctx->image_base);
  const uint64_t key = hyda::island_key_for(h->salt, rva);
  island_lock();
  if (h->refs == 0) {
    hyda::island_decrypt(const_cast<uint8_t*>(static_cast<const uint8_t*>(island)),
                         h->size, key);

    {
      uint32_t mst = 0;
      const uint32_t mrc = hyda::island_mutate(
          const_cast<uint8_t*>(static_cast<const uint8_t*>(island)), h->size,
          island_mut_key(island), &mst);
      if (mrc == hyda::HYDA_MUT_OK) {
        h->reserved2 = mst;
      } else if (mrc != hyda::HYDA_MUT_NO_PLAN) {

        hyda::island_encrypt(
            const_cast<uint8_t*>(static_cast<const uint8_t*>(island)), h->size,
            key);
        island_unlock();
        return false;
      }
    }

    if ((h->flags & hyda::HYDA_ISLAND_IMPORT) != 0) {
      const uint32_t tab_rva = hyda::g_import_table_rva;
      if (tab_rva == 0) { island_unlock(); return false; }
      const hyda::RuntimeImportTable* tab =
          reinterpret_cast<const hyda::RuntimeImportTable*>(
              reinterpret_cast<uint8_t*>(ctx->image_base) + tab_rva);
      if (tab->magic != hyda::HYDA_RIMPTAB_MAGIC) { island_unlock(); return false; }
      if (h->import_index == 0 || h->import_index > tab->count) {
        island_unlock();
        return false;
      }
      void* fn = hyda_resolve_table_entry(tab, h->import_index);
      if (fn == nullptr) { island_unlock(); return false; }
      uint8_t* slot =
          const_cast<uint8_t*>(static_cast<const uint8_t*>(island)) + h->size;
      const uint64_t api = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fn));

      const uint8_t* ap = reinterpret_cast<const uint8_t*>(&api);
      for (uint32_t bi = 0; bi < sizeof(api); ++bi) slot[bi] = ap[bi];
    }
  }
  h->refs++;
  island_unlock();
  return true;
}

void island_release(hyda::VMContext* ctx, const void* island) {
  hyda::IslandHeader* h = island_header_of(island);
  if (h == nullptr) return;

  const uint32_t rva = static_cast<uint32_t>(
      reinterpret_cast<uintptr_t>(island) - ctx->image_base);
  const uint64_t key = hyda::island_key_for(h->salt, rva);
  island_lock();
  if (h->refs > 0) {
    h->refs--;
    if (h->refs == 0) {

      if (h->reserved2 != 0) {
        const uint32_t mrc = hyda::island_unmutate(
            const_cast<uint8_t*>(static_cast<const uint8_t*>(island)), h->size,
            h->reserved2);
        h->reserved2 = 0;
        if (mrc != hyda::HYDA_MUT_OK && ctx != nullptr) {
          ctx->status = hyda::ST_FAULT;
        }
      }
      hyda::island_encrypt(
          const_cast<uint8_t*>(static_cast<const uint8_t*>(island)), h->size,
          key);
    }
  }
  island_unlock();
}

}

namespace {
std::atomic<unsigned> g_gate_owner{hyda::kThreadIndexNone};
uint32_t g_gate_depth[hyda::kMaxThreads] = {};

inline uint64_t gate_rdtsc() {
#if defined(__x86_64__) || defined(__i386__)
  uint32_t lo = 0, hi = 0;
  __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return (static_cast<uint64_t>(hi) << 32) | lo;
#else
  return 0;
#endif
}

bool gate_lock_acquire() {
  const unsigned idx = hyda::thread_index();
  if (idx >= hyda::kMaxThreads) return false;
  if (g_gate_depth[idx] > 0) {
    ++g_gate_depth[idx];
    return true;
  }
  const uint64_t start = gate_rdtsc();
  for (;;) {
    unsigned expect = hyda::kThreadIndexNone;
    if (g_gate_owner.compare_exchange_weak(expect, idx,
                                           std::memory_order_acq_rel)) {
      g_gate_depth[idx] = 1;
      return true;
    }
    if (gate_rdtsc() - start > 2000000000ull) return false;
#if defined(__x86_64__) || defined(__i386__)
    for (int i = 0; i < 16; ++i) __builtin_ia32_pause();
#endif
  }
}
}

extern "C" {
uint32_t hyda_g_island_mut_k = 0xFFFFFFFFu;
}

extern "C" void hyda_gate_island_release(const void* island,
                                         hyda::VMContext* ctx) {
  island_release(ctx, island);
}

extern "C" void hyda_gate_release(void) {
  const unsigned idx = hyda::thread_index();
  if (idx >= hyda::kMaxThreads) return;
  if (g_gate_depth[idx] > 0 && --g_gate_depth[idx] == 0) {
    g_gate_owner.store(hyda::kThreadIndexNone, std::memory_order_release);
  }
}

extern "C" int hyda_vm_gate_fault_ctx(uint64_t* rip, uint64_t* rsp) {
  if (hyda_gate_depth == 0 || hyda_gate_rsp == nullptr) return 0;
  const uint8_t* base = static_cast<const uint8_t*>(hyda_gate_rsp);
  if (rip != nullptr) *rip = *reinterpret_cast<const uint64_t*>(base + 64);
  if (rsp != nullptr) *rsp = reinterpret_cast<uint64_t>(base) + 72;
  return 1;
}

extern "C" void hyda_vm_gate_abort(void) {
  const unsigned d = static_cast<unsigned>(hyda_gate_depth);
  for (unsigned i = 0; i < d && i < hyda::kMaxVmDepth; ++i) {
    hyda::VMContext* ctx =
        reinterpret_cast<hyda::VMContext*>(hyda_gate_slots[i].ctx);
    const void* isl = hyda_gate_slots[i].island;
    if (isl != nullptr) island_release(ctx, isl);
  }
  hyda_gate_depth = 0;
  hyda_gate_ctx = nullptr;
  hyda_gate_island = nullptr;
  hyda_gate_rsp = nullptr;
  const unsigned gidx = hyda::thread_index();
  if (gidx < hyda::kMaxThreads) g_gate_depth[gidx] = 0;
  g_gate_owner.store(hyda::kThreadIndexNone, std::memory_order_release);
}

extern "C" {
__attribute__((used)) HYDA_INTERNAL uint32_t hyda_vreg_off[16] = {
    hyda::vsl(hyda::REG_RAX) * 8u, hyda::vsl(hyda::REG_RCX) * 8u,
    hyda::vsl(hyda::REG_RDX) * 8u, hyda::vsl(hyda::REG_RBX) * 8u,
    hyda::vsl(hyda::REG_RSP) * 8u, hyda::vsl(hyda::REG_RBP) * 8u,
    hyda::vsl(hyda::REG_RSI) * 8u, hyda::vsl(hyda::REG_RDI) * 8u,
    hyda::vsl(hyda::REG_R8) * 8u,  hyda::vsl(hyda::REG_R9) * 8u,
    hyda::vsl(hyda::REG_R10) * 8u, hyda::vsl(hyda::REG_R11) * 8u,
    hyda::vsl(hyda::REG_R12) * 8u, hyda::vsl(hyda::REG_R13) * 8u,
    hyda::vsl(hyda::REG_R14) * 8u, hyda::vsl(hyda::REG_R15) * 8u,
};
__attribute__((used)) HYDA_INTERNAL uint64_t hyda_gpr_tmp[17];
}

#define HYDA_GPR_LOAD                                                    \
   \
   \
  "sub rsp, 144\n"                                                      \
  "lea r10, [rip + hyda_vreg_off]\n"                                    \
  "xor eax, eax\n"                                                      \
  "7:\n"                                                                \
  "  mov edx, dword ptr [r10 + rax*4]\n"                                \
  "  mov r11, qword ptr [rcx + rdx]\n"                                  \
  "  mov qword ptr [rsp + rax*8], r11\n"                                \
  "  inc rax\n"                                                         \
  "  cmp rax, 16\n"                                                     \
  "  jb 7b\n"                                                           \
  "mov r11, qword ptr [rcx + " HYDA_S(HYDA_OFF_FLAGS) "]\n"             \
  "mov qword ptr [rsp + 128], r11\n"                                    \
  "mov rax, [rsp + 0]\n"                                               \
  "mov rcx, [rsp + 8]\n"                                               \
  "mov rdx, [rsp + 16]\n"                                              \
  "mov rbx, [rsp + 24]\n"                                              \
  "mov rbp, [rsp + 40]\n"                                              \
  "mov rsi, [rsp + 48]\n"                                              \
  "mov rdi, [rsp + 56]\n"                                              \
  "mov r8,  [rsp + 64]\n"                                              \
  "mov r9,  [rsp + 72]\n"                                              \
  "mov r10, [rsp + 80]\n"                                              \
  "mov r11, [rsp + 88]\n"                                              \
  "mov r12, [rsp + 96]\n"                                              \
  "mov r13, [rsp + 104]\n"                                             \
  "mov r14, [rsp + 112]\n"                                             \
  "mov r15, [rsp + 120]\n"                                             \
  "push qword ptr [rsp + 128]\n"                                       \
  "popfq\n"                                                             \
  "mov rsp, [rsp + 32]\n"

#define HYDA_GPR_SAVE                                                    \
  "mov [rip + hyda_gpr_tmp + 0], rax\n"                                \
  "mov [rip + hyda_gpr_tmp + 8], rcx\n"                                \
  "mov [rip + hyda_gpr_tmp + 16], rdx\n"                               \
  "mov [rip + hyda_gpr_tmp + 24], rbx\n"                               \
  "mov [rip + hyda_gpr_tmp + 32], rsp\n"                               \
  "mov [rip + hyda_gpr_tmp + 40], rbp\n"                               \
  "mov [rip + hyda_gpr_tmp + 48], rsi\n"                               \
  "mov [rip + hyda_gpr_tmp + 56], rdi\n"                               \
  "mov [rip + hyda_gpr_tmp + 64], r8\n"                                \
  "mov [rip + hyda_gpr_tmp + 72], r9\n"                                \
  "mov [rip + hyda_gpr_tmp + 80], r10\n"                               \
  "mov [rip + hyda_gpr_tmp + 96], r12\n"                               \
  "mov [rip + hyda_gpr_tmp + 104], r13\n"                              \
  "mov [rip + hyda_gpr_tmp + 112], r14\n"                              \
  "mov [rip + hyda_gpr_tmp + 120], r15\n"                              \
  "pushfq\n"                                                           \
  "pop qword ptr [rip + hyda_gpr_tmp + 128]\n"

#if defined(_WIN32)
#  define HYDA_SAVE_ARGS                    \
     "mov [rip + hyda_gate_ctx], rcx\n"     \
     "mov [rip + hyda_gate_island], rdx\n"
#else
#  define HYDA_SAVE_ARGS                    \
     "mov [rip + hyda_gate_ctx], rdi\n"     \
     "mov [rip + hyda_gate_island], rsi\n"
#endif

#define HYDA_SLOT_PUSH                                                       \
  "mov rax, [rip + hyda_gate_depth]\n"                                       \
  "imul rax, rax, " HYDA_S(HYDA_SLOT_SIZE) "\n"                              \
  "lea r10, [rip + hyda_gate_slots]\n"                                       \
  "add r10, rax\n"                                                           \
  "mov rax, [rip + hyda_gate_ctx]\n"                                         \
  "mov [r10 + " HYDA_S(HYDA_SLOT_CTX) "], rax\n"                             \
  "mov rax, [rip + hyda_gate_island]\n"                                      \
  "mov [r10 + " HYDA_S(HYDA_SLOT_ISLAND) "], rax\n"                          \
  "mov rax, [rip + hyda_gate_rsp]\n"                                         \
  "mov [r10 + " HYDA_S(HYDA_SLOT_RSP) "], rax\n"                             \
  "inc qword ptr [rip + hyda_gate_depth]\n"

#define HYDA_SLOT_POP                                                        \
  "mov rax, [rip + hyda_gate_depth]\n"                                       \
  "dec rax\n"                                                                \
  "mov [rip + hyda_gate_depth], rax\n"                                       \
  "test rax, rax\n"                                                          \
  "jz 1f\n"                                                                  \
  "dec rax\n"                                                                \
  "imul rax, rax, " HYDA_S(HYDA_SLOT_SIZE) "\n"                              \
  "lea r10, [rip + hyda_gate_slots]\n"                                       \
  "add r10, rax\n"                                                           \
  "mov rax, [r10 + " HYDA_S(HYDA_SLOT_CTX) "]\n"                             \
  "mov [rip + hyda_gate_ctx], rax\n"                                         \
  "mov rax, [r10 + " HYDA_S(HYDA_SLOT_ISLAND) "]\n"                          \
  "mov [rip + hyda_gate_island], rax\n"                                      \
  "mov rax, [r10 + " HYDA_S(HYDA_SLOT_RSP) "]\n"                             \
  "mov [rip + hyda_gate_rsp], rax\n"                                         \
  "jmp 2f\n"                                                                 \
  "1:\n"                                                                     \
  "mov qword ptr [rip + hyda_gate_ctx], 0\n"                                 \
  "2:\n"

static __attribute__((naked, noinline))
void hyda_gate_enter_asm(hyda::VMContext* , const void* ) {
  __asm__(
      ".intel_syntax noprefix\n"

      "push rbp\n"
      "mov rbp, rsp\n"
      "push rbx\n"
      "push rsi\n"
      "push rdi\n"
      "push r12\n"
      "push r13\n"
      "push r14\n"
      "push r15\n"
      "mov [rip + hyda_gate_rsp], rsp\n"
      HYDA_SAVE_ARGS

      HYDA_SLOT_PUSH

      "mov r8, qword ptr [rip + hyda_gate_fp_ptr]\n"
      "fxrstor [r8]\n"
      "cmp byte ptr [rip + hyda_gate_avx], 0\n"
      "je Lh_gate_fp_in_done\n"
      "vinsertf128 ymm0, ymm0, [r8 + 576], 1\n"
      "vinsertf128 ymm1, ymm1, [r8 + 592], 1\n"
      "vinsertf128 ymm2, ymm2, [r8 + 608], 1\n"
      "vinsertf128 ymm3, ymm3, [r8 + 624], 1\n"
      "vinsertf128 ymm4, ymm4, [r8 + 640], 1\n"
      "vinsertf128 ymm5, ymm5, [r8 + 656], 1\n"
      "vinsertf128 ymm6, ymm6, [r8 + 672], 1\n"
      "vinsertf128 ymm7, ymm7, [r8 + 688], 1\n"
      "vinsertf128 ymm8, ymm8, [r8 + 704], 1\n"
      "vinsertf128 ymm9, ymm9, [r8 + 720], 1\n"
      "vinsertf128 ymm10, ymm10, [r8 + 736], 1\n"
      "vinsertf128 ymm11, ymm11, [r8 + 752], 1\n"
      "vinsertf128 ymm12, ymm12, [r8 + 768], 1\n"
      "vinsertf128 ymm13, ymm13, [r8 + 784], 1\n"
      "vinsertf128 ymm14, ymm14, [r8 + 800], 1\n"
      "vinsertf128 ymm15, ymm15, [r8 + 816], 1\n"
      "Lh_gate_fp_in_done:\n"

      "mov rcx, [rip + hyda_gate_ctx]\n"

      HYDA_GPR_LOAD
      "jmp qword ptr [rip + hyda_gate_island]\n"
      ".att_syntax prefix\n");
}

static void hyda_gate_fp_ensure() {
  static int done = 0;
  if (!done) {
    hyda_gate_avx = hyda::fp_supports_avx() ? 1u : 0u;
    done = 1;
  }
}

HYDA_ENTRY void hyda_vm_gate_enter(hyda::VMContext* ctx, const void* island) {
  if (!gate_lock_acquire()) {
    ctx->status = hyda::ST_FAULT;
    return;
  }
  hyda_gate_fp_ensure();
  hyda_gate_fp_ptr = hyda::fp_state();
  if (!island_acquire(ctx, island)) {
    ctx->status = hyda::ST_FAULT;
    const unsigned idx = hyda::thread_index();
    if (idx < hyda::kMaxThreads && g_gate_depth[idx] > 0 &&
        --g_gate_depth[idx] == 0) {
      g_gate_owner.store(hyda::kThreadIndexNone, std::memory_order_release);
    }
    return;
  }
  hyda_gate_enter_asm(ctx, island);
}

HYDA_ENTRY __attribute__((naked, noinline)) void hyda_vm_gate_leave(void) {
  __asm__(
      ".intel_syntax noprefix\n"

      "xchg r11, qword ptr [rip + hyda_gate_ctx]\n"

      "push rax\n push rdx\n push r8\n"
      "mov r8, qword ptr [rip + hyda_gate_fp_ptr]\n"
      "cmp byte ptr [rip + hyda_gate_avx], 0\n"
      "je Lh_gate_fp_out_done\n"
      "vextractf128 [r8 + 576], ymm0, 1\n"
      "vextractf128 [r8 + 592], ymm1, 1\n"
      "vextractf128 [r8 + 608], ymm2, 1\n"
      "vextractf128 [r8 + 624], ymm3, 1\n"
      "vextractf128 [r8 + 640], ymm4, 1\n"
      "vextractf128 [r8 + 656], ymm5, 1\n"
      "vextractf128 [r8 + 672], ymm6, 1\n"
      "vextractf128 [r8 + 688], ymm7, 1\n"
      "vextractf128 [r8 + 704], ymm8, 1\n"
      "vextractf128 [r8 + 720], ymm9, 1\n"
      "vextractf128 [r8 + 736], ymm10, 1\n"
      "vextractf128 [r8 + 752], ymm11, 1\n"
      "vextractf128 [r8 + 768], ymm12, 1\n"
      "vextractf128 [r8 + 784], ymm13, 1\n"
      "vextractf128 [r8 + 800], ymm14, 1\n"
      "vextractf128 [r8 + 816], ymm15, 1\n"
      "Lh_gate_fp_out_done:\n"
      "fxsave [r8]\n"
      "pop r8\n pop rdx\n pop rax\n"

      HYDA_GPR_SAVE

      "mov rax, qword ptr [rip + hyda_gate_ctx]\n"
      "mov [rip + hyda_gpr_tmp + 88], rax\n"

      "lea r8, [rip + hyda_vreg_off]\n"
      "lea r9, [rip + hyda_gpr_tmp]\n"
      "xor eax, eax\n"
      "8:\n"
      "  mov edx, dword ptr [r8 + rax*4]\n"
      "  mov rcx, qword ptr [r9 + rax*8]\n"
      "  mov [r11 + rdx], rcx\n"
      "  inc rax\n"
      "  cmp rax, 16\n"
      "  jb 8b\n"

      "mov rax, qword ptr [rip + hyda_gpr_tmp + 128]\n"
      "mov [r11 + " HYDA_S(HYDA_OFF_FLAGS) "], rax\n"

      "cld\n"

      "mov rsp, [rip + hyda_gate_rsp]\n"

#if defined(_WIN32)
      "mov rcx, qword ptr [rip + hyda_gate_island]\n"
      "mov rdx, r11\n"
#else
      "mov rdi, qword ptr [rip + hyda_gate_island]\n"
      "mov rsi, r11\n"
#endif
      "sub rsp, 40\n"
      "call hyda_gate_island_release\n"
      "add rsp, 40\n"

      HYDA_SLOT_POP
      "sub rsp, 40\n"
      "call hyda_gate_release\n"
      "add rsp, 40\n"
      "pop r15\n"
      "pop r14\n"
      "pop r13\n"
      "pop r12\n"
      "pop rdi\n"
      "pop rsi\n"
      "pop rbx\n"
      "pop rbp\n"
      "ret\n"
      ".att_syntax prefix\n");
}

#define HYDA_LEAVE_ALIAS(name)                                                 \
  HYDA_ENTRY __attribute__((naked, noinline)) void name(void) {                \
    __asm__(".intel_syntax noprefix\n"                                          \
            "jmp hyda_vm_gate_leave\n"                                          \
            ".att_syntax prefix\n");                                           \
  }

HYDA_LEAVE_ALIAS(hyda_vm_gate_leave_a)
HYDA_LEAVE_ALIAS(hyda_vm_gate_leave_b)
HYDA_LEAVE_ALIAS(hyda_vm_gate_leave_c)

#undef HYDA_LEAVE_ALIAS

extern "C" void hyda_fp_bind(void) {
  hyda_gate_fp_ensure();
  hyda_gate_fp_ptr = hyda::fp_state();
}

namespace {
struct FpBinder {
  FpBinder() { hyda_fp_bind(); }
};
const FpBinder g_fp_binder;
}  // namespace

extern "C" void hyda_fp_restore_helper(void) {
  hyda_gate_fp_ensure();
  hyda::HydaFpState* fp = hyda::fp_state();
  __asm__ volatile("fxrstor (%0)" ::"r"(fp) : "memory");
  if (hyda_gate_avx) {
    __asm__ volatile(
        "vinsertf128 $1, 576(%0), %%ymm0, %%ymm0\n"
        "vinsertf128 $1, 592(%0), %%ymm1, %%ymm1\n"
        "vinsertf128 $1, 608(%0), %%ymm2, %%ymm2\n"
        "vinsertf128 $1, 624(%0), %%ymm3, %%ymm3\n"
        "vinsertf128 $1, 640(%0), %%ymm4, %%ymm4\n"
        "vinsertf128 $1, 656(%0), %%ymm5, %%ymm5\n"
        "vinsertf128 $1, 672(%0), %%ymm6, %%ymm6\n"
        "vinsertf128 $1, 688(%0), %%ymm7, %%ymm7\n"
        "vinsertf128 $1, 704(%0), %%ymm8, %%ymm8\n"
        "vinsertf128 $1, 720(%0), %%ymm9, %%ymm9\n"
        "vinsertf128 $1, 736(%0), %%ymm10, %%ymm10\n"
        "vinsertf128 $1, 752(%0), %%ymm11, %%ymm11\n"
        "vinsertf128 $1, 768(%0), %%ymm12, %%ymm12\n"
        "vinsertf128 $1, 784(%0), %%ymm13, %%ymm13\n"
        "vinsertf128 $1, 800(%0), %%ymm14, %%ymm14\n"
        "vinsertf128 $1, 816(%0), %%ymm15, %%ymm15\n"
        ::"r"(fp)
        : "memory");
  }
}

HYDA_ENTRY __attribute__((naked, noinline)) void hyda_vm_save_simd(void) {
  __asm__(".intel_syntax noprefix\n"
          "push rax\n push rcx\n push rdx\n push r8\n"
          "push r9\n push r10\n push r11\n"
          "mov r8, qword ptr [rip + hyda_gate_fp_ptr]\n"
          "test r8, r8\n"
          "jne 1f\n"
          "call hyda_fp_bind\n"
          "mov r8, qword ptr [rip + hyda_gate_fp_ptr]\n"
          "1:\n"
          "fxsave [r8]\n"
          "cmp byte ptr [rip + hyda_gate_avx], 0\n"
          "je 2f\n"
          "vextractf128 [r8 + 576], ymm0, 1\n"
          "vextractf128 [r8 + 592], ymm1, 1\n"
          "vextractf128 [r8 + 608], ymm2, 1\n"
          "vextractf128 [r8 + 624], ymm3, 1\n"
          "vextractf128 [r8 + 640], ymm4, 1\n"
          "vextractf128 [r8 + 656], ymm5, 1\n"
          "vextractf128 [r8 + 672], ymm6, 1\n"
          "vextractf128 [r8 + 688], ymm7, 1\n"
          "vextractf128 [r8 + 704], ymm8, 1\n"
          "vextractf128 [r8 + 720], ymm9, 1\n"
          "vextractf128 [r8 + 736], ymm10, 1\n"
          "vextractf128 [r8 + 752], ymm11, 1\n"
          "vextractf128 [r8 + 768], ymm12, 1\n"
          "vextractf128 [r8 + 784], ymm13, 1\n"
          "vextractf128 [r8 + 800], ymm14, 1\n"
          "vextractf128 [r8 + 816], ymm15, 1\n"
          "2:\n"
          "pop r11\n pop r10\n pop r9\n pop r8\n"
          "pop rdx\n pop rcx\n pop rax\n"
          "ret\n .att_syntax prefix\n");
}

HYDA_ENTRY __attribute__((naked, noinline)) void hyda_vm_restore_simd(void) {
  __asm__(".intel_syntax noprefix\n"
          "push rax\n push rcx\n push rdx\n push r8\n"
          "push r9\n push r10\n push r11\n"
          "sub rsp, 32\n"
          "call hyda_fp_restore_helper\n"
          "add rsp, 32\n"
          "pop r11\n pop r10\n pop r9\n pop r8\n"
          "pop rdx\n pop rcx\n pop rax\n"
          "ret\n .att_syntax prefix\n");
}
