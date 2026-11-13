#include "hyda/vm/vm.hpp"

#include "hyda/vm/dispatch.hpp"
#include "hyda/vm/identity.hpp"
#include "hyda/vm/dispatch_ring.hpp"
#include "hyda/core/export.hpp"
#include "hyda/vm/handlers.hpp"
#include "hyda/vm/vm2.hpp"
#include "hyda/codec/hydak.hpp"

#include <atomic>
#include <cstdint>

extern "C" {

__attribute__((used)) uint64_t hyda_handler_lo;
__attribute__((used)) uint64_t hyda_handler_hi;
}

extern "C" {
HYDA_ENTRY_DATA hyda::DispatchProfile g_dispatch_profile = {0, 0, 0, 3, 0, 0, 0, 0};
HYDA_ENTRY_DATA uint64_t g_vm_seed = hyda::kSeedDefaultMasked();
HYDA_ENTRY_DATA uint64_t g_seed_salt = hyda::kSeedSaltDefault;
}

namespace {

std::atomic<int> g_ring_active{0};

void rebuild_dispatch_tables() {
  if (g_ring_active.load(std::memory_order_acquire) != 0) return;
  const hyda::DispatchRange r = hyda::ring_build_from_list();
  hyda_handler_lo = r.lo;
  hyda_handler_hi = r.hi;
}

struct DispatchTables {
  DispatchTables() {
    rebuild_dispatch_tables();

    hyda::vm2_build();
  }
};

const DispatchTables g_dispatch_tables;

}

extern "C" void hyda_vm_set_dispatch_profile(uint32_t index_mask,
                                            uint32_t key_variant,
                                            uint32_t base_variant,
                                            uint32_t entry_shift,
                                            uint32_t call_style,
                                            uint32_t crypt_variant) {
  g_dispatch_profile.index_mask = index_mask & 0xFFu;
  g_dispatch_profile.key_variant = key_variant & 1u;
  g_dispatch_profile.base_variant = base_variant & 3u;
  g_dispatch_profile.entry_shift = (entry_shift == 4u) ? 4u : 3u;
  g_dispatch_profile.call_style = call_style & 1u;
  g_dispatch_profile.crypt_variant = crypt_variant & 1u;
  rebuild_dispatch_tables();
}

namespace hyda {

namespace {

constexpr unsigned kPermPool = 256;

struct PermSlot {
  std::atomic<uint32_t> used{0};
  uint64_t key;
  uint16_t perm[kSlotCount];
};

PermSlot g_perm_pool[kPermPool];
std::atomic<uint32_t> g_perm_next{0};
std::atomic<uint32_t> g_perm_lock{0};

uint16_t g_perm_identity[kSlotCount];
std::atomic<uint32_t> g_perm_identity_ready{0};

void perm_identity_init() {
  if (g_perm_identity_ready.load(std::memory_order_acquire) != 0) return;
  for (uint32_t i = 0; i < kSlotCount; ++i) {
    g_perm_identity[i] = static_cast<uint16_t>(i);
  }
  g_perm_identity_ready.store(1, std::memory_order_release);
}

void perm_slot_fill(PermSlot& slot, uint64_t key) {
  identity_slot_perm(slot.perm, key);
  slot.key = key;
  std::atomic_thread_fence(std::memory_order_release);
  slot.used.store(1, std::memory_order_release);
}

const uint16_t* perm_lookup(uint64_t key) {
  if (key == 0) {
    perm_identity_init();
    return g_perm_identity;
  }
  for (unsigned i = 0; i < kPermPool; ++i) {
    if (g_perm_pool[i].used.load(std::memory_order_acquire) == 0) continue;
    if (g_perm_pool[i].key != key) continue;
    std::atomic_thread_fence(std::memory_order_acquire);
    return g_perm_pool[i].perm;
  }
  uint32_t expect = 0;
  while (!g_perm_lock.compare_exchange_weak(expect, 1, std::memory_order_acq_rel,
                                            std::memory_order_relaxed)) {
    expect = 0;
  }
  const uint16_t* out = nullptr;
  for (unsigned i = 0; i < kPermPool; ++i) {
    if (g_perm_pool[i].used.load(std::memory_order_acquire) != 0 &&
        g_perm_pool[i].key == key) {
      out = g_perm_pool[i].perm;
      break;
    }
  }
  if (out == nullptr) {
    const uint32_t at = g_perm_next.fetch_add(1, std::memory_order_relaxed);
    PermSlot& slot = g_perm_pool[at % kPermPool];
    perm_slot_fill(slot, key);
    out = slot.perm;
  }
  g_perm_lock.store(0, std::memory_order_release);
  return out;
}

}

const uint16_t* dispatch_perm_for(uint64_t key) { return perm_lookup(key); }

uint32_t vm_exec(VMContext& ctx, const uint8_t* code, size_t size,
                 uint64_t crypt_key) {
  if (ctx.ring_perm == nullptr) {
    ctx.ring_perm = dispatch_perm_for(0);
    ctx.crypt_variant = g_dispatch_profile.crypt_variant;
    ctx.call_style = g_dispatch_profile.call_style;
  }
  return hyda_vm_run_asm(&ctx, code, size, crypt_key);
}

uint32_t install_handler_shards(const HandlerShardDesc* descs, unsigned count,
                                uint64_t* arena_lo, uint64_t* arena_hi) {
  if (descs == nullptr || count == 0) return HYDAK_ERR_ARG;

  HydakCatalog cat;
  uint64_t lo = UINT64_MAX;
  uint64_t hi = 0;
  for (unsigned i = 0; i < count; ++i) {
    HydakView v;
    uint32_t err = HYDAK_OK;
    const uint64_t key = hydak_key_for(descs[i].rva);
    if (!hydak_open(descs[i].ptr, descs[i].size, key, &v, &err)) return err;
    if (!hydak_catalog_add(&cat, v, &err)) return err;

    const uint64_t base = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(descs[i].ptr));
    if (base < lo) lo = base;
    if (base + v.h->total_size > hi) hi = base + v.h->total_size;
  }

  uint32_t err = HYDAK_OK;
  if (!hydak_catalog_finish(&cat, &err)) return err;

  const DispatchRange ring = ring_build_from_addrs(cat.addrs, cat.bad);
  hyda_handler_lo = ring.lo;
  hyda_handler_hi = ring.hi;
  if (arena_lo) *arena_lo = lo;
  if (arena_hi) *arena_hi = hi;

  g_ring_active.store(1, std::memory_order_release);
  return HYDAK_OK;
}

}
