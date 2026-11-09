#include "hyda/vm/dispatch_ring.hpp"

#include "hyda/vm/handlers.hpp"

#include <cstdint>

extern "C" {

__attribute__((used))
uint64_t hyda_ring_tab[hyda::kRingTables][hyda::kRingTableWords];

__attribute__((used)) uint16_t hyda_ring_perm[hyda::kRingTables][hyda::kSlotCount];

__attribute__((used)) uint64_t hyda_ring_call[hyda::kRingTables][hyda::kSlotCount];

__attribute__((used))
uint64_t hyda_ring_decoy_tab[hyda::kRingDecoys][hyda::kRingTableWords];
__attribute__((used)) uint16_t hyda_ring_decoy_perm[hyda::kRingDecoys][hyda::kSlotCount];
__attribute__((used)) uint64_t hyda_ring_decoy_call[hyda::kRingDecoys][hyda::kSlotCount];

__attribute__((used)) uint64_t hyda_vm_epoch;
}

namespace hyda {

namespace {

constexpr uint64_t kDecoySalt = 0xD1B54A32D192ED03ull;

}

DispatchRange ring_build_from_list() {
  const DispatchRange r = build_dispatch_ring_list();
  build_decoy_ring_list(kDecoySalt);
  return r;
}

DispatchRange ring_build_from_addrs(const uint64_t* addrs, uint64_t bad_slot) {
  const DispatchRange r = build_dispatch_ring_addrs(addrs, bad_slot);
  build_decoy_ring_addrs(addrs, bad_slot, kDecoySalt);
  return r;
}

}
