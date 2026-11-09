#pragma once

#include "hyda/core/config.hpp"
#include "hyda/vm/dispatch.hpp"
#include "hyda/core/instance.hpp"

#include <cstdint>

namespace hyda {

constexpr uint32_t kRingTables = 8;
constexpr uint32_t kRingDecoys = 8;

constexpr uint32_t kRingTableBytes = 16384;
constexpr uint32_t kRingTableWords = kRingTableBytes / 8;
constexpr uint32_t kRingIndexShift = 14;

constexpr uint64_t kRingSelK1 = 0x2545F491u;
constexpr uint64_t kRingSelK2 = 0x27D4EB2Du;
constexpr unsigned kRingSelShift = 13;

// Must match ring_select in src/vm/dispatch_asm.cpp.
inline uint32_t ring_select(uint64_t vip, uint64_t epoch) {
  uint64_t z = (vip + (vip >> 3)) * kRingSelK1;
  z += epoch * kRingSelK2;
  z ^= z >> kRingSelShift;
  return static_cast<uint32_t>(z) & (kRingTables - 1u);
}

inline uint64_t ring_base_key(uint64_t tab_addr, const DispatchProfile& p) {
  return dispatch_base_key_v(tab_addr, p.base_variant);
}

inline uint64_t dispatch_key_idx(const DispatchProfile& p, uint64_t tab_addr,
                                 uint16_t idx) {
  return dispatch_slot_key_v(ring_base_key(tab_addr, p), idx, p.key_variant);
}

inline DecodedEntry decode_ring_entry(uint64_t raw, uint64_t tab_addr,
                                      uint16_t idx, const DispatchProfile& p) {
  const uint64_t e = raw ^ dispatch_key_idx(p, tab_addr, idx);
  const int32_t off = static_cast<int32_t>(static_cast<uint32_t>(e));
  DecodedEntry d;
  d.handler = tab_addr + static_cast<uint64_t>(static_cast<int64_t>(off));
  d.opsz = static_cast<uint8_t>((e >> kDispatchOpszShift) & 0xFFu);
  d.regcnt = static_cast<uint8_t>((e >> kDispatchRegcntShift) & 0xFFu);
  return d;
}

inline uint64_t ring_seed(const DispatchProfile& p) {
  uint64_t z = vm_seed() ^ kDispatchSecret;
  z ^= static_cast<uint64_t>(p.index_mask) * 0x9E3779B97F4A7C15ull;
  z ^= static_cast<uint64_t>(p.key_variant) << 17;
  z ^= static_cast<uint64_t>(p.base_variant) << 29;
  z ^= static_cast<uint64_t>(p.crypt_variant) << 41;
  z ^= static_cast<uint64_t>(p.call_style) << 53;
  return z | 1u;
}

DispatchRange build_dispatch_ring_list();
void build_decoy_ring_list(uint64_t salt);

DispatchRange build_dispatch_ring_addrs(const uint64_t* addrs, uint64_t bad_slot);
void build_decoy_ring_addrs(const uint64_t* addrs, uint64_t bad_slot,
                            uint64_t salt);

DispatchRange ring_build_from_list();
DispatchRange ring_build_from_addrs(const uint64_t* addrs,
                                    uint64_t bad_slot);

}

extern "C" {
extern uint64_t hyda_ring_tab[hyda::kRingTables][hyda::kRingTableWords];
extern uint16_t hyda_ring_perm[hyda::kRingTables][hyda::kSlotCount];
extern uint64_t hyda_ring_call[hyda::kRingTables][hyda::kSlotCount];
extern uint64_t hyda_ring_decoy_tab[hyda::kRingDecoys][hyda::kRingTableWords];
extern uint16_t hyda_ring_decoy_perm[hyda::kRingDecoys][hyda::kSlotCount];
extern uint64_t hyda_ring_decoy_call[hyda::kRingDecoys][hyda::kSlotCount];

extern uint64_t hyda_vm_epoch;
}
