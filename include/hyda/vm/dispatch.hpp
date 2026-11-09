#pragma once

#include "hyda/core/config.hpp"

#include <cstdint>

namespace hyda {

constexpr uint64_t kDispatchSecret = 0x51ED2701B3F4A9C7ull;

constexpr unsigned kDispatchOpszShift   = 32;
constexpr unsigned kDispatchRegcntShift = 40;

struct DecodedEntry {
  uint64_t handler;
  uint8_t  opsz;
  uint8_t  regcnt;
};

struct DispatchRange {
  uint64_t lo;
  uint64_t hi;
};

struct DispatchProfile {
  uint32_t index_mask;
  uint32_t key_variant;
  uint32_t base_variant;
  uint32_t entry_shift;
  uint32_t call_style;
  uint32_t crypt_variant;
  uint32_t reserved;
  uint32_t reserved2;
};
static_assert(sizeof(DispatchProfile) == 32, "dispatch profile is 32 bytes");

inline constexpr DispatchProfile kDispatchProfileDefault = {0, 0, 0, 3, 0, 0, 0, 0};

inline constexpr uint32_t kDispatchEntrySize8 = 8;
inline constexpr uint32_t kDispatchEntrySize16 = 16;
inline constexpr uint32_t kDispatchTableSlots = 256;

inline uint64_t dispatch_base_key_v(uint64_t tab_addr, uint32_t variant) {
  uint64_t z = tab_addr;
  switch (variant & 3u) {
    case 1:
      z = tab_addr + kDispatchSecret;
      z ^= z >> 29;
      z *= 0x3C6EF372u;
      z ^= z >> 31;
      z *= 0x5BD1E995u;
      z ^= z >> 27;
      break;
    case 2:
      z = tab_addr ^ (kDispatchSecret * 0x3C6EF372u);
      z ^= z >> 31;
      z *= 0x5BD1E995u;
      z ^= z >> 29;
      z += kDispatchSecret;
      break;
    case 3:
      z = (tab_addr ^ kDispatchSecret) + 0x5BD1E995u;
      z *= 0x3C6EF372u;
      z ^= z >> 31;
      z *= 0x5BD1E995u;
      z ^= z >> 27;
      break;
    default:
      z = tab_addr ^ kDispatchSecret;
      z ^= z >> 31;
      z *= 0x3C6EF372u;
      z ^= z >> 29;
      z *= 0x5BD1E995u;
      z ^= z >> 31;
      break;
  }
  return z;
}

inline uint64_t dispatch_slot_key_v(uint64_t base_key, uint32_t slot,
                                   uint32_t variant) {
  uint64_t z;
  if ((variant & 1u) == 0) {
    z = base_key ^ (static_cast<uint64_t>(slot) * 0x1B873593u);
    z ^= z >> 27;
    z *= 0x27D4EB2Du;
    z ^= z >> 31;
  } else {
    z = base_key + (static_cast<uint64_t>(slot) * 0x27D4EB2Du);
    z ^= z >> 31;
    z *= 0x1B873593u;
    z ^= z >> 29;
    z ^= base_key;
  }
  return z;
}

inline uint32_t dispatch_index(uint8_t slot, uint32_t index_mask) {
  return (static_cast<uint32_t>(slot) ^ index_mask) & 0xFFu;
}

}

extern "C" hyda::DispatchProfile g_dispatch_profile;
