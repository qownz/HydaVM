#pragma once

#include "hyda/core/config.hpp"

#include <cstdint>

namespace hyda {

// Per-function dispatch identity. Everything is derived from the function's
// crypt key, so the protector and the runtime agree without the image having
// to carry the mapping: one function's slot numbering tells nothing about
// another's.
struct DispatchIdentity {
  uint32_t crypt_variant;
  uint32_t call_style;
};

inline uint64_t identity_mix(uint64_t& s) {
  s += 0x9E3779B97F4A7C15ull;
  uint64_t z = s;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

inline DispatchIdentity dispatch_identity_for(uint64_t key) {
  uint64_t s = key ^ 0x2A1B3C4D5E6F7081ull;
  DispatchIdentity id;
  id.crypt_variant = static_cast<uint32_t>(identity_mix(s) & 1u);
  id.call_style = static_cast<uint32_t>(identity_mix(s) & 1u);
  return id;
}

// Slot numbering of one function: a bijection over the slot byte space.
inline void identity_slot_perm(uint16_t* dst, uint64_t key) {
  for (uint32_t i = 0; i < kSlotCount; ++i) dst[i] = static_cast<uint16_t>(i);
  uint64_t s = key ^ 0x51633E2D1B7F4A09ull;
  for (uint32_t i = static_cast<uint32_t>(kSlotCount) - 1; i > 0; --i) {
    const uint64_t r = identity_mix(s);
    const uint32_t j = static_cast<uint32_t>(r % (i + 1u));
    const uint16_t t = dst[i];
    dst[i] = dst[j];
    dst[j] = t;
  }
}

inline void identity_slot_perm_inv(uint16_t* dst, uint64_t key) {
  uint16_t fwd[kSlotCount];
  identity_slot_perm(fwd, key);
  for (uint32_t i = 0; i < kSlotCount; ++i) dst[fwd[i]] = static_cast<uint16_t>(i);
}

}
