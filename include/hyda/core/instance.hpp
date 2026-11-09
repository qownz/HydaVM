#pragma once

#include "hyda/core/config.hpp"
#include "hyda/core/export.hpp"

#include <cstdint>

extern "C" uint64_t g_vm_seed;
extern "C" uint64_t g_seed_salt;

namespace hyda {

constexpr uint64_t kSeedSaltDefault = 0x5D3B1A7C9E2F4068ull;

constexpr uint64_t seed_salt_mix(uint64_t salt) {
  uint64_t z = salt ^ 0xA24BAED4963EE407ull;
  z ^= z >> 31;
  z *= 0x9E3779B97F4A7C15ull;
  z ^= z >> 29;
  z *= 0xC2B2AE3D27D4EB4Full;
  z ^= z >> 27;
  return z;
}

constexpr uint64_t kSeedDefaultMasked() {
  uint64_t z = kSeedSaltDefault ^ 0xA24BAED4963EE407ull;
  z ^= z >> 31;
  z *= 0x9E3779B97F4A7C15ull;
  z ^= z >> 29;
  z *= 0xC2B2AE3D27D4EB4Full;
  z ^= z >> 27;
  return static_cast<uint64_t>(HYDA_VM_SEED) ^ z;
}

inline uint64_t vm_seed() {
  const uint64_t s = ::g_vm_seed ^ seed_salt_mix(::g_seed_salt);
  return s == 0 ? static_cast<uint64_t>(HYDA_VM_SEED) : s;
}

inline uint32_t seed_magic(uint64_t tag) {
  uint64_t z = vm_seed() ^ tag;
  z ^= z >> 31;
  z *= 0xBF58476D1CE4E5B9ull;
  z ^= z >> 27;
  z ^= tag * 0x9E3779B97F4A7C15ull;
  const uint32_t m = static_cast<uint32_t>(z ^ (z >> 32));
  return m == 0 ? 1u : m;
}

}
