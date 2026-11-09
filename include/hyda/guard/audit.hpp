#pragma once

#include <cstdint>

#include "hyda/codec/crypt.hpp"

namespace hyda {

constexpr uint32_t HYDA_AUDIT_OK = 0xA5A5A5A5u;

constexpr uint32_t HYDA_AUDIT_BAD = 0xDEAD0001u;

constexpr uint64_t HYDA_AUDIT_MASK_SEED = 0x51ED270B3A9F1C4Dull;

struct AuditMask {
  uint32_t rva;
  uint32_t size;
  uint32_t crc;
};

inline AuditMask audit_mask_for(uint32_t index) {
  const uint64_t z = crypt_mix(index, HYDA_AUDIT_MASK_SEED);
  const uint64_t w = z ^ (z >> 27);
  AuditMask m;
  m.rva = static_cast<uint32_t>(z);
  m.size = static_cast<uint32_t>(z >> 32);
  m.crc = static_cast<uint32_t>(w * 0x2545F4914F6CDD1Dull);
  return m;
}

inline uint64_t audit_hookref_mask_for(uint32_t index) {
  const uint64_t z =
      crypt_mix(index, HYDA_AUDIT_MASK_SEED ^ 0x9E3779B97F4A7C15ull);
  return z ^ (z >> 31);
}

constexpr uint32_t HYDA_AUDIT_PERIOD_MAX = 4096u;
constexpr uint32_t HYDA_AUDIT_CHUNKS_MAX = 64u;
constexpr uint32_t HYDA_AUDIT_REFS_MAX = 64u;

struct AuditPolicy {
  uint32_t period;
  uint32_t chunks;
  uint32_t refs;
  uint32_t reserved;
};

}

extern "C" hyda::AuditPolicy g_audit_policy;
