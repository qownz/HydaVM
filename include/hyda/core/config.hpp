#pragma once

#include <cstddef>
#include <cstdint>

#ifndef HYDA_VM_SEED
#define HYDA_VM_SEED 0x8F3A5C71D2E6B904ull
#endif

namespace hyda {

constexpr int NVREG = 25;

constexpr int kRegSlots = 256;

constexpr unsigned kSlotBits = 10;
constexpr size_t kSlotCount = size_t{1} << kSlotBits;
constexpr uint16_t kSlotMask = static_cast<uint16_t>(kSlotCount - 1);

enum VReg : int {
  REG_RAX = 0, REG_RCX, REG_RDX, REG_RBX,
  REG_RSP,     REG_RBP, REG_RSI, REG_RDI,
  REG_R8,      REG_R9, REG_R10, REG_R11,
  REG_R12,     REG_R13, REG_R14, REG_R15,
  REG_RIP    = 16,
  REG_RFLAGS = 17,
  REG_T0     = 18, REG_T1, REG_T2, REG_T3, REG_T4, REG_T5,
  REG_NOISE  = 24,
};

namespace vreg_detail {

constexpr uint64_t vreg_mix(uint64_t& x) {
  x += 0x9E3779B97F4A7C15ull;
  uint64_t z = x;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

struct VRegMap {
  uint8_t phys[NVREG];
};

constexpr VRegMap make_vreg_map() {
  VRegMap m{};
  for (int i = 0; i < NVREG; ++i) m.phys[i] = static_cast<uint8_t>(i);
  uint64_t s = static_cast<uint64_t>(HYDA_VM_SEED) ^ 0x6A09E667F3BCC908ull;
  for (int i = 15; i > 0; --i) {
    const uint64_t r = vreg_mix(s) % static_cast<uint64_t>(i + 1);
    const uint8_t t = m.phys[i];
    m.phys[i] = m.phys[static_cast<int>(r)];
    m.phys[static_cast<int>(r)] = t;
  }
  return m;
}

inline constexpr VRegMap kVRegMap = make_vreg_map();

}

constexpr int vsl(int logical) {
  return static_cast<int>(vreg_detail::kVRegMap.phys[logical]);
}

enum FlagBit : unsigned {
  F_CF = 0,
  F_PF = 2,
  F_AF = 4,
  F_ZF = 6,
  F_SF = 7,
  F_TF = 8,
  F_IF = 9,
  F_DF = 10,
  F_OF = 11,
};

constexpr uint8_t NO_MEM = 0xFF;

constexpr uint16_t kWin64VolatileMask =
    (1u << REG_RAX) | (1u << REG_RCX) | (1u << REG_RDX) | (1u << REG_R8) |
    (1u << REG_R9) | (1u << REG_R10) | (1u << REG_R11);

enum Status : uint32_t {
  ST_OK         = 0,
  ST_HALT       = 1,
  ST_BAD_OPCODE = 2,
  ST_FAULT      = 3,
  ST_DIV0       = 4,
  ST_STEP_LIMIT = 5,

  ST_BAD_REG    = 6,
};

}
