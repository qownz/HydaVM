#pragma once

#include <cstddef>
#include <cstdint>

namespace hyda {

constexpr size_t kFpLegacy = 512;
constexpr size_t kFpXsaveHeader = 64;
constexpr size_t kFpYmmOff = kFpLegacy + kFpXsaveHeader;
constexpr size_t kFpSize = kFpYmmOff + 16 * 16;

struct alignas(64) HydaFpState {
  uint8_t b[kFpSize];

  constexpr HydaFpState() : b{} {
    b[0] = 0x7F;
    b[1] = 0x03;
    b[24] = 0x80;
    b[25] = 0x1F;
    b[kFpLegacy] = 0x07;
  }

  static constexpr unsigned xmm_off(int n) {
    return 160u + 16u * static_cast<unsigned>(n);
  }
  static constexpr unsigned ymm_hi_off(int n) {
    return static_cast<unsigned>(kFpYmmOff) + 16u * static_cast<unsigned>(n);
  }

  uint64_t* xmm(int n) { return reinterpret_cast<uint64_t*>(b + xmm_off(n)); }
  const uint64_t* xmm(int n) const {
    return reinterpret_cast<const uint64_t*>(b + xmm_off(n));
  }
  uint64_t* ymm_hi(int n) {
    return reinterpret_cast<uint64_t*>(b + ymm_hi_off(n));
  }
  const uint64_t* ymm_hi(int n) const {
    return reinterpret_cast<const uint64_t*>(b + ymm_hi_off(n));
  }
};

static_assert(sizeof(HydaFpState) == kFpSize, "wrong XSAVE area size");
static_assert(alignof(HydaFpState) == 64, "XSAVE area must be 64-byte aligned");
static_assert(offsetof(HydaFpState, b) == 0, "XSAVE area must be at offset 0");

HydaFpState* fp_state();

bool fp_supports_avx();

}
