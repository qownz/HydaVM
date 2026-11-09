#pragma once

#include "hyda/codec/crypt.hpp"
#include "hyda/core/instance.hpp"

#include <cstdint>

namespace hyda {

constexpr uint32_t HYDA_ADBG_FAIL_CODE = 0xD8u;
constexpr uint32_t HYDA_ADBG_LATENT_CODE = 0xD9u;

constexpr uint64_t HYDA_ADBG_SENTINEL = 0xADBDBDADBDBDADBDull;

enum AdbgSel : uint32_t {
  ADBG_PEB_BEING   = 0,
  ADBG_NTGLOBAL    = 1,
  ADBG_HEAP_FORCE  = 2,
  ADBG_DEBUG_PORT  = 3,
  ADBG_DEBUG_OBJ   = 4,
  ADBG_DEBUG_FLAGS = 5,
  ADBG_DR          = 6,
  ADBG_TF          = 7,
  ADBG_INT3        = 8,
  ADBG_NTDLL_CRC   = 9,
  ADBG_MODULE_SCAN = 10,

  HYDA_ADBG_CHECK_COUNT = 11,
};

constexpr uint32_t HYDA_ADBG_NTDLL_WINDOWS = 4u;

inline uint32_t adbg_sub_count(uint32_t sel) {
  if (sel == ADBG_DR) return 3;
  if (sel == ADBG_NTDLL_CRC) return HYDA_ADBG_NTDLL_WINDOWS;
  if (sel < HYDA_ADBG_CHECK_COUNT) return 1;
  return 0;
}

constexpr uint32_t HYDA_ADBG_WEIGHT_HARD = 1000u;
constexpr uint32_t HYDA_ADBG_WEIGHT_SOFT = 100u;
constexpr uint32_t HYDA_ADBG_THRESHOLD = HYDA_ADBG_WEIGHT_HARD;

#ifndef HYDA_ADBG_TICK_BATCH_N
#define HYDA_ADBG_TICK_BATCH_N 4u
#endif
constexpr uint32_t HYDA_ADBG_TICK_BATCH = HYDA_ADBG_TICK_BATCH_N;
constexpr uint32_t HYDA_ADBG_BATCH_MAX = HYDA_ADBG_CHECK_COUNT;

extern "C" uint64_t g_adbg_ntdll_baseline[HYDA_ADBG_NTDLL_WINDOWS];

constexpr uint64_t HYDA_ADBG_MASK_SEED = 0xB5D3E1F0A72C4918ull;
inline uint64_t adbg_state_mask(uint64_t slot) {
  const uint64_t z = crypt_mix(slot, HYDA_ADBG_MASK_SEED);
  return z != 0 ? z : 1u;
}
inline uint32_t adbg_cursor_mask() {
  return static_cast<uint32_t>(adbg_state_mask(1));
}
inline uint64_t adbg_poison_mask() {
  return adbg_state_mask(2);
}

inline uint64_t adbg_ntdll_want(uint32_t arg) {
  return g_adbg_ntdll_baseline[arg] ^ adbg_state_mask(0x10 + arg);
}

inline uint32_t adbg_sel_at(uint64_t index) {
  const uint64_t z =
      crypt_mix(HYDA_ADBG_CHECK_COUNT, vm_seed() ^ 0x11D7F0A0BEE3C2A6ull);
  const uint32_t step =
      1u + static_cast<uint32_t>(z % static_cast<uint64_t>(HYDA_ADBG_CHECK_COUNT - 1));
  const uint32_t off =
      static_cast<uint32_t>((z >> 24) % static_cast<uint64_t>(HYDA_ADBG_CHECK_COUNT));
  return static_cast<uint32_t>(
      (off + index * step) % static_cast<uint64_t>(HYDA_ADBG_CHECK_COUNT));
}

inline uint32_t adbg_eval(uint32_t sel, uint32_t arg, uint64_t obs) {
  switch (sel) {
    case ADBG_PEB_BEING:
      return obs == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_NTGLOBAL:
      return (obs & 0x70u) == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_HEAP_FORCE:
      return (obs & 0x70u) == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_DEBUG_PORT:
      return obs == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_DEBUG_OBJ:
      return (obs == 0 || obs == HYDA_ADBG_SENTINEL)
                 ? 0
                 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_DEBUG_FLAGS:
      return obs == 1u ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_DR:

      if (arg == 0 || arg == 1) return obs == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
      if (arg == 2) return (obs & 0xFFu) == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
      return HYDA_ADBG_WEIGHT_HARD;
    case ADBG_TF:
      return obs == 0 ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_INT3:
      return obs == 1 ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_NTDLL_CRC:
      if (arg >= HYDA_ADBG_NTDLL_WINDOWS) return HYDA_ADBG_WEIGHT_HARD;
      return obs == adbg_ntdll_want(arg) ? 0 : HYDA_ADBG_WEIGHT_HARD;
    case ADBG_MODULE_SCAN:
      return obs == 0 ? 0 : HYDA_ADBG_WEIGHT_SOFT;
    default:
      return HYDA_ADBG_WEIGHT_HARD;
  }
}

template <typename ReadFn>
inline uint32_t audit_adbg_phase(ReadFn read, uint32_t batch,
                                 uint32_t& cursor_m, uint64_t& poison_m) {
  uint32_t cur = cursor_m ^ adbg_cursor_mask();
  if (cur >= HYDA_ADBG_CHECK_COUNT) cur = 0;
  uint64_t poison = poison_m ^ adbg_poison_mask();
  uint32_t hard_seen = 0;
  uint32_t sanction = 0;

  for (uint32_t i = 0; i < batch && sanction == 0; ++i) {
    const uint32_t sel = adbg_sel_at(cur);
    cur = (cur + 1) % HYDA_ADBG_CHECK_COUNT;
    const uint32_t sub = adbg_sub_count(sel);
    for (uint32_t a = 0; a < sub; ++a) {
      const uint64_t obs = read(sel, a);
      const uint32_t w = adbg_eval(sel, a, obs);
      if (w == HYDA_ADBG_WEIGHT_HARD) hard_seen = 1;
      poison += w;
      if (poison >= HYDA_ADBG_THRESHOLD) {
        sanction = hard_seen != 0 ? HYDA_ADBG_FAIL_CODE : HYDA_ADBG_LATENT_CODE;
        break;
      }
    }
  }

  cursor_m = cur ^ adbg_cursor_mask();
  poison_m = poison ^ adbg_poison_mask();
  return sanction;
}

}
