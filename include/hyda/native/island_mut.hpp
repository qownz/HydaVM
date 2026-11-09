#pragma once

#include <cstdint>
#include <cstring>

#include "hyda/core/config.hpp"
#include "hyda/codec/crypt.hpp"
#include "hyda/native/island.hpp"

namespace hyda {

struct IslandMutPlan {
  uint32_t magic;
  uint8_t version;
  uint8_t insn_off;
  uint8_t insn_len;
  uint8_t flip;
  uint8_t flip_off;
  uint8_t disp_off;
  uint16_t tail_off;
  uint32_t pad_seed;
  uint32_t rsv0;
  uint32_t rsv1;
};
static_assert(sizeof(IslandMutPlan) == 24, "mutation plan must be 24 bytes");

constexpr uint8_t HYDA_MUT_NO_DISP = 0xFF;

constexpr uint32_t HYDA_MUT_SLACK = 6;

constexpr uint32_t HYDA_MUT_STATE_MAGIC = 0xA5C3u;
constexpr uint32_t HYDA_MUT_STATE_FLIP = 1u << 8;

enum : uint32_t {
  HYDA_MUT_OK = 0,
  HYDA_MUT_NO_PLAN = 1,
  HYDA_MUT_BAD_PLAN = 2,
  HYDA_MUT_BAD_STATE = 3,
  HYDA_MUT_BAD_BYTES = 4,
};

inline uint32_t island_mut_magic() {
  uint64_t z = static_cast<uint64_t>(vm_seed()) ^ 0x8AD1C0DE12345678ull;
  z ^= z >> 33;
  z *= 0xFF51AFD7ED558CCDull;
  z ^= z >> 33;
  z *= 0xC4CEB9FE1A85EC53ull;
  z ^= z >> 33;
  uint32_t m = static_cast<uint32_t>(z ^ (z >> 32));
  if ((m & 0xFFu) == 0xE9u || (m & 0xFFu) == 0u) m ^= 0x0000A5u;
  return m;
}

inline uint8_t island_mut_fill(uint32_t seed, uint32_t j) {
  const uint64_t z = crypt_mix(static_cast<uint64_t>(j) + 1u, seed);
  return static_cast<uint8_t>((z >> 17) ^ (z >> 41));
}

struct SsePair {
  uint8_t op;
  uint8_t alt;
};

constexpr uint32_t HYDA_SSE_PAIR_COUNT = 8;

inline const SsePair* sse_pair(uint8_t kind) {
  static const SsePair kPairs[HYDA_SSE_PAIR_COUNT] = {
      {0xEF, 0x57},
      {0xDB, 0x54},
      {0xEB, 0x56},
      {0xDF, 0x55},
      {0x10, 0x10},
      {0x6F, 0x28},
      {0x11, 0x11},
      {0x7F, 0x29},
  };
  if (kind == 0 || kind > HYDA_SSE_PAIR_COUNT) return nullptr;
  return &kPairs[kind - 1];
}

inline bool sse_flip(uint8_t* p, uint8_t kind) {
  const SsePair* pr = sse_pair(kind);
  if (pr == nullptr || p == nullptr) return false;
  if (p[0] != 0x66 || p[1] != 0x0F || p[2] != pr->op) return false;
  const uint8_t modrm = p[3];
  p[0] = 0x0F;
  p[1] = pr->alt;
  p[2] = modrm;
  p[3] = 0x90;
  return true;
}

inline bool sse_unflip(uint8_t* p, uint8_t kind) {
  const SsePair* pr = sse_pair(kind);
  if (pr == nullptr || p == nullptr) return false;
  if (p[0] != 0x0F || p[1] != pr->alt || p[3] != 0x90) return false;
  const uint8_t modrm = p[2];
  p[0] = 0x66;
  p[1] = 0x0F;
  p[2] = pr->op;
  p[3] = modrm;
  return true;
}

inline void mut_move(uint8_t* dst, const uint8_t* src, uint32_t n) {
  if (dst == nullptr || src == nullptr || n == 0u) return;
  if (dst == src) return;
  if (dst < src) {
    for (uint32_t i = 0; i < n; ++i) dst[i] = src[i];
  } else {
    for (uint32_t i = n; i > 0u; --i) dst[i - 1u] = src[i - 1u];
  }
}

inline uint32_t mut_rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

inline void mut_wr32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16);
  p[3] = static_cast<uint8_t>(v >> 24);
}

inline bool island_mut_plan_load(const uint8_t* payload, uint32_t size,
                                 IslandMutPlan* out) {
  if (payload == nullptr || out == nullptr) return false;
  if (size < sizeof(IslandMutPlan) + 8u) return false;
  {

    const uint8_t* src = payload + size - sizeof(IslandMutPlan);
    uint8_t* dst = reinterpret_cast<uint8_t*>(out);
    for (uint32_t i = 0; i < sizeof(IslandMutPlan); ++i) dst[i] = src[i];
  }
  if (out->magic != island_mut_magic()) return false;
  if (out->version != 1u) return false;
  return true;
}

inline uint32_t island_mut_slack(uint32_t size, uint16_t tail_off) {
  const uint32_t dead_from = static_cast<uint32_t>(tail_off) + 5u;
  const uint32_t plan_from = size - static_cast<uint32_t>(sizeof(IslandMutPlan));
  return (plan_from > dead_from) ? (plan_from - dead_from) : 0u;
}

inline uint32_t island_mutate(uint8_t* payload, uint32_t size, uint32_t key,
                              uint32_t* state) {
  IslandMutPlan pl;
  if (!island_mut_plan_load(payload, size, &pl)) return HYDA_MUT_NO_PLAN;
  if (state == nullptr) return HYDA_MUT_BAD_STATE;
  if (pl.insn_off + pl.insn_len > size) return HYDA_MUT_BAD_PLAN;
  if (pl.tail_off + 5u > size) return HYDA_MUT_BAD_PLAN;
  if (pl.tail_off < static_cast<uint32_t>(pl.insn_off) + pl.insn_len) {
    return HYDA_MUT_BAD_PLAN;
  }
  const uint32_t slack = island_mut_slack(size, pl.tail_off);
  if (slack == 0u) return HYDA_MUT_NO_PLAN;

  uint32_t st = HYDA_MUT_STATE_MAGIC << 16;

  if (pl.flip != 0u) {
    const uint32_t at = static_cast<uint32_t>(pl.insn_off) + pl.flip_off;
    if (at + 4u > size || pl.flip_off + 4u > pl.insn_len) {
      return HYDA_MUT_BAD_PLAN;
    }
    if (!sse_flip(payload + at, pl.flip)) return HYDA_MUT_BAD_BYTES;
    st |= HYDA_MUT_STATE_FLIP;
  }

  uint32_t k = key % (slack + 1u);
  if (k > 3u) k = 3u;
  if (k > 0u) {
    static const uint8_t kSeg[4] = {0x2E, 0x3E, 0x26, 0x36};
    uint8_t pre[3];
    uint64_t z = key | 1u;
    for (uint32_t i = 0; i < k; ++i) {
      z = z * 6364136223846793005ull + 1442695040888963407ull;
      pre[i] = kSeg[(z >> 60) & 3u];
    }
    const uint32_t blk = static_cast<uint32_t>(pl.tail_off) + 5u - pl.insn_off;
    mut_move(payload + pl.insn_off + k, payload + pl.insn_off, blk);
    for (uint32_t i = 0; i < k; ++i) payload[pl.insn_off + i] = pre[i];

    const uint32_t rat = static_cast<uint32_t>(pl.tail_off) + k + 1u;
    if (rat + 4u > size) return HYDA_MUT_BAD_PLAN;
    mut_wr32(payload + rat,
             mut_rd32(payload + rat) - static_cast<uint32_t>(k));

    if (pl.disp_off != HYDA_MUT_NO_DISP && pl.disp_off != 0u) {
      const uint32_t at = static_cast<uint32_t>(pl.disp_off) + k;
      if (at + 4u > size) return HYDA_MUT_BAD_PLAN;
      mut_wr32(payload + at, mut_rd32(payload + at) - static_cast<uint32_t>(k));
    }
    st |= k;
  }

  *state = st;
  return HYDA_MUT_OK;
}

inline uint32_t island_unmutate(uint8_t* payload, uint32_t size,
                                uint32_t state) {
  IslandMutPlan pl;
  if (!island_mut_plan_load(payload, size, &pl)) return HYDA_MUT_NO_PLAN;
  if ((state >> 16) != HYDA_MUT_STATE_MAGIC) return HYDA_MUT_BAD_STATE;
  const uint32_t k = state & 0xFu;
  const bool flipped = (state & HYDA_MUT_STATE_FLIP) != 0u;
  const uint32_t slack = island_mut_slack(size, pl.tail_off);
  if (k > slack || k > 3u) return HYDA_MUT_BAD_STATE;

  if (k > 0u) {

    if (pl.disp_off != HYDA_MUT_NO_DISP && pl.disp_off != 0u) {
      const uint32_t at = static_cast<uint32_t>(pl.disp_off) + k;
      if (at + 4u > size) return HYDA_MUT_BAD_PLAN;
      mut_wr32(payload + at, mut_rd32(payload + at) + static_cast<uint32_t>(k));
    }

    const uint32_t blk = static_cast<uint32_t>(pl.tail_off) + 5u - pl.insn_off;
    mut_move(payload + pl.insn_off, payload + pl.insn_off + k, blk);

    const uint32_t rat = static_cast<uint32_t>(pl.tail_off) + 1u;
    if (rat + 4u > size) return HYDA_MUT_BAD_PLAN;
    mut_wr32(payload + rat,
             mut_rd32(payload + rat) + static_cast<uint32_t>(k));
  }

  if (flipped) {
    const uint32_t at = static_cast<uint32_t>(pl.insn_off) + pl.flip_off;
    if (at + 4u > size) return HYDA_MUT_BAD_PLAN;
    if (!sse_unflip(payload + at, pl.flip)) return HYDA_MUT_BAD_BYTES;
  }

  for (uint32_t j = 0; j < slack; ++j) {
    payload[pl.tail_off + 5u + j] = island_mut_fill(pl.pad_seed, j);
  }
  return HYDA_MUT_OK;
}

}

extern "C" {
extern uint32_t hyda_g_island_mut_k;
}
