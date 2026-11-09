#pragma once

#include "hyda/core/config.hpp"
#include "hyda/codec/crypt.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

inline uint32_t integrity_magic() { return seed_magic(0x52474E49ull); }
constexpr uint32_t HYDA_INTEGRITY_VERSION = 2u;
constexpr uint32_t HYDA_INTEGRITY_MAX_CHUNKS = 1024u;

#ifndef HYDA_INTEGRITY_WINDOW_BYTES
#define HYDA_INTEGRITY_WINDOW_BYTES 4096u
#endif
constexpr uint32_t HYDA_INTEGRITY_WINDOW = HYDA_INTEGRITY_WINDOW_BYTES;

constexpr uint32_t HYDA_INTEGRITY_FAIL_CODE = 0xD0u;

extern "C" uint32_t hyda_g_integrity_rva;

struct IntegrityCrcTable {
  uint32_t t[256];
  constexpr IntegrityCrcTable() : t{} {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) {
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      }
      t[i] = c;
    }
  }
};
inline constexpr IntegrityCrcTable kIntegrityCrc{};

inline uint32_t integrity_crc32(const uint8_t* p, size_t n,
                                uint32_t seed = 0) {
  uint32_t c = seed ^ 0xFFFFFFFFu;
  for (size_t i = 0; i < n; ++i) {
    c = kIntegrityCrc.t[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFFu;
}

inline uint64_t integrity_key_for(uint32_t salt, uint32_t manifest_rva) {
  uint64_t z = static_cast<uint64_t>(salt) * 0x9E3779B97F4A7C15ull;
  z ^= static_cast<uint64_t>(manifest_rva) + 0x165667B19E3779F9ull;
  z ^= static_cast<uint64_t>(vm_seed());
  z ^= z >> 29;
  z *= 0xBF58476D1CE4E5B9ull;
  z ^= z >> 32;
  return z == 0 ? 1u : z;
}

inline void integrity_crypt(uint8_t* p, uint32_t n, uint64_t key,
                             bool encrypt) {
  if (p == nullptr || n == 0 || key == 0) return;
  uint8_t prev = 0;
  uint32_t i = 0;
  while (i < n) {
    const uint64_t z = crypt_mix(static_cast<uint64_t>(i), key);
    for (unsigned j = 0; j < 8 && i < n; ++j, ++i) {
      const uint8_t k = crypt_ks_byte(z, i);
      if (encrypt) {
        p[i] = static_cast<uint8_t>(p[i] + k + prev);
        prev = p[i];
      } else {
        const uint8_t c = p[i];
        p[i] = static_cast<uint8_t>(c - k - prev);
        prev = c;
      }
    }
  }
}

struct IntegrityChunk {
  uint32_t rva;
  uint32_t size;
  uint32_t crc32;
  uint32_t flags;
};
static_assert(sizeof(IntegrityChunk) == 16, "integrity chunk must be 16 bytes");

struct IntegrityManifest {
  uint32_t magic;
  uint32_t version;
  uint32_t count;
  uint32_t chunks_rva;
  uint32_t self_crc32;
  uint32_t salt;
  uint32_t reserved[2];
};
static_assert(sizeof(IntegrityManifest) == 32, "integrity manifest is 32 bytes");

struct IntegrityRegion {
  uint32_t rva;
  uint32_t size;
  uint32_t raw;
};
static_assert(sizeof(IntegrityRegion) == 12, "integrity region is 12 bytes");

struct RelocHole {
  uint32_t rva;
  uint32_t size;
};

inline uint32_t integrity_collect_holes(const uint8_t* base, uint32_t reloc_rva,
                                        uint32_t reloc_size, RelocHole* out,
                                        uint32_t max) {
  if (base == nullptr || reloc_rva == 0 || reloc_size == 0) return 0;
  if (out == nullptr) return 0;
  uint32_t n = 0;
  uint32_t pos = 0;
  while (pos + 8 <= reloc_size) {
    const uint8_t* blk = base + reloc_rva + pos;
    const uint32_t page = static_cast<uint32_t>(blk[0]) |
                          (static_cast<uint32_t>(blk[1]) << 8) |
                          (static_cast<uint32_t>(blk[2]) << 16) |
                          (static_cast<uint32_t>(blk[3]) << 24);
    const uint32_t bsize = static_cast<uint32_t>(blk[4]) |
                           (static_cast<uint32_t>(blk[5]) << 8) |
                           (static_cast<uint32_t>(blk[6]) << 16) |
                           (static_cast<uint32_t>(blk[7]) << 24);
    if (bsize < 8 || pos + bsize > reloc_size) break;
    const uint32_t cnt = (bsize - 8) / 2;
    for (uint32_t i = 0; i < cnt; ++i) {
      const uint8_t* ep = blk + 8 + i * 2;
      const uint16_t e = static_cast<uint16_t>(ep[0]) |
                         (static_cast<uint16_t>(ep[1]) << 8);
      const uint32_t type = e >> 12;
      const uint32_t off = e & 0xFFFu;
      if (type == 0) continue;
      uint32_t hsz = 0;
      if (type == 10) hsz = 8;
      else if (type == 3) hsz = 4;
      else continue;
      if (n >= max) return n;
      out[n].rva = page + off;
      out[n].size = hsz;
      ++n;
    }
    pos += bsize;
  }
  return n;
}

inline uint32_t integrity_split_region(uint32_t rva_start, uint32_t rva_end,
                                        const RelocHole* holes,
                                        uint32_t hole_count,
                                        IntegrityChunk* out, uint32_t max) {
  if (out == nullptr || rva_end <= rva_start) return 0;
  uint32_t n = 0;
  uint32_t cur = rva_start;
  const auto emit = [&](uint32_t a, uint32_t b) {
    while (a < b) {
      const uint32_t w = (b - a > HYDA_INTEGRITY_WINDOW)
                             ? HYDA_INTEGRITY_WINDOW : (b - a);
      if (n >= max) return;
      out[n].rva = a;
      out[n].size = w;
      out[n].crc32 = 0;
      out[n].flags = 0;
      ++n;
      a += w;
    }
  };
  for (uint32_t i = 0; i < hole_count; ++i) {
    const RelocHole h = holes[i];
    if (h.size == 0) continue;
    if (h.rva + h.size <= rva_start) continue;
    if (h.rva >= rva_end) break;
    const uint32_t hs = h.rva < rva_start ? rva_start : h.rva;
    const uint32_t he = (h.rva + h.size > rva_end) ? rva_end : (h.rva + h.size);
    if (hs > cur) emit(cur, hs);
    if (he > cur) cur = he;
  }
  emit(cur, rva_end);
  return n;
}

inline uint32_t integrity_chunk_crc(const uint8_t* base, uint32_t rva,
                                    uint32_t size) {
  return integrity_crc32(base + rva, size);
}

inline void integrity_crypt_range(const uint8_t* src, uint32_t off, uint32_t n,
                                  uint64_t key, uint8_t* out) {
  if (src == nullptr || out == nullptr || n == 0 || key == 0) return;
  uint8_t prev = (off == 0) ? 0u : src[off - 1u];
  const uint32_t end = off + n;
  uint32_t i = off;
  while (i < end) {

    const uint64_t z = crypt_mix(static_cast<uint64_t>(i & ~7u), key);
    for (unsigned j = 0; j < 8 && i < end; ++j, ++i) {
      const uint8_t k = crypt_ks_byte(z, i);
      const uint8_t c = src[i];
      out[i - off] = static_cast<uint8_t>(c - k - prev);
      prev = c;
    }
  }
}

inline uint32_t integrity_chunks_crc(const IntegrityChunk* chunks,
                                     uint32_t count) {
  if (chunks == nullptr || count == 0) return 0;
  return integrity_crc32(reinterpret_cast<const uint8_t*>(chunks),
                         static_cast<size_t>(count) * sizeof(IntegrityChunk));
}

inline bool integrity_check_chunk(const uint8_t* base, const IntegrityChunk& c) {
  if (c.size == 0) return false;
  return integrity_chunk_crc(base, c.rva, c.size) == c.crc32;
}

}
