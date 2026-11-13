#pragma once

#include <array>
#include <cstdint>

#include "hyda/core/instance.hpp"

namespace hyda {

inline uint32_t blob_magic() { return seed_magic(0x424D5648ull); }

constexpr uint32_t HYDA_BLOB_VERSION = 4u;

constexpr uint32_t HYDA_BLOB_NO_CRYPT = 1u << 0;
constexpr uint32_t HYDA_BLOB_IDENTITY = 1u << 1;

constexpr uint32_t HYDA_BLOB_KNOWN_FLAGS =
    HYDA_BLOB_NO_CRYPT | HYDA_BLOB_IDENTITY;

constexpr uint32_t HYDA_BLOB_MAX_CODE = 1u << 20;

constexpr uint32_t HYDA_BLOB_MAX_ISLAND_SPAN = 1u << 20;

struct BlobHeader {
  uint32_t magic;
  uint32_t code_size;
  uint32_t entry_offset;
  uint32_t code_crc32;
  uint32_t version;
  uint32_t flags;
  uint32_t islands_rva;
  uint32_t island_count;
  uint32_t island_span;
  uint32_t import_tab_rva;

  uint64_t shard_mask;
};
static_assert(sizeof(BlobHeader) == 48, "blob header must be 48 bytes");

inline bool blob_no_crypt(const BlobHeader& h) {
  return (h.flags & HYDA_BLOB_NO_CRYPT) != 0;
}

inline bool blob_identity(const BlobHeader& h) {
  return (h.flags & HYDA_BLOB_IDENTITY) != 0;
}

inline bool blob_header_check(const BlobHeader& h) {
  if (h.magic != blob_magic()) return false;
  if (h.version != HYDA_BLOB_VERSION) return false;
  if ((h.flags & ~HYDA_BLOB_KNOWN_FLAGS) != 0) return false;
  if (h.code_size == 0 || h.code_size > HYDA_BLOB_MAX_CODE) return false;

  if (h.islands_rva == 0) {
    if (h.island_count != 0 || h.island_span != 0) return false;
  } else {
    if (h.island_count == 0) return false;
    if (h.island_span == 0 || h.island_span > HYDA_BLOB_MAX_ISLAND_SPAN) {
      return false;
    }
  }

  if (h.import_tab_rva == 0) {

  }
  return true;
}

inline uint32_t crc32(const uint8_t* p, uint32_t n, uint32_t seed = 0) {
  uint32_t c = seed ^ 0xFFFFFFFFu;
  for (uint32_t i = 0; i < n; ++i) {
    c ^= p[i];
    for (int k = 0; k < 8; ++k) {
      const uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(c & 1u));
      c = (c >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return c ^ 0xFFFFFFFFu;
}

constexpr std::array<uint32_t, 256> crc32_make_table() {
  std::array<uint32_t, 256> t{};
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) {
      c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
    }
    t[i] = c;
  }
  return t;
}

inline constexpr std::array<uint32_t, 256> kCrc32Table = crc32_make_table();

// Same result as crc32(), table-driven (used on the per-call integrity path).
inline uint32_t crc32_fast(const uint8_t* p, uint32_t n, uint32_t seed = 0) {
  uint32_t c = seed ^ 0xFFFFFFFFu;
  for (uint32_t i = 0; i < n; ++i) {
    c = kCrc32Table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFFu;
}

}
