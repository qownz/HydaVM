#pragma once

#include "hyda/core/config.hpp"
#include "hyda/codec/crypt.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

struct IslandHeader {
  uint32_t magic;
  uint32_t size;
  uint32_t salt;
  uint32_t flags;
  uint64_t refs;
  uint32_t import_index;

  uint32_t reserved2;
};
static_assert(sizeof(IslandHeader) == 32, "island header must be 32 bytes");
static_assert(offsetof(IslandHeader, magic) == 0, "island header offset");
static_assert(offsetof(IslandHeader, size) == 4, "island header offset");
static_assert(offsetof(IslandHeader, salt) == 8, "island header offset");
static_assert(offsetof(IslandHeader, flags) == 12, "island header offset");
static_assert(offsetof(IslandHeader, refs) == 16, "island header offset");
static_assert(offsetof(IslandHeader, import_index) == 24, "island header offset");

constexpr uint32_t HYDA_ISLAND_SIZE = 32u;

constexpr uint32_t HYDA_ISLAND_IMPORT = 1u << 0;

constexpr uint32_t HYDA_ISLAND_KNOWN_FLAGS = HYDA_ISLAND_IMPORT;

inline uint32_t island_magic() {
  uint64_t z = static_cast<uint64_t>(vm_seed()) ^ 0xA5A5C3C3F0F0F0F0ull;
  z ^= z >> 31;
  z *= 0xBF58476D1CE4E5B9ull;
  z ^= z >> 27;
  return static_cast<uint32_t>(z ^ (z >> 32)) | 1u;
}

inline uint64_t island_key_for(uint32_t salt, uint32_t rva) {
  uint64_t z = static_cast<uint64_t>(salt) * 0x9E3779B97F4A7C15ull;
  z ^= static_cast<uint64_t>(rva) + 0x165667B19E3779F9ull;
  z ^= static_cast<uint64_t>(vm_seed());
  z ^= z >> 29;
  z *= 0xBF58476D1CE4E5B9ull;
  z ^= z >> 32;
  return z == 0 ? 1u : z;
}

inline uint32_t island_salt_for(uint32_t idx, uint32_t rva) {
  uint64_t z = static_cast<uint64_t>(vm_seed()) ^
               (static_cast<uint64_t>(idx) + 0x9E3779B97F4A7C15ull) ^
               (static_cast<uint64_t>(rva) * 0xD6E8FEB86659FD93ull);
  z ^= z >> 32;
  z *= 0xD6E8FEB86659FD93ull;
  z ^= z >> 32;
  return static_cast<uint32_t>(z);
}

inline void island_crypt(uint8_t* p, uint32_t n, uint64_t key, bool encrypt) {
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

inline void island_encrypt(uint8_t* p, uint32_t n, uint64_t key) {
  island_crypt(p, n, key, true);
}

inline void island_decrypt(uint8_t* p, uint32_t n, uint64_t key) {
  island_crypt(p, n, key, false);
}

inline bool island_header_check(const IslandHeader& h) {
  if (h.magic != island_magic()) return false;
  if (h.size == 0 || h.size > (1u << 16)) return false;
  if ((h.flags & ~HYDA_ISLAND_KNOWN_FLAGS) != 0) return false;
  return true;
}

constexpr uint32_t kIslandLeaveAliasCount = 4u;

extern uint32_t g_import_table_rva;

}
