#pragma once

#include <cstdint>

#include "hyda/codec/crypt.hpp"
#include "hyda/codec/hydak.hpp"
#include "hyda/guard/integrity.hpp"

namespace hyda {

inline uint32_t dat_magic() { return seed_magic(0x54414448ull); }
constexpr uint32_t HYDA_DAT_VERSION = 1u;
constexpr uint32_t HYDA_DAT_ALIGN = 16u;

struct DatHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t total_size;
  uint32_t count;
  uint32_t salt;
  uint32_t self_crc32;
  uint32_t reserved[2];
};
static_assert(sizeof(DatHeader) == 32, "dat header must be 32 bytes");

inline uint64_t dat_key_for(uint32_t rva) { return hydak_key_for(rva); }

inline bool dat_probe(uint8_t* p, uint32_t avail, uint64_t key,
                      uint32_t* total_out) {
  if (p == nullptr || avail < sizeof(DatHeader) || key == 0) return false;
  hydak_xor(p, static_cast<uint32_t>(sizeof(DatHeader)), key);
  const DatHeader* h = reinterpret_cast<const DatHeader*>(p);
  const bool ok = (h->magic == dat_magic()) &&
                  (h->version == HYDA_DAT_VERSION);
  const uint32_t t = h->total_size;
  hydak_xor(p, static_cast<uint32_t>(sizeof(DatHeader)), key);
  if (!ok || t < sizeof(DatHeader) || t > avail) return false;
  if (total_out != nullptr) *total_out = t;
  return true;
}

inline bool dat_open(uint8_t* p, uint32_t avail, uint64_t key, DatHeader* out) {
  if (p == nullptr || out == nullptr || key == 0) return false;
  uint32_t total = 0;
  if (!dat_probe(p, avail, key, &total)) return false;
  if (total > avail) return false;
  hydak_xor(p, total, key);
  const DatHeader* h = reinterpret_cast<const DatHeader*>(p);
  const bool ok = (h->magic == dat_magic()) &&
                  (h->version == HYDA_DAT_VERSION) && (h->total_size == total) &&
                  (h->count != 0) &&
                  (h->count <= HYDA_INTEGRITY_MAX_CHUNKS) &&
                  (total == sizeof(DatHeader) + h->count * sizeof(IntegrityChunk));
  if (!ok) {
    hydak_xor(p, total, key);
    return false;
  }
  *out = *h;
  return true;
}

inline void dat_close(uint8_t* p, uint32_t total, uint64_t key) {
  if (p == nullptr || total == 0 || key == 0) return;
  hydak_xor(p, total, key);
}

inline uint8_t* dat_payload(DatHeader* h) {
  return reinterpret_cast<uint8_t*>(h) + sizeof(DatHeader);
}

}
