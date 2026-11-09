#pragma once

#include "hyda/codec/blob.hpp"
#include "hyda/core/config.hpp"
#include "hyda/codec/crypt.hpp"
#include "hyda/core/opcodes.hpp"

#include <cstddef>
#include <cstdint>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

namespace hyda {

inline uint32_t hydak_magic() { return seed_magic(0x4B414448ull); }

constexpr uint32_t HYDA_HYDAK_VERSION = 3u;

constexpr uint32_t HYDA_HYDAK_CODE_OFF = 32u;

constexpr uint16_t HYDA_HYDAK_NO_CHUNK = 0xFFFFu;

constexpr uint32_t HYDA_HYDAK_PART_ALIGN = 16u;

constexpr unsigned HYDA_HYDAK_MAX_PARTS = 48u;

struct HandlerShardDesc {
  uint8_t* ptr = nullptr;
  uint32_t size = 0;
  uint32_t rva = 0;
};

struct HydakHeader {
  uint32_t magic;
  uint32_t total_size;
  uint32_t code_size;
  uint32_t chunk_count;
  uint32_t chunks_off;
  uint32_t opmap_off;
  uint16_t bad_chunk;

  uint16_t version;
  uint32_t crc32;
};
static_assert(sizeof(HydakHeader) == 32, "hydak header must be 32 bytes");

struct HydakChunk {
  uint32_t off;
  uint32_t size;
  uint32_t orig_rva;
};
static_assert(sizeof(HydakChunk) == 12, "hydak chunk entry must be 12 bytes");

inline uint64_t hydak_key_for(uint32_t shard_rva) {
  uint64_t z = vm_seed() ^ 0x9E3779B97F4A7C15ull;
  z ^= static_cast<uint64_t>(shard_rva) * 0xC2B2AE3D27D4EB4Full;
  z ^= z >> 29;
  z *= 0xBF58476D1CE4E5B9ull;
  z ^= z >> 32;
  return z == 0 ? 1u : z;
}

namespace detail {

inline uint32_t hydak_avx2_state = 0xFFFFFFFFu;

#if defined(__x86_64__) || defined(__i386__)

inline void hydak_cpuid(uint32_t leaf, uint32_t sub, uint32_t* a, uint32_t* b,
                        uint32_t* c, uint32_t* d) {
  __asm__ __volatile__("cpuid"
                       : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                       : "a"(leaf), "c"(sub));
}

inline bool hydak_detect_avx2() {
  uint32_t a = 0, b = 0, c = 0, d = 0;
  hydak_cpuid(0u, 0u, &a, &b, &c, &d);
  if (a < 7u) return false;
  hydak_cpuid(1u, 0u, &a, &b, &c, &d);
  if ((c & (1u << 27)) == 0u) return false;
  uint32_t xlo = 0, xhi = 0;
  __asm__ __volatile__("xgetbv" : "=a"(xlo), "=d"(xhi) : "c"(0u));
  (void)xhi;
  if ((xlo & 0x6u) != 0x6u) return false;
  hydak_cpuid(7u, 0u, &a, &b, &c, &d);
  return (b & (1u << 5)) != 0u;
}

inline bool hydak_avx2_ok() {
  uint32_t s = hydak_avx2_state;
  if (s == 0xFFFFFFFFu) {
    s = hydak_detect_avx2() ? 1u : 0u;
    hydak_avx2_state = s;
  }
  return s == 1u;
}

#else

inline bool hydak_avx2_ok() { return false; }

#endif

inline void hydak_xor_scalar(uint8_t* p, uint32_t n, uint64_t key) {
  uint64_t idx = 0;
  uint32_t i = 0;
  while (i + 32u <= n) {
    const uint64_t z0 = crypt_mix(idx, key);
    const uint64_t z1 = crypt_mix(idx + 1u, key);
    const uint64_t z2 = crypt_mix(idx + 2u, key);
    const uint64_t z3 = crypt_mix(idx + 3u, key);
    for (unsigned b = 0; b < 8; ++b) {
      p[i + b] = static_cast<uint8_t>(p[i + b] ^ static_cast<uint8_t>(z0 >> (8 * b)));
      p[i + 8u + b] = static_cast<uint8_t>(p[i + 8u + b] ^ static_cast<uint8_t>(z1 >> (8 * b)));
      p[i + 16u + b] = static_cast<uint8_t>(p[i + 16u + b] ^ static_cast<uint8_t>(z2 >> (8 * b)));
      p[i + 24u + b] = static_cast<uint8_t>(p[i + 24u + b] ^ static_cast<uint8_t>(z3 >> (8 * b)));
    }
    i += 32u;
    idx += 4u;
  }
  while (i < n) {
    const uint64_t z = crypt_mix(idx, key);
    for (unsigned b = 0; b < 8 && i < n; ++b, ++i) {
      p[i] = static_cast<uint8_t>(p[i] ^ static_cast<uint8_t>(z >> (8 * b)));
    }
    ++idx;
  }
}

#if defined(__x86_64__) || defined(__i386__)

__attribute__((target("avx2"), always_inline)) inline __m256i
hydak_mul64x32(__m256i z, __m256i c) {
  const __m256i lo = _mm256_mul_epu32(z, c);
  const __m256i hi = _mm256_mul_epu32(_mm256_srli_epi64(z, 32), c);
  return _mm256_add_epi64(lo, _mm256_slli_epi64(hi, 32));
}

__attribute__((target("avx2"))) inline void hydak_xor_avx2(uint8_t* p,
                                                           uint32_t n,
                                                           uint64_t key) {
  const __m256i k = _mm256_set1_epi64x(static_cast<long long>(key));
  const __m256i m1 = _mm256_set1_epi64x(0x2C1B3C6Du);
  const __m256i m2 = _mm256_set1_epi64x(0x297A2D39u);
  const __m256i m3 = _mm256_set1_epi64x(0x1B873593u);
  const __m256i inc = _mm256_set1_epi64x(4);
  __m256i iv = _mm256_setr_epi64x(0, 1, 2, 3);
  uint64_t idx = 0;
  uint32_t i = 0;
  while (i + 32u <= n) {
    __m256i z = _mm256_xor_si256(iv, k);
    z = hydak_mul64x32(z, m1);
    z = _mm256_xor_si256(z, _mm256_srli_epi64(z, 29));
    z = hydak_mul64x32(z, m2);
    z = _mm256_xor_si256(z, _mm256_srli_epi64(z, 32));
    z = hydak_mul64x32(z, m3);
    z = _mm256_xor_si256(z, _mm256_srli_epi64(z, 29));
    const __m256i cur = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p + i));
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(p + i),
                        _mm256_xor_si256(cur, z));
    iv = _mm256_add_epi64(iv, inc);
    i += 32u;
    idx += 4u;
  }
  _mm256_zeroupper();
  while (i < n) {
    const uint64_t z = crypt_mix(idx, key);
    for (unsigned b = 0; b < 8 && i < n; ++b, ++i) {
      p[i] = static_cast<uint8_t>(p[i] ^ static_cast<uint8_t>(z >> (8 * b)));
    }
    ++idx;
  }
}
#endif

}

inline void hydak_xor(uint8_t* p, uint32_t n, uint64_t key) {
  if (key == 0 || p == nullptr || n == 0u) return;
#if defined(__x86_64__) || defined(__i386__)
  if (detail::hydak_avx2_ok()) {
    detail::hydak_xor_avx2(p, n, key);
    return;
  }
#endif
  detail::hydak_xor_scalar(p, n, key);
}

struct HydakView {
  const HydakHeader* h = nullptr;
  const HydakChunk* chunks = nullptr;
  const uint16_t* op_chunk = nullptr;
  uint8_t* base = nullptr;
};

enum HydakError : uint32_t {
  HYDAK_OK = 0,
  HYDAK_ERR_ARG = 1,
  HYDAK_ERR_MAGIC = 2,
  HYDAK_ERR_SIZE = 3,
  HYDAK_ERR_VERSION = 4,
  HYDAK_ERR_LAYOUT = 5,
  HYDAK_ERR_CRC = 6,
};

inline bool hydak_open(uint8_t* shard, uint32_t size, uint64_t key,
                       HydakView* out, uint32_t* err) {
  if (err) *err = HYDAK_OK;
  if (shard == nullptr || out == nullptr || size < sizeof(HydakHeader)) {
    if (err) *err = HYDAK_ERR_ARG;
    return false;
  }
  hydak_xor(shard, size, key);

  const HydakHeader* h = reinterpret_cast<const HydakHeader*>(shard);
  if (h->magic != hydak_magic()) { if (err) *err = HYDAK_ERR_MAGIC; return false; }
  if (h->version != HYDA_HYDAK_VERSION) { if (err) *err = HYDAK_ERR_VERSION; return false; }
  if (h->total_size != size) { if (err) *err = HYDAK_ERR_SIZE; return false; }

  if (h->chunk_count == 0 || h->chunk_count > OP_COUNT + 1 ||
      h->chunks_off + h->chunk_count * sizeof(HydakChunk) > size ||
      h->opmap_off + OP_COUNT * sizeof(uint16_t) > size ||
      (h->bad_chunk != HYDA_HYDAK_NO_CHUNK && h->bad_chunk >= h->chunk_count) ||
      static_cast<uint64_t>(HYDA_HYDAK_CODE_OFF) + h->code_size > size) {
    if (err) *err = HYDAK_ERR_LAYOUT;
    return false;
  }

  const uint8_t* pay = shard + sizeof(HydakHeader);
  const uint32_t pay_n = size - sizeof(HydakHeader);
  if (crc32(pay, pay_n) != h->crc32) { if (err) *err = HYDAK_ERR_CRC; return false; }

  out->h = h;
  out->chunks = reinterpret_cast<const HydakChunk*>(shard + h->chunks_off);
  out->op_chunk = reinterpret_cast<const uint16_t*>(shard + h->opmap_off);
  out->base = shard;
  return true;
}

inline bool hydak_probe(const uint8_t* p, uint32_t avail, uint64_t key,
                        uint32_t* total) {
  if (p == nullptr || avail < sizeof(HydakHeader)) return false;
  uint8_t buf[sizeof(HydakHeader)];
  for (uint32_t i = 0; i < sizeof(HydakHeader); ++i) buf[i] = p[i];
  hydak_xor(buf, static_cast<uint32_t>(sizeof(HydakHeader)), key);
  const HydakHeader* h = reinterpret_cast<const HydakHeader*>(buf);
  const bool ok = (h->magic == hydak_magic()) &&
                  (h->version == HYDA_HYDAK_VERSION);
  const uint32_t t = h->total_size;
  if (ok && total) *total = t;
  return ok;
}

inline unsigned hydak_scan_parts(const uint8_t* sec, uint32_t sec_size,
                                 uint32_t sec_rva, HandlerShardDesc* out,
                                 unsigned cap, uint32_t* err) {
  if (err) *err = HYDAK_OK;
  if (sec == nullptr || out == nullptr) {
    if (err) *err = HYDAK_ERR_ARG;
    return 0;
  }
  constexpr uint32_t kAlign = HYDA_HYDAK_PART_ALIGN;
  unsigned n = 0;
  uint32_t off = 0;
  while (off + sizeof(HydakHeader) <= sec_size) {
    uint32_t total = 0;
    if (hydak_probe(sec + off, sec_size - off, hydak_key_for(sec_rva + off),
                    &total) &&
        total >= sizeof(HydakHeader) && total <= sec_size - off) {
      if (n >= cap) {
        if (err) *err = HYDAK_ERR_LAYOUT;
        return 0;
      }
      out[n].ptr = const_cast<uint8_t*>(sec + off);
      out[n].size = total;
      out[n].rva = sec_rva + off;
      ++n;
      const uint32_t step = (total + kAlign - 1u) & ~(kAlign - 1u);
      off += step;
    } else {
      off += kAlign;
    }
  }
  return n;
}

struct HydakCatalog {
  uint64_t addrs[OP_COUNT] = {};
  uint8_t claim[OP_COUNT] = {};
  uint64_t bad = 0;
  uint8_t bad_claim = 0;
  uint16_t shards = 0;
};

inline bool hydak_catalog_add(HydakCatalog* c, const HydakView& v,
                              uint32_t* err) {
  if (err) *err = HYDAK_OK;
  if (c == nullptr || v.h == nullptr || v.chunks == nullptr ||
      v.op_chunk == nullptr) {
    if (err) *err = HYDAK_ERR_ARG;
    return false;
  }
  const HydakHeader* h = v.h;
  const uint64_t base = reinterpret_cast<uint64_t>(v.base);

  uint8_t hit[(OP_COUNT + 1 + 7) / 8] = {};
  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint16_t chunk = v.op_chunk[op];
    if (chunk == HYDA_HYDAK_NO_CHUNK) continue;
    if (chunk >= h->chunk_count) {
      if (err) *err = HYDAK_ERR_LAYOUT;
      return false;
    }
    hit[chunk >> 3] = static_cast<uint8_t>(hit[chunk >> 3] | (1u << (chunk & 7u)));
  }
  if (h->bad_chunk != HYDA_HYDAK_NO_CHUNK) {
    if (h->bad_chunk >= h->chunk_count || c->bad_claim) {
      if (err) *err = HYDAK_ERR_LAYOUT;
      return false;
    }
    hit[h->bad_chunk >> 3] =
        static_cast<uint8_t>(hit[h->bad_chunk >> 3] | (1u << (h->bad_chunk & 7u)));
    c->bad = base + v.chunks[h->bad_chunk].off;
    c->bad_claim = 1;
  }
  for (uint32_t k = 0; k < h->chunk_count; ++k) {
    if ((hit[k >> 3] & (1u << (k & 7u))) == 0) {
      if (err) *err = HYDAK_ERR_LAYOUT;
      return false;
    }
  }

  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint16_t chunk = v.op_chunk[op];
    if (chunk == HYDA_HYDAK_NO_CHUNK) continue;
    if (c->claim[op] != 0) {
      if (err) *err = HYDAK_ERR_LAYOUT;
      return false;
    }
    c->claim[op] = 1;
    c->addrs[op] = base + v.chunks[chunk].off;
  }
  ++c->shards;
  return true;
}

inline bool hydak_catalog_finish(const HydakCatalog* c, uint32_t* err) {
  if (err) *err = HYDAK_OK;
  if (c == nullptr || c->shards == 0 || c->bad_claim == 0) {
    if (err) *err = HYDAK_ERR_LAYOUT;
    return false;
  }
  for (size_t op = 0; op < OP_COUNT; ++op) {
    if (c->claim[op] == 0) {
      if (err) *err = HYDAK_ERR_LAYOUT;
      return false;
    }
  }
  return true;
}

}
