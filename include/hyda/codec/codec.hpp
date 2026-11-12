#pragma once

#include "hyda/core/config.hpp"
#include "hyda/core/instance.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

constexpr unsigned kHeaderBytes = 2;

// The dispatch loop reads slots through the table built in
// src/vm/dispatch_asm.cpp, which tabulates this function.
constexpr uint8_t codec_mix_core(uint8_t v) {
  v = static_cast<uint8_t>(v + (v << 1));
  v = static_cast<uint8_t>(v ^ (v >> 3));
  v = static_cast<uint8_t>(v + (v << 2));
  v = static_cast<uint8_t>(v ^ (v >> 5));
  v = static_cast<uint8_t>(v + (v << 3));
  v = static_cast<uint8_t>(v ^ (v >> 6));
  return v;
}

inline uint8_t codec_mix8(uint8_t v, uint8_t k) {
  return codec_mix_core(static_cast<uint8_t>(v ^ k));
}

inline uint8_t codec_unmix8(uint8_t v, uint8_t k) {
  v = static_cast<uint8_t>(v ^ (v >> 6));
  v = static_cast<uint8_t>(v * 57u);
  v = static_cast<uint8_t>(v ^ (v >> 5));
  v = static_cast<uint8_t>(v * 205u);
  v = static_cast<uint8_t>(v ^ (v >> 3));
  v = static_cast<uint8_t>(v ^ (v >> 6));
  v = static_cast<uint8_t>(v * 171u);
  return static_cast<uint8_t>(v ^ k);
}

static_assert((3u * 171u) % 256u == 1u, "mix8 multiply inverse is wrong");
static_assert((5u * 205u) % 256u == 1u, "mix8 multiply inverse is wrong");
static_assert((9u * 57u) % 256u == 1u, "mix8 multiply inverse is wrong");

struct CodecKey {
  uint8_t k0 = 0;
  uint8_t k1 = 0;
};

inline void codec_init(CodecKey& ck, uint64_t key) {
  uint64_t z = key ^ 0xA24BAED4963EE407ull;
  z ^= z >> 31;
  z *= 0x9E3779B97F4A7C15ull;
  z ^= z >> 29;
  z *= 0xC2B2AE3D27D4EB4Full;
  z ^= z >> 27;
  ck.k0 = static_cast<uint8_t>(z);
  ck.k1 = static_cast<uint8_t>(z >> 8);
}

inline uint32_t codec_rnd_seed(uint64_t key) {
  return static_cast<uint32_t>(key ^ (key >> 32)) | 1u;
}

inline uint32_t codec_rand(uint32_t& s) {
  s ^= s << 13;
  s ^= s >> 17;
  s ^= s << 5;
  return s;
}

struct CodecMask {
  uint8_t rol;
  uint8_t ka;
  uint8_t kb;
  uint8_t fb;
};

inline CodecMask codec_mask(const CodecKey& ck, uint64_t z) {
  CodecMask m;
  m.rol = static_cast<uint8_t>(z >> 8);
  m.ka = static_cast<uint8_t>(ck.k0 ^ static_cast<uint8_t>(z));
  m.kb = static_cast<uint8_t>(ck.k1 ^ static_cast<uint8_t>(z >> 16));
  m.fb = static_cast<uint8_t>(z >> 24);
  return m;
}

inline uint16_t codec_decode(const CodecKey& ck, uint8_t h0, uint8_t h1,
                             uint64_t z) {
  const CodecMask m = codec_mask(ck, z);
  const uint16_t x = codec_mix8(static_cast<uint8_t>(h0 ^ m.rol), m.ka);
  const uint16_t y = codec_mix8(h1, m.kb);
  return static_cast<uint16_t>(
      ((x ^ m.fb) | static_cast<uint16_t>(y << 8)) & kSlotMask);
}

inline void codec_encode(const CodecKey& ck, uint16_t slot, uint64_t z,
                         uint32_t& rnd, uint8_t* h0, uint8_t* h1) {
  const CodecMask m = codec_mask(ck, z);
  const uint8_t xl = static_cast<uint8_t>((slot & 0xFFu) ^ m.fb);
  *h0 = static_cast<uint8_t>(codec_unmix8(xl, m.ka) ^ m.rol);
  const uint8_t y = static_cast<uint8_t>(((slot >> 8) & 0x03u) |
                                         (static_cast<uint8_t>(codec_rand(rnd)) &
                                          0xFCu));
  *h1 = codec_unmix8(y, m.kb);
}

}
