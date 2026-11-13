#pragma once

#include "hyda/codec/codec.hpp"
#include "hyda/core/config.hpp"
#include "hyda/core/opcodes.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

inline uint64_t crypt_key_for(uint32_t blob_rva) {
  uint64_t z = vm_seed() ^ 0x51ED2701B3F4A9C7ull;
  z ^= static_cast<uint64_t>(blob_rva) * 0x9E3779B97F4A7C15ull;
  z ^= z >> 31;
  return z == 0 ? 1u : z;
}

// Must match crypt_mix in src/vm/dispatch_asm.cpp.
inline uint64_t crypt_mix(uint64_t vip, uint64_t key) {
  uint64_t z = vip ^ key;
  z *= 0x2C1B3C6Du;
  z ^= z >> 29;
  z *= 0x297A2D39u;
  z ^= z >> 32;
  z *= 0x1B873593u;
  z ^= z >> 29;
  return z;
}

inline uint8_t crypt_ks_byte(uint64_t z, unsigned i) {
  const uint8_t lo = static_cast<uint8_t>((z >> (8u * (i & 7u))) & 0xFFu);
  const uint8_t hi = static_cast<uint8_t>((z >> (8u * ((i + 4u) & 7u))) & 0xFFu);
  uint8_t k = static_cast<uint8_t>(lo ^ hi);
  if (i >= 8) k = static_cast<uint8_t>(k ^ 0xA5u);
  return k;
}

inline uint8_t crypt_ks_byte_v(uint64_t z, unsigned i, uint32_t variant) {
  unsigned a = i;
  unsigned b = i + 4u;
  if ((variant & 1u) != 0) {
    a = i ^ 1u;
    b = (i + 4u) ^ 1u;
  }
  const uint8_t lo = static_cast<uint8_t>((z >> (8u * (a & 7u))) & 0xFFu);
  const uint8_t hi = static_cast<uint8_t>((z >> (8u * (b & 7u))) & 0xFFu);
  uint8_t k = static_cast<uint8_t>(lo ^ hi);
  if (i >= 8) k = static_cast<uint8_t>(k ^ 0xA5u);
  return k;
}

namespace detail {

inline uint64_t codec_stream_key(uint64_t key, uint32_t variant) {
  return key ^ (static_cast<uint64_t>(variant) * 0x27D4EB2Du);
}

template <bool kEncrypt>
inline void crypt_operands_impl(uint8_t* code, size_t size, uint64_t key,
                               uint32_t variant = 0,
                               const uint16_t* slot_perm = nullptr) {
  if (key == 0 || code == nullptr) return;
  const OpcodeMap& m = opcode_map();
  CodecKey ck;
  codec_init(ck, codec_stream_key(key, variant));
  uint32_t rnd = codec_rnd_seed(codec_stream_key(key, variant));

  uint16_t inv[kSlotCount];
  if (slot_perm != nullptr) {
    for (uint32_t i = 0; i < kSlotCount; ++i) {
      inv[slot_perm[i]] = static_cast<uint16_t>(i);
    }
  }

  size_t vip = 0;
  while (vip + kHeaderBytes <= size) {

    const uint64_t z = crypt_mix(vip, key);

    uint16_t stored = 0;
    uint16_t slot = 0;
    if (kEncrypt) {
      slot = static_cast<uint16_t>(code[vip] |
                                   (static_cast<uint16_t>(code[vip + 1]) << 8));
      if (m.op_of_slot[slot] == BAD_SLOT) break;
      stored = slot_perm != nullptr ? inv[slot] : slot;
      uint8_t h0 = 0;
      uint8_t h1 = 0;
      codec_encode(ck, stored, z, rnd, &h0, &h1);
      code[vip] = h0;
      code[vip + 1] = h1;
    } else {
      stored = codec_decode(ck, code[vip], code[vip + 1], z);
      slot = slot_perm != nullptr ? slot_perm[stored] : stored;
      if (m.op_of_slot[slot] == BAD_SLOT) break;
      code[vip] = static_cast<uint8_t>(slot & 0xFFu);
      code[vip + 1] = static_cast<uint8_t>(slot >> 8);
    }

    const uint16_t op = m.op_of_slot[slot];
    const unsigned opsz = op_size(static_cast<Op>(op));
    if (vip + kHeaderBytes + opsz > size) break;

    const uint64_t zs = z ^ (static_cast<uint64_t>(stored) * 0x27D4EB2Du);
    uint8_t prev = 0;
    for (unsigned i = 0; i < opsz; ++i) {
      const uint8_t k = crypt_ks_byte_v(zs, i, variant);
      uint8_t& b = code[vip + kHeaderBytes + i];
      if (kEncrypt) {
        b = static_cast<uint8_t>(b + k + prev);
        prev = b;
      } else {
        const uint8_t c = b;
        b = static_cast<uint8_t>(c - k - prev);
        prev = c;
      }
    }
    vip += kHeaderBytes + opsz;
  }
}

}

inline void crypt_operands_encrypt(uint8_t* code, size_t size, uint64_t key) {
  detail::crypt_operands_impl<true>(code, size, key, 0);
}

inline void crypt_operands_encrypt_v(uint8_t* code, size_t size, uint64_t key,
                                    uint32_t variant,
                                    const uint16_t* slot_perm = nullptr) {
  detail::crypt_operands_impl<true>(code, size, key, variant, slot_perm);
}

inline void crypt_operands_decrypt_v(uint8_t* code, size_t size, uint64_t key,
                                    uint32_t variant,
                                    const uint16_t* slot_perm = nullptr) {
  detail::crypt_operands_impl<false>(code, size, key, variant, slot_perm);
}

inline void crypt_operands_decrypt(uint8_t* code, size_t size, uint64_t key,
                                   const uint16_t* slot_perm = nullptr) {
  detail::crypt_operands_impl<false>(code, size, key, 0, slot_perm);
}

}
