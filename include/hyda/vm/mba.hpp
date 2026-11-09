#pragma once

#include <cstdint>

#include "hyda/core/context.hpp"

namespace hyda {

inline uint64_t hid(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(x));
#endif
  return x;
}

inline uint64_t mba_add(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x ^ y) + 2u * (x & y);
}

inline uint64_t mba_sub(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  const uint64_t ny = ~y;
  return (x ^ ny) + 2u * (x & ny) + 1u;
}

inline uint64_t mba_and(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x + y) - (x | y);
}

inline uint64_t mba_or(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x & ~y) + y;
}

inline uint64_t mba_xor(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x | y) - (x & y);
}

inline uint64_t mba_add_v2(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x | y) + (x & y);
}

inline uint64_t mba_sub_v2(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return x + (~y) + 1u;
}

inline uint64_t mba_and_v2(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return ~((~x) | (~y));
}

inline uint64_t mba_or_v2(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return ~((~x) & (~y));
}

inline uint64_t mba_xor_v2(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x | y) & ~(x & y);
}

inline uint64_t mba_add_v3(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return x - (~y) - 1u;
}

inline uint64_t mba_sub_v3(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return ~((~x) + y);
}

inline uint64_t mba_and_v3(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x ^ y) ^ (x | y);
}

inline uint64_t mba_or_v3(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return (x ^ y) | (x & y);
}

inline uint64_t mba_xor_v3(uint64_t a, uint64_t b) {
  const uint64_t x = hid(a);
  const uint64_t y = hid(b);
  return ~(x & y) & (x | y);
}

inline uint64_t mba_opaque(const VMContext& c, uint64_t mba_val,
                           uint64_t plain_val) {
  return (c.status == 0u) ? mba_val : plain_val;
}

}
