#include <stdint.h>

#define HYDA_FN(name) \
  __attribute__((noinline, section("hydafn_" #name), aligned(16)))

HYDA_FN(fnv1a)
uint64_t fnv1a(const uint8_t* p, int n) {
  uint64_t h = 1469598103934665603ull;
  for (int i = 0; i < n; ++i) {
    h ^= p[i];
    h *= 1099511628211ull;
  }
  return h;
}

HYDA_FN(mix64)
uint64_t mix64(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdull;
  x ^= x >> 33;
  x *= 0xc4ceb9fe1a85ec53ull;
  return x ^ (x >> 33);
}

HYDA_FN(rotl)
uint64_t rotl(uint64_t v, unsigned n) {
  n &= 63;
  return (v << n) | (v >> ((64 - n) & 63));
}

HYDA_FN(rot_step)
uint32_t rot_step(uint32_t v, unsigned n) {
  n &= 31;
  return (v << n) | (v >> ((32 - n) & 31));
}

HYDA_FN(shld128)
uint64_t shld128(uint64_t hi, uint64_t lo, unsigned n) {
  unsigned __int128 v = ((unsigned __int128)hi << 64) | lo;
  return (uint64_t)(v << n >> 64);
}

HYDA_FN(shrd128)
uint64_t shrd128(uint64_t hi, uint64_t lo, unsigned n) {
  unsigned __int128 v = ((unsigned __int128)hi << 64) | lo;
  return (uint64_t)(v >> n);
}

HYDA_FN(copy_words)
void copy_words(uint64_t* d, const uint64_t* s, int n) {
  for (int i = 0; i < n; ++i) d[i] = s[i];
}

HYDA_FN(fill_bytes)
void fill_bytes(uint8_t* d, uint8_t v, int n) {
  for (int i = 0; i < n; ++i) d[i] = v;
}

HYDA_FN(byte_cmp)
int byte_cmp(const uint8_t* a, const uint8_t* b, int n) {
  for (int i = 0; i < n; ++i) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return 0;
}

HYDA_FN(str_len)
int str_len(const char* s) {
  const char* p = s;
  while (*p) ++p;
  return (int)(p - s);
}

HYDA_FN(word_cmp)
int word_cmp(const uint64_t* a, const uint64_t* b, int n) {
  for (int i = 0; i < n; ++i) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

HYDA_FN(is_pow2)
int is_pow2(uint64_t v) { return v && !(v & (v - 1)); }

HYDA_FN(bit_reverse)
uint64_t bit_reverse(uint64_t v) {
  v = ((v >> 1) & 0x5555555555555555ull) | ((v & 0x5555555555555555ull) << 1);
  v = ((v >> 2) & 0x3333333333333333ull) | ((v & 0x3333333333333333ull) << 2);
  v = ((v >> 4) & 0x0f0f0f0f0f0f0f0full) | ((v & 0x0f0f0f0f0f0f0f0full) << 4);
  return __builtin_bswap64(v);
}

HYDA_FN(popcount_swar)
int popcount_swar(uint64_t v) {
  v = v - ((v >> 1) & 0x5555555555555555ull);
  v = (v & 0x3333333333333333ull) + ((v >> 2) & 0x3333333333333333ull);
  v = (v + (v >> 4)) & 0x0f0f0f0f0f0f0f0full;
  return (int)((v * 0x0101010101010101ull) >> 56);
}

HYDA_FN(mul_hi64)
uint64_t mul_hi64(uint64_t a, uint64_t b) {
  unsigned __int128 p = (unsigned __int128)a * b;
  return (uint64_t)(p >> 64);
}

HYDA_FN(divmod64)
uint64_t divmod64(uint64_t a, uint64_t b) { return (a / b) ^ (a % b); }

HYDA_FN(divmod32)
uint32_t divmod32(uint32_t a, uint32_t b) { return (a / b) ^ (a % b); }

HYDA_FN(atomic_swap)
uint64_t atomic_swap(volatile uint64_t* p, uint64_t v) {
  return __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST);
}

HYDA_FN(atomic_add)
uint64_t atomic_add(volatile uint64_t* p, uint64_t v) {
  return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST);
}

HYDA_FN(atomic_cas)
int atomic_cas(volatile uint64_t* p, uint64_t* expect, uint64_t v) {
  return __atomic_compare_exchange_n(p, expect, v, 0, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST);
}

HYDA_FN(atomic_and)
uint32_t atomic_and(volatile uint32_t* p, uint32_t v) {
  return __atomic_fetch_and(p, v, __ATOMIC_SEQ_CST);
}

HYDA_FN(switch_dispatch)
int switch_dispatch(int op, int a, int b) {
  switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return a ^ b;
    case 4: return a | b;
    case 5: return a & b;
    case 6: return a << b;
    case 7: return a >> b;
    default: return -1;
  }
}

HYDA_FN(fixed_mul)
int64_t fixed_mul(int64_t a, int64_t b) { return (a * b) >> 32; }

HYDA_FN(sat_add)
int32_t sat_add(int32_t a, int32_t b) {
  int64_t s = (int64_t)a + b;
  if (s > 0x7fffffff) return 0x7fffffff;
  if (s < -0x7fffffff - 1) return -0x7fffffff - 1;
  return (int32_t)s;
}

HYDA_FN(sign_extend24)
int32_t sign_extend24(uint32_t v) {
  return (int32_t)(v << 8) >> 8;
}

HYDA_FN(float_poly)
float float_poly(float x) { return ((x * 1.5f + 2.25f) * x - 0.5f) * x; }

HYDA_FN(sqrt_sum)
float sqrt_sum(float a, float b) { return __builtin_sqrtf(a * a + b * b); }

HYDA_FN(double_lerp)
double double_lerp(double a, double b, double t) { return a + (b - a) * t; }

HYDA_FN(int_to_float)
float int_to_float(int v) { return (float)v * 0.5f; }

HYDA_FN(float_to_int)
int float_to_int(float v) { return (int)(v * 2.0f); }

HYDA_FN(crc32_step)
uint32_t crc32_step(uint32_t crc, const uint8_t* p, int n) {
  for (int i = 0; i < n; ++i) {
    crc ^= p[i];
    for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
  }
  return crc;
}

HYDA_FN(unaligned_load)
uint32_t unaligned_load(const uint8_t* p) {
  uint32_t v;
  __builtin_memcpy(&v, p, 4);
  return v;
}

HYDA_FN(byte_swap16)
uint16_t byte_swap16(uint16_t v) { return __builtin_bswap16(v); }

HYDA_FN(bt_scan)
int bt_scan(uint64_t v, unsigned bit) { return (v >> bit) & 1; }

HYDA_FN(abs_diff)
uint32_t abs_diff(int32_t a, int32_t b) {
  return (uint32_t)(a > b ? a - b : b - a);
}

HYDA_FN(imul_const)
int32_t imul_const(int32_t v) { return v * 1000 + 7; }

HYDA_FN(lea_scale)
int64_t lea_scale(int64_t a, int64_t b, int64_t c) {
  return a + b * 8 + c * 16;
}

HYDA_FN(min_max)
int32_t min_max(int32_t a, int32_t b) {
  return (a < b ? a : b) ^ (a > b ? a : b);
}