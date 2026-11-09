#pragma once

#include "hyda/core/config.hpp"

#include <cstdint>
#include <cstring>

namespace hyda {

struct VMContext {
  uint64_t r[kRegSlots];
  uint32_t status;
  uint32_t reserved;
  uint64_t steps;
  uint64_t max_steps;

  uint64_t image_base;

  uint64_t stack_base;
  uint64_t stack_limit;

  uint8_t save_flags = 1;
};

inline void vm_set_stack(VMContext& c, uint64_t base, uint64_t limit) {
  c.stack_base = base;
  c.stack_limit = limit;
}

inline bool vm_stack_push_ok(const VMContext& c, uint64_t new_rsp) {
  if (c.stack_base == 0) return true;
  return new_rsp >= c.stack_base && new_rsp + 8 <= c.stack_limit;
}

inline bool vm_stack_pop_ok(const VMContext& c, uint64_t rsp) {
  if (c.stack_base == 0) return true;
  return rsp >= c.stack_base && rsp + 8 <= c.stack_limit;
}

inline void vm_init(VMContext& c, uint64_t guest_rsp) {
  std::memset(c.r, 0, sizeof(c.r));
  c.r[vsl(REG_RSP)] = guest_rsp;
  c.r[REG_RFLAGS] = 0x202;
  c.status = ST_OK;
  c.steps = 0;
  c.max_steps = 0;
  c.image_base = 0;
  c.stack_base = 0;
  c.stack_limit = 0;
  c.save_flags = 1;
}

inline bool flag(const VMContext& c, unsigned bit) {
  return ((c.r[REG_RFLAGS] >> bit) & 1u) != 0;
}

inline void set_flag(VMContext& c, unsigned bit, bool v) {
  if (!c.save_flags) return;
  const uint64_t m = 1ull << bit;
  if (v) c.r[REG_RFLAGS] |= m;
  else   c.r[REG_RFLAGS] &= ~m;
}

constexpr uint64_t mask_bits(unsigned bits) {
  return bits >= 64 ? ~0ull : ((1ull << bits) - 1ull);
}

constexpr uint64_t sign_bit(unsigned bits) { return 1ull << (bits - 1); }

constexpr bool parity_even(uint64_t v) {
  v &= 0xFF;
  v ^= v >> 4;
  v &= 0xF;
  return ((0x9669u >> v) & 1u) != 0;
}

inline void set_szp(VMContext& c, uint64_t res, unsigned bits) {
  res &= mask_bits(bits);
  set_flag(c, F_ZF, res == 0);
  set_flag(c, F_SF, (res & sign_bit(bits)) != 0);
  set_flag(c, F_PF, parity_even(res));
}

// 32/64-bit writes clear the upper bits; 8/16-bit writes preserve them.
inline void store_sized(VMContext& c, int dst, uint64_t res, unsigned bits) {
  if (bits >= 32) {
    c.r[dst] = res & mask_bits(bits);
  } else {
    const uint64_t m = mask_bits(bits);
    c.r[dst] = (c.r[dst] & ~m) | (res & m);
  }
}

inline void vm_push(VMContext& c, uint64_t v) {
  const uint64_t nr = c.r[vsl(REG_RSP)] - 8;

  if (!vm_stack_push_ok(c, nr)) {
    c.status = ST_FAULT;
    return;
  }
  c.r[vsl(REG_RSP)] = nr;
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(nr)), &v, 8);
}

inline uint64_t vm_pop(VMContext& c) {
  const uint64_t rsp = c.r[vsl(REG_RSP)];
  if (!vm_stack_pop_ok(c, rsp)) {
    c.status = ST_FAULT;
    return 0;
  }
  uint64_t v = 0;
  std::memcpy(&v, reinterpret_cast<const void*>(static_cast<uintptr_t>(rsp)), 8);
  c.r[vsl(REG_RSP)] = rsp + 8;
  return v;
}

}
