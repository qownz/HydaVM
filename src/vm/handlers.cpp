#include "hyda/vm/handlers.hpp"
#include "hyda/vm/mba.hpp"
#include "hyda/vm/vm2.hpp"

#include "hyda/vm/dispatch.hpp"
#include "hyda/vm/dispatch_ring.hpp"
#include "hyda/vm/gate.hpp"
#include "hyda/vm/fpstate.hpp"
#include "hyda/vm/sse.hpp"

#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define HF(f) (::hyda::HandlerFn)(f)

namespace hyda {

bool cond_true(const VMContext& c, unsigned cc) {
  const bool cf = flag(c, F_CF);
  const bool pf = flag(c, F_PF);
  const bool zf = flag(c, F_ZF);
  const bool sf = flag(c, F_SF);
  const bool of = flag(c, F_OF);

  switch (cc & 15u) {
    case 0x0: return of;
    case 0x1: return !of;
    case 0x2: return cf;
    case 0x3: return !cf;
    case 0x4: return zf;
    case 0x5: return !zf;
    case 0x6: return cf || zf;
    case 0x7: return !cf && !zf;
    case 0x8: return sf;
    case 0x9: return !sf;
    case 0xA: return pf;
    case 0xB: return !pf;
    case 0xC: return sf != of;
    case 0xD: return sf == of;
    case 0xE: return zf || (sf != of);
    default:  return !zf && (sf == of);
  }
}

uint64_t mem_addr(const VMContext& c, int base, int index, int scale, int32_t disp) {
  uint64_t a = static_cast<uint64_t>(static_cast<int64_t>(disp));
  if (base != static_cast<int>(NO_MEM)) a += c.r[base];
  if (index != static_cast<int>(NO_MEM)) a += c.r[index] * static_cast<uint64_t>(scale);
  return a;
}

namespace {

inline uint64_t rd_u64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }
inline uint32_t rd_u32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
inline int64_t  rd_i64(const uint8_t* p) { return static_cast<int64_t>(rd_u64(p)); }
inline int32_t  rd_i32(const uint8_t* p) { return static_cast<int32_t>(rd_u32(p)); }
inline int8_t   rd_i8 (const uint8_t* p) { return static_cast<int8_t>(p[0]); }

inline uint64_t ld64(uint64_t a) {
  uint64_t v; std::memcpy(&v, reinterpret_cast<const void*>(static_cast<uintptr_t>(a)), 8); return v;
}
inline void st64(uint64_t a, uint64_t v) {
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(a)), &v, 8);
}

inline uint64_t f_add(VMContext& c, uint64_t a, uint64_t b, unsigned bits,
                      uint64_t carry_in, bool write_cf) {
  const uint64_t m  = mask_bits(bits);
  const uint64_t sb = sign_bit(bits);
  const uint64_t am = a & m;
  const uint64_t bm = b & m;

  const unsigned __int128 s = static_cast<unsigned __int128>(am) + bm + carry_in;
  const uint64_t res = static_cast<uint64_t>(s) & m;

  if (write_cf) set_flag(c, F_CF, (s >> bits) != 0);
  set_flag(c, F_OF, (((~(am ^ bm)) & (am ^ res)) & sb) != 0);
  set_flag(c, F_AF, ((am ^ bm ^ res) & 0x10u) != 0);
  set_szp(c, res, bits);
  return res;
}

inline uint64_t f_sub(VMContext& c, uint64_t a, uint64_t b, unsigned bits,
                      uint64_t borrow_in, bool write_cf) {
  const uint64_t m  = mask_bits(bits);
  const uint64_t sb = sign_bit(bits);
  const uint64_t am = a & m;
  const uint64_t bm = b & m;

  const unsigned __int128 sub = static_cast<unsigned __int128>(bm) + borrow_in;
  const uint64_t res = static_cast<uint64_t>(static_cast<unsigned __int128>(am) - sub) & m;

  if (write_cf) set_flag(c, F_CF, static_cast<unsigned __int128>(am) < sub);
  set_flag(c, F_OF, (((am ^ bm) & (am ^ res)) & sb) != 0);
  set_flag(c, F_AF, ((am ^ bm ^ res) & 0x10u) != 0);
  set_szp(c, res, bits);
  return res;
}

inline uint64_t f_logic(VMContext& c, uint64_t a, uint64_t b, unsigned bits, int op) {
  const uint64_t m = mask_bits(bits);
  uint64_t res = (op == 0) ? (a & b) : (op == 1) ? (a | b) : (a ^ b);
  res &= m;
  set_flag(c, F_CF, false);
  set_flag(c, F_OF, false);
  set_szp(c, res, bits);
  return res;
}

inline uint64_t cf_in(const VMContext& c) { return flag(c, F_CF) ? 1ull : 0ull; }

void h_nop(VMContext&, const uint8_t*) {}

void h_halt(VMContext& c, const uint8_t*) { c.status = ST_HALT; }

void h_bad_slot(VMContext& c, const uint8_t*) { c.status = ST_BAD_OPCODE; }

void h_vm_junk(VMContext&, const uint8_t*) {}

void h_vm_noise(VMContext& c, const uint8_t* o) {
  c.r[o[0]] ^= rd_u64(o + 1) ^ 0x9E3779B97F4A7C15ull;
}

void h_inv_r(VMContext& c, const uint8_t* o) { c.r[o[0]] = ~c.r[o[0]]; }

void h_push_imm(VMContext& c, const uint8_t* o) { vm_push(c, rd_u64(o)); }
void h_push_r (VMContext& c, const uint8_t* o) { vm_push(c, c.r[o[0]]); }
void h_pop_r  (VMContext& c, const uint8_t* o) { c.r[o[0]] = vm_pop(c); }
void h_pushf  (VMContext& c, const uint8_t*)   { vm_push(c, c.r[REG_RFLAGS]); }
void h_popf   (VMContext& c, const uint8_t*)   { c.r[REG_RFLAGS] = (vm_pop(c) & 0x0CD5ull) | 0x2ull; }

void h_clc(VMContext& c, const uint8_t*) { set_flag(c, F_CF, false); }
void h_stc(VMContext& c, const uint8_t*) { set_flag(c, F_CF, true); }
void h_cmc(VMContext& c, const uint8_t*) { set_flag(c, F_CF, !flag(c, F_CF)); }

void h_mov_rr(VMContext& c, const uint8_t* o) { c.r[o[0]] = c.r[o[1]]; }
void h_mov_ri(VMContext& c, const uint8_t* o) { c.r[o[0]] = rd_u64(o + 1); }

void h_mov_ri_base(VMContext& c, const uint8_t* o) {
  c.r[o[0]] = c.image_base + rd_u64(o + 1);
}

template <unsigned BITS>
void mov_rr_sized(VMContext& c, const uint8_t* o) {
  store_sized(c, o[0], c.r[o[1]], BITS);
}
template <unsigned BITS>
void mov_ri_sized(VMContext& c, const uint8_t* o) {
  store_sized(c, o[0], rd_u64(o + 1), BITS);
}

void h_mov_rr8 (VMContext& c, const uint8_t* o) { mov_rr_sized<8>(c, o); }
void h_mov_rr16(VMContext& c, const uint8_t* o) { mov_rr_sized<16>(c, o); }
void h_mov_rr32(VMContext& c, const uint8_t* o) { mov_rr_sized<32>(c, o); }
void h_mov_ri8 (VMContext& c, const uint8_t* o) { mov_ri_sized<8>(c, o); }
void h_mov_ri16(VMContext& c, const uint8_t* o) { mov_ri_sized<16>(c, o); }
void h_mov_ri32(VMContext& c, const uint8_t* o) { mov_ri_sized<32>(c, o); }

void h_mov_rm(VMContext& c, const uint8_t* o) {
  c.r[o[0]] = ld64(mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4)));
}
void h_mov_mr(VMContext& c, const uint8_t* o) {
  st64(mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4)), c.r[o[0]]);
}

template <unsigned BYTES>
void load_impl(VMContext& c, const uint8_t* o) {
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  uint64_t v = 0;
  std::memcpy(&v, reinterpret_cast<const void*>(static_cast<uintptr_t>(a)), BYTES);
  c.r[o[0]] = v;
}

template <unsigned BYTES>
void store_impl(VMContext& c, const uint8_t* o) {
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  const uint64_t v = c.r[o[0]];
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(a)), &v, BYTES);
}

void h_load8  (VMContext& c, const uint8_t* o) { load_impl<1>(c, o); }
void h_load16 (VMContext& c, const uint8_t* o) { load_impl<2>(c, o); }
void h_load32 (VMContext& c, const uint8_t* o) { load_impl<4>(c, o); }
void h_store8 (VMContext& c, const uint8_t* o) { store_impl<1>(c, o); }
void h_store16(VMContext& c, const uint8_t* o) { store_impl<2>(c, o); }
void h_store32(VMContext& c, const uint8_t* o) { store_impl<4>(c, o); }

void h_movzx8 (VMContext& c, const uint8_t* o) { c.r[o[0]] = c.r[o[1]] & 0xFFull; }
void h_movzx16(VMContext& c, const uint8_t* o) { c.r[o[0]] = c.r[o[1]] & 0xFFFFull; }
void h_movsx8 (VMContext& c, const uint8_t* o) { c.r[o[0]] = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(c.r[o[1]]))); }
void h_movsx16(VMContext& c, const uint8_t* o) { c.r[o[0]] = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(c.r[o[1]]))); }
void h_movsxd(VMContext& c, const uint8_t* o) { c.r[o[0]] = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(c.r[o[1]]))); }

void h_lea(VMContext& c, const uint8_t* o) {
  c.r[o[0]] = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
}

void h_xchg(VMContext& c, const uint8_t* o) {
  const uint64_t t = c.r[o[0]];
  c.r[o[0]] = c.r[o[1]];
  c.r[o[1]] = t;
}

template <unsigned BITS>
void cmov_impl(VMContext& c, const uint8_t* o) {
  const uint64_t v = cond_true(c, static_cast<unsigned>(o[2])) ? c.r[o[1]] : c.r[o[0]];
  store_sized(c, o[0], v, BITS);
}

void h_cmov8 (VMContext& c, const uint8_t* o) { cmov_impl<8>(c, o); }
void h_cmov16(VMContext& c, const uint8_t* o) { cmov_impl<16>(c, o); }
void h_cmov32(VMContext& c, const uint8_t* o) { cmov_impl<32>(c, o); }
void h_cmov  (VMContext& c, const uint8_t* o) { cmov_impl<64>(c, o); }

void h_bswap(VMContext& c, const uint8_t* o) { c.r[o[0]] = __builtin_bswap64(c.r[o[0]]); }

void h_cdq(VMContext& c, const uint8_t*) {

  c.r[vsl(REG_RDX)] = (c.r[vsl(REG_RAX)] & 0x80000000ull) ? 0xFFFFFFFFull : 0ull;
}
void h_cqo(VMContext& c, const uint8_t*) {
  c.r[vsl(REG_RDX)] = (c.r[vsl(REG_RAX)] & 0x8000000000000000ull) ? ~0ull : 0ull;
}

template <unsigned BITS>
void h_alu_add(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  store_sized(c, d, f_add(c, c.r[d], c.r[o[1]], BITS, 0, true), BITS);
}
template <unsigned BITS>
void h_alu_adc(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t ci = cf_in(c);
  store_sized(c, d, f_add(c, c.r[d], c.r[o[1]], BITS, ci, true), BITS);
}
template <unsigned BITS>
void h_alu_sub(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  store_sized(c, d, f_sub(c, c.r[d], c.r[o[1]], BITS, 0, true), BITS);
}
template <unsigned BITS>
void h_alu_sbb(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t bi = cf_in(c);
  store_sized(c, d, f_sub(c, c.r[d], c.r[o[1]], BITS, bi, true), BITS);
}

template <unsigned BITS, int OP>
void logic_impl(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  store_sized(c, d, f_logic(c, c.r[d], c.r[o[1]], BITS, OP), BITS);
}
template <unsigned BITS> void h_alu_and(VMContext& c, const uint8_t* o) { logic_impl<BITS, 0>(c, o); }
template <unsigned BITS> void h_alu_or (VMContext& c, const uint8_t* o) { logic_impl<BITS, 1>(c, o); }
template <unsigned BITS> void h_alu_xor(VMContext& c, const uint8_t* o) { logic_impl<BITS, 2>(c, o); }

template <unsigned BITS>
void h_alu_cmp(VMContext& c, const uint8_t* o) {
  f_sub(c, c.r[o[0]], c.r[o[1]], BITS, 0, true);
}

void h_cmp_jcc(VMContext& c, const uint8_t* o) {
  const uint64_t a = c.r[o[0]];
  const uint64_t b = c.r[o[1]];
  const bool is_test = (o[2] != 0);
  switch (o[4]) {
    case 0: is_test ? (void)f_logic(c, a, b, 8, 0) : (void)f_sub(c, a, b, 8, 0, true); break;
    case 1: is_test ? (void)f_logic(c, a, b, 16, 0) : (void)f_sub(c, a, b, 16, 0, true); break;
    case 2: is_test ? (void)f_logic(c, a, b, 32, 0) : (void)f_sub(c, a, b, 32, 0, true); break;
    default: is_test ? (void)f_logic(c, a, b, 64, 0) : (void)f_sub(c, a, b, 64, 0, true); break;
  }
  if (cond_true(c, o[3]))
    c.r[REG_RIP] += static_cast<uint64_t>(static_cast<int64_t>(rd_i32(o + 5)));
}

void h_alu_jcc(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[d];
  const uint64_t b = c.r[o[1]];
  unsigned bits = 64;
  switch (o[4]) {
    case 0: bits = 8; break;
    case 1: bits = 16; break;
    case 2: bits = 32; break;
    default: bits = 64; break;
  }
  uint64_t v = a;
  switch (o[2]) {
    case 0: v = f_add(c, a, b, bits, 0, true); break;
    case 2: v = f_sub(c, a, b, bits, 0, true); break;
    case 4: v = f_logic(c, a, b, bits, 0); break;
    case 5: v = f_logic(c, a, b, bits, 1); break;
    case 6: v = f_logic(c, a, b, bits, 2); break;
    default: break;
  }
  store_sized(c, d, v, bits);
  if (cond_true(c, o[3])) {
    c.r[REG_RIP] += static_cast<uint64_t>(static_cast<int64_t>(rd_i32(o + 5)));
  }
}

template <unsigned BITS>
void h_alu_add_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_add(c, a, b, BITS, 0, true);
  store_sized(c, d, mba_opaque(c, mba_add(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_sub_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[0]], b = c.r[o[1]];
  const uint64_t v = f_sub(c, a, b, BITS, 0, true);
  store_sized(c, d, mba_opaque(c, mba_sub(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_and_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 0);
  store_sized(c, d, mba_opaque(c, mba_and(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_or_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 1);
  store_sized(c, d, mba_opaque(c, mba_or(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_xor_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 2);
  store_sized(c, d, mba_opaque(c, mba_xor(a, b), v), BITS);
}
void h_inc_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t x = c.r[d];
  const uint64_t v = f_add(c, 1, x, 64, 0, false);
  store_sized(c, d, mba_opaque(c, mba_add(1, x), v), 64);
}
template <unsigned BITS>
void h_dec_b(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t x = c.r[d];
  const uint64_t v = f_sub(c, x, 1, BITS, 0, false);
  store_sized(c, d, mba_opaque(c, mba_sub(x, 1), v), BITS);
}

template <unsigned BITS>
void h_alu_add_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_add(c, a, b, BITS, 0, true);
  store_sized(c, d, mba_opaque(c, mba_add_v2(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_sub_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[0]], b = c.r[o[1]];
  const uint64_t v = f_sub(c, a, b, BITS, 0, true);
  store_sized(c, d, mba_opaque(c, mba_sub_v2(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_and_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 0);
  store_sized(c, d, mba_opaque(c, mba_and_v2(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_or_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 1);
  store_sized(c, d, mba_opaque(c, mba_or_v2(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_xor_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 2);
  store_sized(c, d, mba_opaque(c, mba_xor_v2(a, b), v), BITS);
}
void h_inc_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t x = c.r[d];
  const uint64_t v = f_add(c, 1, x, 64, 0, false);
  store_sized(c, d, mba_opaque(c, mba_add_v2(1, x), v), 64);
}
template <unsigned BITS>
void h_dec_b2(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t x = c.r[d];
  const uint64_t v = f_sub(c, x, 1, BITS, 0, false);
  store_sized(c, d, mba_opaque(c, mba_sub_v2(x, 1), v), BITS);
}

template <unsigned BITS>
void h_alu_add_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_add(c, a, b, BITS, 0, true);
  store_sized(c, d, mba_opaque(c, mba_add_v3(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_sub_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[0]], b = c.r[o[1]];
  const uint64_t v = f_sub(c, a, b, BITS, 0, true);
  store_sized(c, d, mba_opaque(c, mba_sub_v3(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_and_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 0);
  store_sized(c, d, mba_opaque(c, mba_and_v3(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_or_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 1);
  store_sized(c, d, mba_opaque(c, mba_or_v3(a, b), v), BITS);
}
template <unsigned BITS>
void h_alu_xor_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[1]], b = c.r[o[0]];
  const uint64_t v = f_logic(c, a, b, BITS, 2);
  store_sized(c, d, mba_opaque(c, mba_xor_v3(a, b), v), BITS);
}
void h_inc_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t x = c.r[d];
  const uint64_t v = f_add(c, 1, x, 64, 0, false);
  const uint64_t mba = ~((~x) - 1u);
  store_sized(c, d, mba_opaque(c, mba, v), 64);
}
template <unsigned BITS>
void h_dec_b3(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t x = c.r[d];
  const uint64_t v = f_sub(c, x, 1, BITS, 0, false);
  const uint64_t mba = ~((~x) + 1u);
  store_sized(c, d, mba_opaque(c, mba, v), BITS);
}

template <unsigned BITS>
void h_alu_add_n(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[0]], b = c.r[o[1]];
  const uint64_t direct = f_add(c, a, b, BITS, 0, true);
  uint64_t v = 0;
  if (vm2_eval(kV2ProgAdd, a, b, &v) != V2_OK ||
      (v & mask_bits(BITS)) != direct) {
    c.status = ST_FAULT;
    return;
  }
  store_sized(c, d, v, BITS);
}
template <unsigned BITS>
void h_alu_sub_n(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[0]], b = c.r[o[1]];
  const uint64_t direct = f_sub(c, a, b, BITS, 0, true);
  uint64_t v = 0;
  if (vm2_eval(kV2ProgSub, a, b, &v) != V2_OK ||
      (v & mask_bits(BITS)) != direct) {
    c.status = ST_FAULT;
    return;
  }
  store_sized(c, d, v, BITS);
}
template <unsigned BITS>
void h_alu_xor_n(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t a = c.r[o[0]], b = c.r[o[1]];
  const uint64_t direct = f_logic(c, a, b, BITS, 2);
  uint64_t v = 0;
  if (vm2_eval(kV2ProgXor, a, b, &v) != V2_OK ||
      (v & mask_bits(BITS)) != direct) {
    c.status = ST_FAULT;
    return;
  }
  store_sized(c, d, v, BITS);
}

template <unsigned BITS, int OP>
void unary_impl(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  if (OP == 0) {
    store_sized(c, d, f_add(c, c.r[d], 1, BITS, 0, false), BITS);
  } else if (OP == 1) {
    store_sized(c, d, f_sub(c, c.r[d], 1, BITS, 0, false), BITS);
  } else if (OP == 2) {
    store_sized(c, d, ~c.r[d], BITS);
  } else {
    store_sized(c, d, f_sub(c, 0, c.r[d], BITS, 0, true), BITS);
  }
}

void h_inc8 (VMContext& c, const uint8_t* o) { unary_impl<8, 0>(c, o); }
void h_inc16(VMContext& c, const uint8_t* o) { unary_impl<16, 0>(c, o); }
void h_inc32(VMContext& c, const uint8_t* o) { unary_impl<32, 0>(c, o); }
void h_inc  (VMContext& c, const uint8_t* o) { unary_impl<64, 0>(c, o); }
void h_dec8 (VMContext& c, const uint8_t* o) { unary_impl<8, 1>(c, o); }
void h_dec16(VMContext& c, const uint8_t* o) { unary_impl<16, 1>(c, o); }
void h_dec32(VMContext& c, const uint8_t* o) { unary_impl<32, 1>(c, o); }
void h_dec  (VMContext& c, const uint8_t* o) { unary_impl<64, 1>(c, o); }
void h_not8 (VMContext& c, const uint8_t* o) { unary_impl<8, 2>(c, o); }
void h_not16(VMContext& c, const uint8_t* o) { unary_impl<16, 2>(c, o); }
void h_not32(VMContext& c, const uint8_t* o) { unary_impl<32, 2>(c, o); }
void h_not  (VMContext& c, const uint8_t* o) { unary_impl<64, 2>(c, o); }
void h_neg8 (VMContext& c, const uint8_t* o) { unary_impl<8, 3>(c, o); }
void h_neg16(VMContext& c, const uint8_t* o) { unary_impl<16, 3>(c, o); }
void h_neg32(VMContext& c, const uint8_t* o) { unary_impl<32, 3>(c, o); }
void h_neg  (VMContext& c, const uint8_t* o) { unary_impl<64, 3>(c, o); }

template <unsigned BITS, int OP>
void shift_core(VMContext& c, int d, unsigned raw_cnt) {

  const unsigned cnt = raw_cnt & (BITS == 64 ? 63u : 31u);
  const uint64_t m  = mask_bits(BITS);
  const uint64_t sb = sign_bit(BITS);
  const uint64_t v  = c.r[d] & m;

  if (cnt == 0) {

    store_sized(c, d, v, BITS);
    return;
  }

  uint64_t res = v;
  bool cf = false;
  bool of = false;

  if (OP == 3 || OP == 4) {
    const unsigned k = cnt % BITS;
    if (k) {
      res = (OP == 3) ? (((v << k) | (v >> (BITS - k))) & m)
                      : (((v >> k) | (v << (BITS - k))) & m);
    }
    if (OP == 3) {

      cf = (res & 1ull) != 0;
      of = ((res & sb) != 0) != cf;
    } else {

      cf = (res & sb) != 0;
      const uint64_t second = (BITS >= 2) ? ((res >> (BITS - 2)) & 1ull) : 0ull;
      of = ((res & sb) != 0) != (second != 0);
    }
  } else if (cnt >= BITS) {
    if (OP == 0)      { res = 0; cf = false; }
    else if (OP == 1) { res = 0; cf = false; }
    else {
      res = (v & sb) ? m : 0;
      cf = (v & sb) != 0;
    }
    of = false;
  } else {
    switch (OP) {
      case 0: {
        res = (v << cnt) & m;
        cf = ((v >> (BITS - cnt)) & 1ull) != 0;
        of = ((res & sb) != 0) != cf;
        break;
      }
      case 1: {
        res = (v >> cnt) & m;
        cf = ((v >> (cnt - 1)) & 1ull) != 0;
        if (cnt == 1) of = ((v & sb) != 0);
        break;
      }
      case 2: {
        const int64_t sv =
            static_cast<int64_t>(v | ((v & sb) ? ~m : 0ull));
        res = static_cast<uint64_t>(sv >> cnt) & m;
        cf = ((v >> (cnt - 1)) & 1ull) != 0;
        if (cnt == 1) of = false;
        break;
      }
      default: break;
    }
  }

  store_sized(c, d, res, BITS);
  set_flag(c, F_CF, cf);
  set_flag(c, F_OF, of);

  if (OP != 3 && OP != 4) set_szp(c, res, BITS);
}

#define HYDA_SHIFT4(SFX, OP)                                                       \
  void h_##SFX##8 (VMContext& c, const uint8_t* o) { shift_impl<8,  OP>(c, o); }    \
  void h_##SFX##16(VMContext& c, const uint8_t* o) { shift_impl<16, OP>(c, o); }    \
  void h_##SFX##32(VMContext& c, const uint8_t* o) { shift_impl<32, OP>(c, o); }    \
  void h_##SFX    (VMContext& c, const uint8_t* o) { shift_impl<64, OP>(c, o); }

template <unsigned BITS, int OP>
void shift_impl(VMContext& c, const uint8_t* o) {
  shift_core<BITS, OP>(c, o[0], static_cast<uint8_t>(o[1]));
}

template <unsigned BITS, int OP>
void shiftv_impl(VMContext& c, const uint8_t* o) {
  shift_core<BITS, OP>(c, o[0], static_cast<uint8_t>(c.r[o[1]] & 0xFFu));
}

HYDA_SHIFT4(shl, 0)
HYDA_SHIFT4(shr, 1)
HYDA_SHIFT4(sar, 2)
HYDA_SHIFT4(rol, 3)
HYDA_SHIFT4(ror, 4)

#undef HYDA_SHIFT4

template <unsigned BITS> void shl_v_impl(VMContext& c, const uint8_t* o) { shiftv_impl<BITS, 0>(c, o); }
template <unsigned BITS> void shr_v_impl(VMContext& c, const uint8_t* o) { shiftv_impl<BITS, 1>(c, o); }
template <unsigned BITS> void sar_v_impl(VMContext& c, const uint8_t* o) { shiftv_impl<BITS, 2>(c, o); }
template <unsigned BITS> void rol_v_impl(VMContext& c, const uint8_t* o) { shiftv_impl<BITS, 3>(c, o); }
template <unsigned BITS> void ror_v_impl(VMContext& c, const uint8_t* o) { shiftv_impl<BITS, 4>(c, o); }

struct nf_guard {
  VMContext& c;
  uint8_t saved;
  explicit nf_guard(VMContext& ctx)
      : c(ctx), saved(ctx.save_flags) { c.save_flags = 0; }
  ~nf_guard() { c.save_flags = saved; }
  nf_guard(const nf_guard&) = delete;
  nf_guard& operator=(const nf_guard&) = delete;
};

#define HYDA_NF_ALU4_WRAP(NM, F)                                     \
  template <unsigned BITS> void NM(VMContext& c, const uint8_t* o) { \
    nf_guard g(c);                                                   \
    F<BITS>(c, o);                                                   \
  }
HYDA_NF_ALU4_WRAP(h_alu_adc_nf, h_alu_adc)
HYDA_NF_ALU4_WRAP(h_alu_add_nf, h_alu_add)
HYDA_NF_ALU4_WRAP(h_alu_sub_nf, h_alu_sub)
HYDA_NF_ALU4_WRAP(h_alu_sbb_nf, h_alu_sbb)
HYDA_NF_ALU4_WRAP(h_alu_and_nf, h_alu_and)
HYDA_NF_ALU4_WRAP(h_alu_or_nf, h_alu_or)
HYDA_NF_ALU4_WRAP(h_alu_xor_nf, h_alu_xor)
#undef HYDA_NF_ALU4_WRAP

#define HYDA_NF_UN_WRAP(NM, OP)                                      \
  template <unsigned BITS> void NM(VMContext& c, const uint8_t* o) { \
    nf_guard g(c);                                                   \
    unary_impl<BITS, OP>(c, o);                                      \
  }
HYDA_NF_UN_WRAP(h_inc_nf, 0)
HYDA_NF_UN_WRAP(h_dec_nf, 1)
HYDA_NF_UN_WRAP(h_neg_nf, 3)
#undef HYDA_NF_UN_WRAP

inline __int128 sign_extend128(uint64_t v, unsigned bits) {
  const unsigned sh = 128u - bits;
  return static_cast<__int128>(static_cast<unsigned __int128>(v) << sh) >> sh;
}

template <unsigned BITS>
void mul_impl(VMContext& c, const uint8_t* o) {
  const uint64_t m = mask_bits(BITS);
  const unsigned __int128 p =
      static_cast<unsigned __int128>(c.r[vsl(REG_RAX)] & m) * (c.r[o[0]] & m);
  const uint64_t lo = static_cast<uint64_t>(p) & m;
  if (BITS == 8) {
    store_sized(c, vsl(REG_RAX), static_cast<uint64_t>(p) & 0xFFFFu, 16);
  } else {
    store_sized(c, vsl(REG_RAX), lo, BITS);
    store_sized(c, vsl(REG_RDX), static_cast<uint64_t>(p >> BITS) & m, BITS);
  }
  const bool ovf = (p >> BITS) != 0;
  set_flag(c, F_CF, ovf);
  set_flag(c, F_OF, ovf);
}

template <unsigned BITS>
void imul1_impl(VMContext& c, const uint8_t* o) {
  const uint64_t m = mask_bits(BITS);
  const __int128 p = sign_extend128(c.r[vsl(REG_RAX)], BITS) * sign_extend128(c.r[o[0]], BITS);
  const uint64_t lo = static_cast<uint64_t>(p) & m;
  if (BITS == 8) {
    store_sized(c, vsl(REG_RAX), static_cast<uint64_t>(p) & 0xFFFFu, 16);
  } else {
    store_sized(c, vsl(REG_RAX), lo, BITS);
    store_sized(c, vsl(REG_RDX),
                static_cast<uint64_t>(static_cast<unsigned __int128>(p) >> BITS) & m, BITS);
  }
  const bool ovf = (p != sign_extend128(lo, BITS));
  set_flag(c, F_CF, ovf);
  set_flag(c, F_OF, ovf);
}

template <unsigned BITS>
void div_impl(VMContext& c, const uint8_t* o) {
  const uint64_t m = mask_bits(BITS);
  const uint64_t d = c.r[o[0]] & m;
  if (d == 0) { c.status = ST_DIV0; return; }
  const unsigned __int128 n =
      (BITS == 8)
          ? (c.r[vsl(REG_RAX)] & 0xFFFFu)
          : ((static_cast<unsigned __int128>(c.r[vsl(REG_RDX)] & m) << BITS) | (c.r[vsl(REG_RAX)] & m));
  const unsigned __int128 q = n / d;
  if (q > m) { c.status = ST_DIV0; return; }
  const uint64_t qq = static_cast<uint64_t>(q) & m;
  const uint64_t rr = static_cast<uint64_t>(n % d) & m;
  if (BITS == 8) {
    store_sized(c, vsl(REG_RAX), (qq & 0xFFu) | (rr << 8), 16);
  } else {
    store_sized(c, vsl(REG_RAX), qq, BITS);
    store_sized(c, vsl(REG_RDX), rr, BITS);
  }
}

template <unsigned BITS>
void idiv_impl(VMContext& c, const uint8_t* o) {
  const uint64_t m = mask_bits(BITS);
  const __int128 dv = sign_extend128(c.r[o[0]] & m, BITS);
  if (dv == 0) { c.status = ST_DIV0; return; }
  __int128 n;
  if (BITS == 8) {
    n = sign_extend128(c.r[vsl(REG_RAX)] & 0xFFFFu, 16);
  } else if (BITS == 64) {
    n = (static_cast<__int128>(static_cast<uint64_t>(c.r[vsl(REG_RDX)])) << 64) |
        static_cast<__int128>(static_cast<uint64_t>(c.r[vsl(REG_RAX)]));
  } else {
    const uint64_t raw = (static_cast<uint64_t>(c.r[vsl(REG_RDX)] & m) << BITS) | (c.r[vsl(REG_RAX)] & m);
    n = sign_extend128(raw, 2u * BITS);
  }
  const __int128 q = n / dv;
  const __int128 qmin = -(static_cast<__int128>(1) << (BITS - 1));
  const __int128 qmax = (static_cast<__int128>(1) << (BITS - 1)) - 1;
  if (q < qmin || q > qmax) { c.status = ST_DIV0; return; }
  const uint64_t qq = static_cast<uint64_t>(q) & m;
  const uint64_t rr = static_cast<uint64_t>(n % dv) & m;
  if (BITS == 8) {
    store_sized(c, vsl(REG_RAX), (qq & 0xFFu) | ((rr & 0xFFu) << 8), 16);
  } else {
    store_sized(c, vsl(REG_RAX), qq, BITS);
    store_sized(c, vsl(REG_RDX), rr, BITS);
  }
}

template <unsigned BITS>
void imul2_impl(VMContext& c, const uint8_t* o) {
  const int d = o[0];
  const uint64_t m = mask_bits(BITS);
  const __int128 p = sign_extend128(c.r[d], BITS) * sign_extend128(c.r[o[1]], BITS);
  const uint64_t lo = static_cast<uint64_t>(p) & m;
  const bool ovf = (p != sign_extend128(lo, BITS));
  store_sized(c, d, lo, BITS);
  set_flag(c, F_CF, ovf);
  set_flag(c, F_OF, ovf);
}

void h_test(VMContext& c, const uint8_t* o) {
  (void)f_logic(c, c.r[o[0]], c.r[o[1]], 64, 0);
}

void h_bsf(VMContext& c, const uint8_t* o) {
  const uint64_t v = c.r[o[1]];
  if (v == 0) { set_flag(c, F_ZF, true); return; }
  set_flag(c, F_ZF, false);
  c.r[o[0]] = static_cast<uint64_t>(__builtin_ctzll(v));
}

void h_bsr(VMContext& c, const uint8_t* o) {
  const uint64_t v = c.r[o[1]];
  if (v == 0) { set_flag(c, F_ZF, true); return; }
  set_flag(c, F_ZF, false);
  c.r[o[0]] = static_cast<uint64_t>(63 - __builtin_clzll(v));
}

void h_tzcnt(VMContext& c, const uint8_t* o) {
  const unsigned bits = static_cast<unsigned>(static_cast<uint8_t>(o[2])) * 8u;
  const uint64_t v = c.r[o[1]] & mask_bits(bits);
  const bool z = (v == 0);
  const uint64_t res = z ? bits : static_cast<uint64_t>(__builtin_ctzll(v));
  store_sized(c, o[0], res, bits);
  set_flag(c, F_CF, z);
  set_flag(c, F_ZF, res == 0);
  set_flag(c, F_OF, false);
  set_flag(c, F_SF, false);
  set_flag(c, F_PF, false);
  set_flag(c, F_AF, false);
}

void h_lzcnt(VMContext& c, const uint8_t* o) {
  const unsigned bits = static_cast<unsigned>(static_cast<uint8_t>(o[2])) * 8u;
  const uint64_t v = c.r[o[1]] & mask_bits(bits);
  const bool z = (v == 0);
  const uint64_t res =
      z ? bits : static_cast<uint64_t>(__builtin_clzll(v) - (64u - bits));
  store_sized(c, o[0], res, bits);
  set_flag(c, F_CF, z);
  set_flag(c, F_ZF, res == 0);
  set_flag(c, F_OF, false);
  set_flag(c, F_SF, false);
  set_flag(c, F_PF, false);
  set_flag(c, F_AF, false);
}

void h_popcnt(VMContext& c, const uint8_t* o) {
  const unsigned bits = static_cast<unsigned>(static_cast<uint8_t>(o[2])) * 8u;
  const uint64_t v = c.r[o[1]] & mask_bits(bits);
  const uint64_t res = static_cast<uint64_t>(__builtin_popcountll(v));
  store_sized(c, o[0], res, bits);
  set_flag(c, F_ZF, res == 0);
  set_flag(c, F_CF, false);
  set_flag(c, F_OF, false);
  set_flag(c, F_SF, false);
  set_flag(c, F_PF, false);
  set_flag(c, F_AF, false);
}

inline unsigned bit_index(uint64_t v) { return static_cast<unsigned>(v & 63ull); }

void h_bt (VMContext& c, const uint8_t* o) {
  const unsigned b = bit_index(c.r[o[1]]);
  set_flag(c, F_CF, ((c.r[o[0]] >> b) & 1ull) != 0);
}
void h_bts(VMContext& c, const uint8_t* o) {
  const unsigned b = bit_index(c.r[o[1]]);
  set_flag(c, F_CF, ((c.r[o[0]] >> b) & 1ull) != 0);
  c.r[o[0]] |= (1ull << b);
}
void h_btr(VMContext& c, const uint8_t* o) {
  const unsigned b = bit_index(c.r[o[1]]);
  set_flag(c, F_CF, ((c.r[o[0]] >> b) & 1ull) != 0);
  c.r[o[0]] &= ~(1ull << b);
}
void h_btc(VMContext& c, const uint8_t* o) {
  const unsigned b = bit_index(c.r[o[1]]);
  set_flag(c, F_CF, ((c.r[o[0]] >> b) & 1ull) != 0);
  c.r[o[0]] ^= (1ull << b);
}

void h_jmp(VMContext& c, const uint8_t* o) {
  c.r[REG_RIP] += static_cast<uint64_t>(static_cast<int64_t>(rd_i32(o)));
}
void h_jmp_r(VMContext& c, const uint8_t* o) { c.r[REG_RIP] = c.r[o[0]]; }

void h_call(VMContext& c, const uint8_t* o) {
  vm_push(c, c.r[REG_RIP]);
  c.r[REG_RIP] += static_cast<uint64_t>(static_cast<int64_t>(rd_i32(o)));
}
void h_ret(VMContext& c, const uint8_t*) { c.r[REG_RIP] = vm_pop(c); }
void h_ret_imm(VMContext& c, const uint8_t* o) {
  c.r[REG_RIP] = vm_pop(c);
  c.r[vsl(REG_RSP)] += static_cast<uint64_t>(static_cast<int64_t>(rd_i32(o)));
}

#define HYDA_JCC(SFX, CC)                                              \
  void h_jcc_##SFX(VMContext& c, const uint8_t* o) {                    \
    if (cond_true(c, (CC)))                                            \
      c.r[REG_RIP] += static_cast<uint64_t>(static_cast<int64_t>(rd_i32(o))); \
  }

HYDA_JCC(o,  0x0) HYDA_JCC(no, 0x1) HYDA_JCC(b,  0x2) HYDA_JCC(ae, 0x3)
HYDA_JCC(z,  0x4) HYDA_JCC(nz, 0x5) HYDA_JCC(be, 0x6) HYDA_JCC(a,  0x7)
HYDA_JCC(s,  0x8) HYDA_JCC(ns, 0x9) HYDA_JCC(p,  0xA) HYDA_JCC(np, 0xB)
HYDA_JCC(l,  0xC) HYDA_JCC(ge, 0xD) HYDA_JCC(le, 0xE) HYDA_JCC(g,  0xF)

#undef HYDA_JCC

void h_native_gate(VMContext& c, const uint8_t* o) {
  const uint32_t rva = rd_u32(o + 1);
  if (rva == 0) return;

  if (vm_gate_depth() + 1 >= hyda::kMaxVmDepth) {
    c.status = ST_FAULT;
    return;
  }

  hyda_vm_gate_enter(
      &c, reinterpret_cast<const void*>(static_cast<uintptr_t>(c.image_base + rva)));
}

namespace sse {

union V128 {
  uint64_t q[2];
  uint32_t d[4];
  uint16_t w[8];
  uint8_t  b[16];
  float    f[4];
  double   df[2];
};

inline uint32_t f32b(float f) { uint32_t u; std::memcpy(&u, &f, 4); return u; }
inline float    b32f(uint32_t u) { float f; std::memcpy(&f, &u, 4); return f; }
inline uint64_t f64b(double d) { uint64_t u; std::memcpy(&u, &d, 8); return u; }
inline double   b64f(uint64_t u) { double d; std::memcpy(&d, &u, 8); return d; }

inline bool reg_ok(VMContext& c, int n) {
  if (n < 0 || n > 15) { c.status = ST_BAD_REG; return false; }
  return true;
}

inline uint64_t* xr(int n) { return fp_state()->xmm(n); }

inline void get(V128& v, int n) {
  const uint64_t* p = fp_state()->xmm(n);
  v.q[0] = p[0];
  v.q[1] = p[1];
}
inline void put(int n, const V128& v) {
  uint64_t* p = fp_state()->xmm(n);
  p[0] = v.q[0];
  p[1] = v.q[1];

  uint64_t* h = fp_state()->ymm_hi(n);
  h[0] = 0;
  h[1] = 0;
}
inline void getm(V128& v, const uint64_t* p) { v.q[0] = p[0]; v.q[1] = p[1]; }

union V256 {
  uint64_t q[4];
  uint32_t d[8];
  uint16_t w[16];
  uint8_t  b[32];
  float    f[8];
  double   df[4];
};

inline void zero_hi(int n) {
  uint64_t* h = fp_state()->ymm_hi(n);
  h[0] = 0;
  h[1] = 0;
}
inline void get256(V256& v, int n) {
  const uint64_t* p = fp_state()->xmm(n);
  const uint64_t* h = fp_state()->ymm_hi(n);
  v.q[0] = p[0];
  v.q[1] = p[1];
  v.q[2] = h[0];
  v.q[3] = h[1];
}
inline void put256(int n, const V256& v) {
  uint64_t* p = fp_state()->xmm(n);
  uint64_t* h = fp_state()->ymm_hi(n);
  p[0] = v.q[0];
  p[1] = v.q[1];
  h[0] = v.q[2];
  h[1] = v.q[3];
}

inline int8_t  sat_i8(int v)  { return static_cast<int8_t>(v < -128 ? -128 : (v > 127 ? 127 : v)); }
inline int16_t sat_i16(int v) { return static_cast<int16_t>(v < -32768 ? -32768 : (v > 32767 ? 32767 : v)); }
inline uint8_t sat_u8(int v)  { return static_cast<uint8_t>(v < 0 ? 0 : (v > 255 ? 255 : v)); }
inline uint16_t sat_u16(int v){ return static_cast<uint16_t>(v < 0 ? 0 : (v > 65535 ? 65535 : v)); }

inline bool bin_apply(V128& a, const V128& b, int op) {
  const V128 o = a;
  switch (static_cast<SseBin>(op)) {

    case SseBin::AddSS: a.d[0] = f32b(a.f[0] + b.f[0]); break;
    case SseBin::SubSS: a.d[0] = f32b(a.f[0] - b.f[0]); break;
    case SseBin::MulSS: a.d[0] = f32b(a.f[0] * b.f[0]); break;
    case SseBin::DivSS: a.d[0] = f32b(a.f[0] / b.f[0]); break;
    case SseBin::MinSS: a.d[0] = f32b((a.f[0] < b.f[0]) ? a.f[0] : b.f[0]); break;
    case SseBin::MaxSS: a.d[0] = f32b((a.f[0] > b.f[0]) ? a.f[0] : b.f[0]); break;

    case SseBin::AddSD: a.q[0] = f64b(a.df[0] + b.df[0]); break;
    case SseBin::SubSD: a.q[0] = f64b(a.df[0] - b.df[0]); break;
    case SseBin::MulSD: a.q[0] = f64b(a.df[0] * b.df[0]); break;
    case SseBin::DivSD: a.q[0] = f64b(a.df[0] / b.df[0]); break;
    case SseBin::MinSD: a.q[0] = f64b((a.df[0] < b.df[0]) ? a.df[0] : b.df[0]); break;
    case SseBin::MaxSD: a.q[0] = f64b((a.df[0] > b.df[0]) ? a.df[0] : b.df[0]); break;

    case SseBin::AddPS: for (int i = 0; i < 4; ++i) a.f[i] = a.f[i] + b.f[i]; break;
    case SseBin::SubPS: for (int i = 0; i < 4; ++i) a.f[i] = a.f[i] - b.f[i]; break;
    case SseBin::MulPS: for (int i = 0; i < 4; ++i) a.f[i] = a.f[i] * b.f[i]; break;
    case SseBin::DivPS: for (int i = 0; i < 4; ++i) a.f[i] = a.f[i] / b.f[i]; break;
    case SseBin::MinPS: for (int i = 0; i < 4; ++i) a.f[i] = (a.f[i] < b.f[i]) ? a.f[i] : b.f[i]; break;
    case SseBin::MaxPS: for (int i = 0; i < 4; ++i) a.f[i] = (a.f[i] > b.f[i]) ? a.f[i] : b.f[i]; break;

    case SseBin::AddPD: for (int i = 0; i < 2; ++i) a.df[i] = a.df[i] + b.df[i]; break;
    case SseBin::SubPD: for (int i = 0; i < 2; ++i) a.df[i] = a.df[i] - b.df[i]; break;
    case SseBin::MulPD: for (int i = 0; i < 2; ++i) a.df[i] = a.df[i] * b.df[i]; break;
    case SseBin::DivPD: for (int i = 0; i < 2; ++i) a.df[i] = a.df[i] / b.df[i]; break;
    case SseBin::MinPD: for (int i = 0; i < 2; ++i) a.df[i] = (a.df[i] < b.df[i]) ? a.df[i] : b.df[i]; break;
    case SseBin::MaxPD: for (int i = 0; i < 2; ++i) a.df[i] = (a.df[i] > b.df[i]) ? a.df[i] : b.df[i]; break;

    case SseBin::AndPS: case SseBin::AndPD: case SseBin::PAnd:
      a.q[0] &= b.q[0]; a.q[1] &= b.q[1]; break;
    case SseBin::AndNPS: case SseBin::AndNPD: case SseBin::PAndN:
      a.q[0] = ~a.q[0] & b.q[0]; a.q[1] = ~a.q[1] & b.q[1]; break;
    case SseBin::OrPS: case SseBin::OrPD: case SseBin::POr:
      a.q[0] |= b.q[0]; a.q[1] |= b.q[1]; break;
    case SseBin::XorPS: case SseBin::XorPD: case SseBin::PXor:
      a.q[0] ^= b.q[0]; a.q[1] ^= b.q[1]; break;

    case SseBin::PAddB: for (int i = 0; i < 16; ++i) a.b[i] = static_cast<uint8_t>(a.b[i] + b.b[i]); break;
    case SseBin::PSubB: for (int i = 0; i < 16; ++i) a.b[i] = static_cast<uint8_t>(a.b[i] - b.b[i]); break;
    case SseBin::PAddW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>(a.w[i] + b.w[i]); break;
    case SseBin::PSubW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>(a.w[i] - b.w[i]); break;
    case SseBin::PAddD: for (int i = 0; i < 4; ++i) a.d[i] = a.d[i] + b.d[i]; break;
    case SseBin::PSubD: for (int i = 0; i < 4; ++i) a.d[i] = a.d[i] - b.d[i]; break;
    case SseBin::PAddQ: for (int i = 0; i < 2; ++i) a.q[i] = a.q[i] + b.q[i]; break;
    case SseBin::PSubQ: for (int i = 0; i < 2; ++i) a.q[i] = a.q[i] - b.q[i]; break;

    case SseBin::PAddSB: for (int i = 0; i < 16; ++i) a.b[i] = static_cast<uint8_t>(sat_i8(int(static_cast<int8_t>(a.b[i])) + int(static_cast<int8_t>(b.b[i])))); break;
    case SseBin::PAddSW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>(sat_i16(int(static_cast<int16_t>(a.w[i])) + int(static_cast<int16_t>(b.w[i])))); break;
    case SseBin::PAddUSB: for (int i = 0; i < 16; ++i) a.b[i] = sat_u8(int(a.b[i]) + int(b.b[i])); break;
    case SseBin::PAddUSW: for (int i = 0; i < 8; ++i) a.w[i] = sat_u16(int(a.w[i]) + int(b.w[i])); break;
    case SseBin::PSubSB: for (int i = 0; i < 16; ++i) a.b[i] = static_cast<uint8_t>(sat_i8(int(static_cast<int8_t>(a.b[i])) - int(static_cast<int8_t>(b.b[i])))); break;
    case SseBin::PSubSW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>(sat_i16(int(static_cast<int16_t>(a.w[i])) - int(static_cast<int16_t>(b.w[i])))); break;
    case SseBin::PSubUSB: for (int i = 0; i < 16; ++i) a.b[i] = sat_u8(int(a.b[i]) - int(b.b[i])); break;
    case SseBin::PSubUSW: for (int i = 0; i < 8; ++i) a.w[i] = sat_u16(int(a.w[i]) - int(b.w[i])); break;

    case SseBin::PMullW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>(a.w[i] * b.w[i]); break;
    case SseBin::PMulHW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>((static_cast<int32_t>(static_cast<int16_t>(a.w[i])) * static_cast<int32_t>(static_cast<int16_t>(b.w[i]))) >> 16); break;
    case SseBin::PMulHUW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>((static_cast<uint32_t>(a.w[i]) * static_cast<uint32_t>(b.w[i])) >> 16); break;
    case SseBin::PMulLD: for (int i = 0; i < 4; ++i) a.d[i] = a.d[i] * b.d[i]; break;
    case SseBin::PMulUDQ: a.q[0] = static_cast<uint64_t>(a.d[0]) * static_cast<uint64_t>(b.d[0]); a.q[1] = static_cast<uint64_t>(a.d[2]) * static_cast<uint64_t>(b.d[2]); break;
    case SseBin::PMaddWD: for (int i = 0; i < 4; ++i) { const int32_t p = int32_t(static_cast<int16_t>(a.w[2*i])) * int32_t(static_cast<int16_t>(b.w[2*i])) + int32_t(static_cast<int16_t>(a.w[2*i+1])) * int32_t(static_cast<int16_t>(b.w[2*i+1])); a.d[i] = static_cast<uint32_t>(p); } break;

    case SseBin::PMinUB: for (int i = 0; i < 16; ++i) a.b[i] = a.b[i] < b.b[i] ? a.b[i] : b.b[i]; break;
    case SseBin::PMinSW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<int16_t>(a.w[i]) < static_cast<int16_t>(b.w[i]) ? a.w[i] : b.w[i]; break;
    case SseBin::PMinUD: for (int i = 0; i < 4; ++i) a.d[i] = a.d[i] < b.d[i] ? a.d[i] : b.d[i]; break;
    case SseBin::PMaxUB: for (int i = 0; i < 16; ++i) a.b[i] = a.b[i] > b.b[i] ? a.b[i] : b.b[i]; break;
    case SseBin::PMaxSW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<int16_t>(a.w[i]) > static_cast<int16_t>(b.w[i]) ? a.w[i] : b.w[i]; break;
    case SseBin::PMaxUD: for (int i = 0; i < 4; ++i) a.d[i] = a.d[i] > b.d[i] ? a.d[i] : b.d[i]; break;

    case SseBin::PCmpeqB: for (int i = 0; i < 16; ++i) a.b[i] = (a.b[i] == b.b[i]) ? 0xFF : 0x00; break;
    case SseBin::PCmpeqW: for (int i = 0; i < 8; ++i) a.w[i] = (a.w[i] == b.w[i]) ? 0xFFFF : 0x0000; break;
    case SseBin::PCmpeqD: for (int i = 0; i < 4; ++i) a.d[i] = (a.d[i] == b.d[i]) ? 0xFFFFFFFFu : 0u; break;
    case SseBin::PCmpgtB: for (int i = 0; i < 16; ++i) a.b[i] = (static_cast<int8_t>(a.b[i]) > static_cast<int8_t>(b.b[i])) ? 0xFF : 0x00; break;
    case SseBin::PCmpgtW: for (int i = 0; i < 8; ++i) a.w[i] = (static_cast<int16_t>(a.w[i]) > static_cast<int16_t>(b.w[i])) ? 0xFFFF : 0x0000; break;
    case SseBin::PCmpgtD: for (int i = 0; i < 4; ++i) a.d[i] = (static_cast<int32_t>(a.d[i]) > static_cast<int32_t>(b.d[i])) ? 0xFFFFFFFFu : 0u; break;

    case SseBin::PunpckLBW: for (int i = 0; i < 8; ++i) { a.b[2*i] = o.b[i]; a.b[2*i+1] = b.b[i]; } break;
    case SseBin::PunpckLWD: for (int i = 0; i < 4; ++i) { a.w[2*i] = o.w[i]; a.w[2*i+1] = b.w[i]; } break;
    case SseBin::PunpckLDQ: for (int i = 0; i < 2; ++i) { a.d[2*i] = o.d[i]; a.d[2*i+1] = b.d[i]; } break;
    case SseBin::PunpckHBW: for (int i = 0; i < 8; ++i) { a.b[2*i] = o.b[i+8]; a.b[2*i+1] = b.b[i+8]; } break;
    case SseBin::PunpckHWD: for (int i = 0; i < 4; ++i) { a.w[2*i] = o.w[i+4]; a.w[2*i+1] = b.w[i+4]; } break;
    case SseBin::PunpckHDQ: for (int i = 0; i < 2; ++i) { a.d[2*i] = o.d[i+2]; a.d[2*i+1] = b.d[i+2]; } break;

    case SseBin::PackssWB: for (int i = 0; i < 8; ++i) { a.b[i] = static_cast<uint8_t>(sat_i8(static_cast<int16_t>(o.w[i]))); a.b[i+8] = static_cast<uint8_t>(sat_i8(static_cast<int16_t>(b.w[i]))); } break;
    case SseBin::PackssDW: for (int i = 0; i < 4; ++i) { a.w[i] = static_cast<uint16_t>(sat_i16(static_cast<int32_t>(o.d[i]))); a.w[i+4] = static_cast<uint16_t>(sat_i16(static_cast<int32_t>(b.d[i]))); } break;
    case SseBin::PackusWB: for (int i = 0; i < 8; ++i) { a.b[i] = sat_u8(static_cast<int16_t>(o.w[i])); a.b[i+8] = sat_u8(static_cast<int16_t>(b.w[i])); } break;

    case SseBin::PabsB: for (int i = 0; i < 16; ++i) { const int8_t v = static_cast<int8_t>(a.b[i]); a.b[i] = static_cast<uint8_t>(v < 0 ? -int(v) : int(v)); } break;
    case SseBin::PabsW: for (int i = 0; i < 8; ++i) { const int16_t v = static_cast<int16_t>(a.w[i]); a.w[i] = static_cast<uint16_t>(v < 0 ? -int(v) : int(v)); } break;
    case SseBin::PabsD: for (int i = 0; i < 4; ++i) { const int32_t v = static_cast<int32_t>(a.d[i]); a.d[i] = static_cast<uint32_t>(v < 0 ? -int64_t(v) : int64_t(v)); } break;
    case SseBin::PavgB: for (int i = 0; i < 16; ++i) a.b[i] = static_cast<uint8_t>((int(a.b[i]) + int(b.b[i]) + 1) >> 1); break;
    case SseBin::PavgW: for (int i = 0; i < 8; ++i) a.w[i] = static_cast<uint16_t>((int(a.w[i]) + int(b.w[i]) + 1) >> 1); break;
    case SseBin::PsignB: for (int i = 0; i < 16; ++i) { const int8_t s = static_cast<int8_t>(b.b[i]); a.b[i] = s < 0 ? static_cast<uint8_t>(-static_cast<int8_t>(a.b[i])) : (s > 0 ? a.b[i] : 0); } break;
    case SseBin::PsignW: for (int i = 0; i < 8; ++i) { const int16_t s = static_cast<int16_t>(b.w[i]); a.w[i] = s < 0 ? static_cast<uint16_t>(-static_cast<int16_t>(a.w[i])) : (s > 0 ? a.w[i] : 0); } break;
    case SseBin::PsignD: for (int i = 0; i < 4; ++i) { const int32_t s = static_cast<int32_t>(b.d[i]); a.d[i] = s < 0 ? static_cast<uint32_t>(-static_cast<int32_t>(a.d[i])) : (s > 0 ? a.d[i] : 0); } break;
    default: return false;
  }
  return true;
}

inline bool bin(int d, const V128& b, int op) {
  V128 a;
  get(a, d);
  if (!bin_apply(a, b, op)) return false;
  put(d, a);
  return true;
}

inline bool bin3(int d, int s1, const V128& b, int op) {
  V128 a;
  get(a, s1);
  if (!bin_apply(a, b, op)) return false;
  put(d, a);
  return true;
}

inline bool avx_bin_apply(V256& a, const V256& b, int op) {
  V128 al, bl, ah, bh;
  al.q[0] = a.q[0]; al.q[1] = a.q[1];
  bl.q[0] = b.q[0]; bl.q[1] = b.q[1];
  ah.q[0] = a.q[2]; ah.q[1] = a.q[3];
  bh.q[0] = b.q[2]; bh.q[1] = b.q[3];
  if (!bin_apply(al, bl, op)) return false;
  if (!bin_apply(ah, bh, op)) return false;
  a.q[0] = al.q[0]; a.q[1] = al.q[1];
  a.q[2] = ah.q[0]; a.q[3] = ah.q[1];
  return true;
}
inline bool bin3_256(int d, int s1, const V256& b, int op) {
  V256 a;
  get256(a, s1);
  if (!avx_bin_apply(a, b, op)) return false;
  put256(d, a);
  return true;
}

inline bool un(int d, int op) {
  V128 a;
  get(a, d);
  switch (static_cast<SseUn>(op)) {
    case SseUn::SqrtSS: a.d[0] = f32b(__builtin_sqrtf(a.f[0])); break;
    case SseUn::SqrtSD: a.q[0] = f64b(__builtin_sqrt(a.df[0])); break;
    case SseUn::SqrtPS: for (int i = 0; i < 4; ++i) a.f[i] = __builtin_sqrtf(a.f[i]); break;
    case SseUn::SqrtPD: for (int i = 0; i < 2; ++i) a.df[i] = __builtin_sqrt(a.df[i]); break;
    default: return false;
  }
  put(d, a);
  return true;
}

inline bool sh(int d, int op, int imm) {
  V128 a;
  get(a, d);
  const unsigned sh = static_cast<unsigned>(imm) & 0xFFu;
  switch (static_cast<SseShift>(op)) {
    case SseShift::PslW: for (int i = 0; i < 8; ++i) a.w[i] = sh >= 16 ? 0 : static_cast<uint16_t>(a.w[i] << sh); break;
    case SseShift::PslD: for (int i = 0; i < 4; ++i) a.d[i] = sh >= 32 ? 0u : (a.d[i] << sh); break;
    case SseShift::PslQ: for (int i = 0; i < 2; ++i) a.q[i] = sh >= 64 ? 0ull : (a.q[i] << sh); break;
    case SseShift::PsrW: for (int i = 0; i < 8; ++i) a.w[i] = sh >= 16 ? 0 : static_cast<uint16_t>(a.w[i] >> sh); break;
    case SseShift::PsrD: for (int i = 0; i < 4; ++i) a.d[i] = sh >= 32 ? 0u : (a.d[i] >> sh); break;
    case SseShift::PsrQ: for (int i = 0; i < 2; ++i) a.q[i] = sh >= 64 ? 0ull : (a.q[i] >> sh); break;
    case SseShift::PsaW: for (int i = 0; i < 8; ++i) a.w[i] = sh >= 16 ? static_cast<uint16_t>(static_cast<int16_t>(a.w[i]) >> 15) : static_cast<uint16_t>(static_cast<int16_t>(a.w[i]) >> sh); break;
    case SseShift::PsaD: for (int i = 0; i < 4; ++i) a.d[i] = sh >= 32 ? static_cast<uint32_t>(static_cast<int32_t>(a.d[i]) >> 31) : static_cast<uint32_t>(static_cast<int32_t>(a.d[i]) >> sh); break;
    case SseShift::PslDQ: { const unsigned s = sh > 16 ? 16u : sh; V128 t{}; for (int i = 0; i < 16; ++i) { const int src = i - static_cast<int>(s); t.b[i] = src >= 0 ? a.b[src] : 0; } a = t; } break;
    case SseShift::PsrDQ: { const unsigned s = sh > 16 ? 16u : sh; V128 t{}; for (int i = 0; i < 16; ++i) { const int src = i + static_cast<int>(s); t.b[i] = src < 16 ? a.b[src] : 0; } a = t; } break;
    default: return false;
  }
  put(d, a);
  return true;
}

inline void cmp_flags(VMContext& c, bool unord, bool less, bool equal) {
  set_flag(c, F_CF, unord || less);
  set_flag(c, F_PF, unord);
  set_flag(c, F_ZF, unord || equal);
  set_flag(c, F_OF, false);
  set_flag(c, F_SF, false);
  set_flag(c, F_AF, false);
}

inline bool cmp(int d, const V128& b, int op, VMContext& c) {
  V128 a;
  get(a, d);
  bool unord, less, equal;
  switch (static_cast<SseCmp>(op)) {
    case SseCmp::ComiSS: case SseCmp::UcomiSS: {
      const float x = a.f[0], y = b.f[0];
      unord = !(x == x) || !(y == y);
      less = !unord && (x < y);
      equal = !unord && (x == y);
      break;
    }
    case SseCmp::ComiSD: case SseCmp::UcomiSD: {
      const double x = a.df[0], y = b.df[0];
      unord = !(x == x) || !(y == y);
      less = !unord && (x < y);
      equal = !unord && (x == y);
      break;
    }
    default: return false;
  }
  cmp_flags(c, unord, less, equal);
  return true;
}

inline bool cvt(VMContext& c, int d, int s, int op) {
  switch (static_cast<SseCvt>(op)) {
    case SseCvt::Si2SS32: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      a.d[0] = f32b(static_cast<float>(static_cast<int32_t>(static_cast<uint32_t>(c.r[s]))));
      put(d, a);
      return true;
    }
    case SseCvt::Si2SS64: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      a.d[0] = f32b(static_cast<float>(static_cast<int64_t>(c.r[s])));
      put(d, a);
      return true;
    }
    case SseCvt::Si2SD32: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      a.q[0] = f64b(static_cast<double>(static_cast<int32_t>(static_cast<uint32_t>(c.r[s]))));
      put(d, a);
      return true;
    }
    case SseCvt::Si2SD64: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      a.q[0] = f64b(static_cast<double>(static_cast<int64_t>(c.r[s])));
      put(d, a);
      return true;
    }
    case SseCvt::TtSS2Si32: {
      if (!reg_ok(c, s)) return true;
      V128 a; get(a, s);
      const float v = a.f[0];
      int32_t r = INT32_MIN;
      if (v >= -2147483648.0f && v < 2147483648.0f) r = static_cast<int32_t>(v);
      c.r[d] = static_cast<uint32_t>(r);
      return true;
    }
    case SseCvt::TtSS2Si64: {
      if (!reg_ok(c, s)) return true;
      V128 a; get(a, s);
      const float v = a.f[0];
      int64_t r = INT64_MIN;
      if (v >= -9223372036854775808.0 && v < 9223372036854775808.0)
        r = static_cast<int64_t>(v);
      c.r[d] = static_cast<uint64_t>(r);
      return true;
    }
    case SseCvt::TtSD2Si32: {
      if (!reg_ok(c, s)) return true;
      V128 a; get(a, s);
      const double v = a.df[0];
      int32_t r = INT32_MIN;
      if (v >= -2147483648.0 && v < 2147483648.0) r = static_cast<int32_t>(v);
      c.r[d] = static_cast<uint32_t>(r);
      return true;
    }
    case SseCvt::TtSD2Si64: {
      if (!reg_ok(c, s)) return true;
      V128 a; get(a, s);
      const double v = a.df[0];
      int64_t r = INT64_MIN;
      if (v >= -9223372036854775808.0 && v < 9223372036854775808.0)
        r = static_cast<int64_t>(v);
      c.r[d] = static_cast<uint64_t>(r);
      return true;
    }
    case SseCvt::Ss2Sd: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      V128 b; get(b, s);
      a.q[0] = f64b(static_cast<double>(b.f[0]));
      put(d, a);
      return true;
    }
    case SseCvt::Sd2Ss: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      V128 b; get(b, s);
      a.d[0] = f32b(static_cast<float>(b.df[0]));
      put(d, a);
      return true;
    }
    case SseCvt::MovdToX: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      a.d[0] = static_cast<uint32_t>(c.r[s]);
      a.d[1] = 0; a.d[2] = 0; a.d[3] = 0;
      put(d, a);
      return true;
    }
    case SseCvt::MovdFromX: {
      if (!reg_ok(c, s)) return true;
      V128 b; get(b, s);
      c.r[d] = static_cast<uint32_t>(b.d[0]);
      return true;
    }
    case SseCvt::MovqToX: {
      if (!reg_ok(c, d)) return true;
      V128 a; get(a, d);
      a.q[0] = c.r[s];
      a.q[1] = 0;
      put(d, a);
      return true;
    }
    case SseCvt::MovqFromX: {
      if (!reg_ok(c, s)) return true;
      V128 b; get(b, s);
      c.r[d] = b.q[0];
      return true;
    }
  }
  return false;
}

inline bool shuf(int d, int s, uint8_t imm, int op) {
  V128 a, b;
  get(a, d);
  get(b, s);
  switch (static_cast<SseShuf>(op)) {
    case SseShuf::Pshufd: {
      V128 r;
      for (int i = 0; i < 4; ++i) r.d[i] = b.d[(imm >> (2 * i)) & 3];
      put(d, r);
      return true;
    }
    case SseShuf::ShufPS: {
      V128 r;
      r.d[0] = a.d[imm & 3];
      r.d[1] = a.d[(imm >> 2) & 3];
      r.d[2] = b.d[(imm >> 4) & 3];
      r.d[3] = b.d[(imm >> 6) & 3];
      put(d, r);
      return true;
    }
    case SseShuf::ShufPD: {
      V128 r;
      r.q[0] = a.q[imm & 1];
      r.q[1] = b.q[(imm >> 1) & 1];
      put(d, r);
      return true;
    }
    case SseShuf::UnpckLPS: {
      V128 r;
      r.d[0] = a.d[0]; r.d[1] = b.d[0];
      r.d[2] = a.d[1]; r.d[3] = b.d[1];
      put(d, r);
      return true;
    }
    case SseShuf::UnpckLPD: case SseShuf::UnpckLQDQ: {
      V128 r;
      r.q[0] = a.q[0];
      r.q[1] = b.q[0];
      put(d, r);
      return true;
    }
    case SseShuf::UnpckHQDQ: {
      V128 r;
      r.q[0] = a.q[1];
      r.q[1] = b.q[1];
      put(d, r);
      return true;
    }
  }
  return false;
}

}

void h_sse_ld16(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  uint64_t* d = sse::xr(o[0]);
  d[0] = ld64(a);
  d[1] = ld64(a + 8);
  sse::zero_hi(o[0]);
}
void h_sse_ld8(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  uint64_t* d = sse::xr(o[0]);
  d[0] = ld64(a);
  d[1] = 0;
  sse::zero_hi(o[0]);
}
void h_sse_ld4(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  uint32_t v;
  std::memcpy(&v, reinterpret_cast<const void*>(static_cast<uintptr_t>(a)), 4);
  uint64_t* d = sse::xr(o[0]);
  d[0] = v;
  d[1] = 0;
  sse::zero_hi(o[0]);
}
void h_sse_st16(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  const uint64_t* s = sse::xr(o[0]);
  st64(a, s[0]);
  st64(a + 8, s[1]);
}
void h_sse_st8(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  st64(a, sse::xr(o[0])[0]);
}
void h_sse_st4(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  const uint32_t v = static_cast<uint32_t>(sse::xr(o[0])[0]);
  std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(a)), &v, 4);
}

void h_sse_mov(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  uint64_t* d = sse::xr(o[0]);
  const uint64_t* s = sse::xr(o[1]);
  switch (o[2]) {
    case kSseMovFull: d[0] = s[0]; d[1] = s[1]; break;
    case kSseMovSS: d[0] = (d[0] & 0xFFFFFFFF00000000ull) | (s[0] & 0xFFFFFFFFull); break;
    case kSseMovSD: d[0] = s[0]; break;
    case kSseMovQ: d[0] = s[0]; d[1] = 0; break;
    default: c.status = ST_FAULT; break;
  }
  sse::zero_hi(o[0]);
}

void h_sse_bin(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  sse::V128 b;
  sse::get(b, o[1]);
  if (!sse::bin(o[0], b, o[2])) c.status = ST_FAULT;
}

void h_sse_bin3(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1]) || !sse::reg_ok(c, o[2])) return;
  sse::V128 b;
  sse::get(b, o[2]);
  if (!sse::bin3(o[0], o[1], b, o[3])) c.status = ST_FAULT;
}

void h_sse_binm(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  sse::V128 b;
  b.q[0] = ld64(a);
  b.q[1] = ld64(a + 8);
  if (!sse::bin(o[0], b, o[8])) c.status = ST_FAULT;
}

void h_sse_un(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  if (!sse::un(o[0], o[1])) c.status = ST_FAULT;
}

void h_sse_cmp(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  sse::V128 b;
  sse::get(b, o[1]);
  if (!sse::cmp(o[0], b, o[2], c)) c.status = ST_FAULT;
}

void h_sse_cmpm(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  sse::V128 b;
  b.q[0] = ld64(a);
  b.q[1] = ld64(a + 8);
  if (!sse::cmp(o[0], b, o[8], c)) c.status = ST_FAULT;
}

void h_sse_cvt(VMContext& c, const uint8_t* o) {
  if (!sse::cvt(c, o[0], o[1], o[2])) c.status = ST_FAULT;
}

void h_sse_shuf(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  if (!sse::shuf(o[0], o[1], o[2], o[3])) c.status = ST_FAULT;
}

void h_sse_shift(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  if (!sse::sh(o[0], o[1], o[2])) c.status = ST_FAULT;
}

void h_avx_ld256(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  sse::V256 v;
  v.q[0] = ld64(a);
  v.q[1] = ld64(a + 8);
  v.q[2] = ld64(a + 16);
  v.q[3] = ld64(a + 24);
  sse::put256(o[0], v);
}
void h_avx_st256(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  const uint64_t* p = fp_state()->xmm(o[0]);
  const uint64_t* h = fp_state()->ymm_hi(o[0]);
  st64(a, p[0]);
  st64(a + 8, p[1]);
  st64(a + 16, h[0]);
  st64(a + 24, h[1]);
}
void h_avx_mov256(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  sse::V256 v;
  sse::get256(v, o[1]);
  sse::put256(o[0], v);
}
void h_avx_bin3_256(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1]) || !sse::reg_ok(c, o[2])) {
    return;
  }
  sse::V256 b;
  sse::get256(b, o[2]);
  if (!sse::bin3_256(o[0], o[1], b, o[3])) c.status = ST_FAULT;
}

void h_avx_ex128(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  const unsigned lane = (o[2] != 0) ? 1u : 0u;
  sse::V256 v;
  sse::get256(v, o[1]);
  sse::V128 r;
  r.q[0] = v.q[lane * 2];
  r.q[1] = v.q[lane * 2 + 1];
  sse::put(o[0], r);
}

void h_avx_ins128(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1]) || !sse::reg_ok(c, o[2])) {
    return;
  }
  const unsigned lane = (o[3] != 0) ? 1u : 0u;
  sse::V256 a, b;
  sse::get256(a, o[1]);
  sse::get256(b, o[2]);
  a.q[lane * 2] = b.q[0];
  a.q[lane * 2 + 1] = b.q[1];
  sse::put256(o[0], a);
}

void h_avx_stl128(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  const unsigned lane = (o[8] != 0) ? 1u : 0u;
  sse::V256 v;
  sse::get256(v, o[0]);
  st64(a, v.q[lane * 2]);
  st64(a + 8, v.q[lane * 2 + 1]);
}

void h_avx_ldl128(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  const unsigned lane = (o[8] != 0) ? 1u : 0u;
  sse::V256 v;
  sse::get256(v, o[0]);
  v.q[lane * 2] = ld64(a);
  v.q[lane * 2 + 1] = ld64(a + 8);
  sse::put256(o[0], v);
}

void h_avx_bcast(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0]) || !sse::reg_ok(c, o[1])) return;
  sse::V128 s;
  sse::get(s, o[1]);
  sse::V256 v;
  switch (o[2]) {
    case 0: {
      uint8_t x = s.b[0];
      for (int i = 0; i < 32; ++i) v.b[i] = x;
      break;
    }
    case 1: {
      uint16_t x = s.w[0];
      for (int i = 0; i < 16; ++i) v.w[i] = x;
      break;
    }
    case 2: {
      uint32_t x = s.d[0];
      for (int i = 0; i < 8; ++i) v.d[i] = x;
      break;
    }
    default: {
      uint64_t x = s.q[0];
      for (int i = 0; i < 4; ++i) v.q[i] = x;
      break;
    }
  }
  sse::put256(o[0], v);
}

void h_avx_binm256(VMContext& c, const uint8_t* o) {
  if (!sse::reg_ok(c, o[0])) return;
  const uint64_t a = mem_addr(c, o[1], o[2], rd_i8(o + 3), rd_i32(o + 4));
  sse::V256 b;
  b.q[0] = ld64(a);
  b.q[1] = ld64(a + 8);
  b.q[2] = ld64(a + 16);
  b.q[3] = ld64(a + 24);
  if (!sse::bin3_256(o[0], o[0], b, o[8])) c.status = ST_FAULT;
}

#define HYDA_MK_HANDLER(NAME, A, B, C, D, E, F, H) H,

}

extern "C" HandlerFn hyda_handler_list[OP_COUNT + 1];

__attribute__((used)) HandlerFn hyda_handler_list[OP_COUNT + 1] = {
    HYDA_OPCODES(HYDA_MK_HANDLER)(::hyda::HandlerFn)(h_bad_slot)};

extern "C" void hyda_handler_neutral(VMContext& c, const uint8_t*) {
  c.status = ST_BAD_OPCODE;
}

uint64_t pack_dispatch_entry(uint64_t tab_addr, HandlerFn fn, uint8_t opsz,
                             uint8_t regcnt, uint16_t idx) {
  const int64_t off = static_cast<int64_t>(reinterpret_cast<uintptr_t>(fn)) -
                      static_cast<int64_t>(tab_addr);
  if (off < INT32_MIN || off > INT32_MAX) {
    std::fprintf(stderr,
                 "HydaVM: handler address does not fit a 32-bit base-relative offset "
                 "(table and code are too far apart)\n");
    std::abort();
  }
  uint64_t e = static_cast<uint32_t>(static_cast<int32_t>(off));
  e |= static_cast<uint64_t>(opsz) << kDispatchOpszShift;
  e |= static_cast<uint64_t>(regcnt) << kDispatchRegcntShift;
  e ^= dispatch_key_idx(::g_dispatch_profile, tab_addr, idx);
  return e;
}

namespace {

uint64_t ring_mix(uint64_t& s) {
  s += 0x9E3779B97F4A7C15ull;
  uint64_t z = s;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

void ring_make_perm(uint16_t* perm, uint64_t seed) {
  for (size_t i = 0; i < kSlotCount; ++i) perm[i] = static_cast<uint16_t>(i);
  uint64_t s = seed;
  for (size_t i = kSlotCount - 1; i > 0; --i) {
    const uint64_t r = ring_mix(s);
    const size_t j = static_cast<size_t>(r % (i + 1));
    const uint16_t t = perm[i];
    perm[i] = perm[j];
    perm[j] = t;
  }
}

size_t ring_word(const DispatchProfile& p, uint16_t idx) {
  return static_cast<size_t>(idx) << (p.entry_shift - 3u);
}

void ring_fill_table(uint64_t* tab, uint16_t* perm, uint64_t* call,
                     const HandlerFn* ops, HandlerFn bad_slot, uint64_t seed) {
  const DispatchProfile& prof = ::g_dispatch_profile;
  ring_make_perm(perm, seed);
  const uint64_t tab_addr =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(tab));
  const uint64_t bad_addr =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(bad_slot));

  for (size_t i = 0; i < kSlotCount; ++i) {
    const uint16_t idx = static_cast<uint16_t>(i);
    tab[ring_word(prof, idx)] =
        pack_dispatch_entry(tab_addr, bad_slot, 0, 0, idx);
    if (call != nullptr) {

      call[idx] = bad_addr ^ dispatch_key_idx(prof, tab_addr, idx);
    }
  }

  const OpcodeMap& m = opcode_map();
  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint16_t idx = perm[m.slot_of_op[op]];
    tab[ring_word(prof, idx)] = pack_dispatch_entry(
        tab_addr, ops[op], static_cast<uint8_t>(op_size(static_cast<Op>(op))),
        static_cast<uint8_t>(leading_reg_count(OP_SIGS[op])), idx);
    if (call != nullptr) {
      call[idx] = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ops[op])) ^
                  dispatch_key_idx(prof, tab_addr, idx);
    }
  }
}

DispatchRange ring_fill(uint64_t (*tabs)[kRingTableWords],
                        uint16_t (*perms)[kSlotCount],
                        uint64_t (*calls)[kSlotCount], unsigned count,
                        const HandlerFn* ops, HandlerFn bad_slot, uint64_t salt) {
  uint64_t lo = UINT64_MAX;
  uint64_t hi = 0;
  const auto bump = [&](const void* p) {
    const uint64_t a = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p));
    if (a < lo) lo = a;
    if (a + 1 > hi) hi = a + 1;
  };
  bump(reinterpret_cast<const void*>(bad_slot));

  const uint64_t seed0 = ring_seed(::g_dispatch_profile) ^ salt;
  for (unsigned e = 0; e < count; ++e) {

    uint64_t s = seed0 + static_cast<uint64_t>(e) * 0x9E3779B97F4A7C15ull;
    const uint64_t seed = ring_mix(s);
    ring_fill_table(tabs[e], perms[e], calls == nullptr ? nullptr : calls[e],
                    ops, bad_slot, seed);
    for (size_t op = 0; op < OP_COUNT; ++op)
      bump(reinterpret_cast<const void*>(ops[op]));
  }
  return DispatchRange{lo, hi};
}

void ring_addrs_to_ops(const uint64_t* addrs, HandlerFn* out) {
  for (size_t op = 0; op < OP_COUNT; ++op) {
    out[op] = reinterpret_cast<HandlerFn>(static_cast<uintptr_t>(addrs[op]));
  }
}

}

DispatchRange build_dispatch_ring_list() {
  return ring_fill(hyda_ring_tab, hyda_ring_perm, hyda_ring_call, kRingTables,
                   hyda_handler_list, hyda_handler_list[OP_COUNT], 0);
}

void build_decoy_ring_list(uint64_t salt) {
  (void)ring_fill(hyda_ring_decoy_tab, hyda_ring_decoy_perm,
                  hyda_ring_decoy_call, kRingDecoys, hyda_handler_list,
                  hyda_handler_list[OP_COUNT], salt);
}

DispatchRange build_dispatch_ring_addrs(const uint64_t* addrs,
                                        uint64_t bad_slot) {
  HandlerFn ops[OP_COUNT];
  ring_addrs_to_ops(addrs, ops);
  return ring_fill(hyda_ring_tab, hyda_ring_perm, hyda_ring_call, kRingTables,
                   ops, reinterpret_cast<HandlerFn>(
                            static_cast<uintptr_t>(bad_slot)), 0);
}

void build_decoy_ring_addrs(const uint64_t* addrs, uint64_t bad_slot,
                            uint64_t salt) {
  HandlerFn ops[OP_COUNT];
  ring_addrs_to_ops(addrs, ops);
  (void)ring_fill(hyda_ring_decoy_tab, hyda_ring_decoy_perm,
                  hyda_ring_decoy_call, kRingDecoys, ops,
                  reinterpret_cast<HandlerFn>(
                      static_cast<uintptr_t>(bad_slot)), salt);
}

}
