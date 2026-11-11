#include "harness/test.hpp"
#include "hyda/ir/assembler.hpp"
#include "hyda/guard/antidbg.hpp"
#include "hyda/guard/apihash.hpp"
#include "hyda/vm/fpstate.hpp"
#include "hyda/mutate/fuse.hpp"
#include "hyda/vm/sse.hpp"
#include "hyda/codec/crypt.hpp"
#include "hyda/ir/disasm.hpp"
#include "hyda/vm/dispatch.hpp"
#include "hyda/vm/dispatch_ring.hpp"
#include "hyda/vm/handlers.hpp"
#include "hyda/codec/hydak.hpp"
#include "hyda/guard/audit.hpp"
#include "hyda/codec/datblob.hpp"
#include "hyda/guard/integrity.hpp"
#include "hyda/native/island.hpp"
#include "hyda/ir/ir_codegen.hpp"
#include "hyda/vm/mba.hpp"
#include "hyda/vm/vm2.hpp"
#include "hyda/mutate/mutate.hpp"
#include "hyda/vm/vm.hpp"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace hyda;

namespace {

hyda::test::Reporter* g_rep = nullptr;

}  // namespace

#define CHECK_TRUE(expr) \
  (g_rep->check(static_cast<bool>(expr), #expr, __FILE__, __LINE__))

#define CHECK_EQ(a, b)                                          \
  do {                                                          \
    const long long _a = (long long)(a);                        \
    const long long _b = (long long)(b);                        \
    g_rep->eq(_a, _b, #a " == " #b, __FILE__, __LINE__);        \
  } while (0)

#define CHECK_U64(a, b)                                         \
  do {                                                          \
    g_rep->eq_hex(static_cast<uint64_t>(a), static_cast<uint64_t>(b), \
                  #a " == " #b, __FILE__, __LINE__);            \
  } while (0)

alignas(64) static uint8_t g_stack[128 * 1024];
alignas(64) static uint8_t g_data[4096];

static uint64_t stack_top() {
  return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(g_stack + sizeof(g_stack)));
}

static bool flag_bit(uint64_t flags, unsigned bit) {
  return ((flags >> bit) & 1u) != 0;
}

static void reset(VMContext& ctx, uint64_t max_steps = 0) {
  vm_init(ctx, stack_top());
  ctx.max_steps = max_steps;
}

static uint32_t run(VMContext& ctx, Asm& a, uint64_t max_steps = 0) {
  a.finalize();
  reset(ctx, max_steps);
  return vm_exec(ctx, a.code.data(), a.code.size());
}

static inline uint16_t bc_slot(const uint8_t* c, size_t off) {
  return static_cast<uint16_t>(c[off] |
                               (static_cast<uint16_t>(c[off + 1]) << 8));
}

static void test_permutation() {
  const OpcodeMap& m = opcode_map();

  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint16_t slot = m.slot_of_op[op];
    CHECK_EQ(m.op_of_slot[slot], (int)op);
  }

  bool seen[kSlotCount] = {false};
  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint16_t s = m.slot_of_op[op];
    CHECK_TRUE(!seen[s]);
    seen[s] = true;
  }

  int used = 0;
  for (size_t i = 0; i < kSlotCount; ++i) {
    if (m.op_of_slot[i] != BAD_SLOT) ++used;
  }
  CHECK_EQ(used, (int)OP_COUNT);

  CHECK_TRUE(kSlotCount > 256u);
  bool beyond = false;
  for (size_t op = 0; op < OP_COUNT; ++op) {
    if (m.slot_of_op[op] >= 256u) { beyond = true; break; }
  }
  CHECK_TRUE(beyond);
}

static void test_basic_arith() {
  VMContext ctx;
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 7);
  a.i_rq(Op::MOV_RI, REG_RCX, 35);
  a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
  a.i_rq(Op::MOV_RI, REG_RDX, 2);
  a.i_rr(Op::IMUL2, REG_RAX, REG_RDX);
  a.i_rr(Op::SUB64, REG_RAX, REG_RCX);
  a.i0(Op::HALT);

  CHECK_EQ(run(ctx, a), (int)ST_HALT);
  CHECK_U64(ctx.r[vsl(REG_RAX)], 49);
  CHECK_U64(ctx.r[vsl(REG_RCX)], 35);
  CHECK_U64(ctx.r[vsl(REG_RDX)], 2);

  CHECK_U64(ctx.r[vsl(REG_R15)], 0);
}

static void test_loop_sum() {
  VMContext ctx;
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 0);
  a.i_rq(Op::MOV_RI, REG_RCX, 100);
  a.i_rq(Op::MOV_RI, REG_RDX, 0);

  size_t loop = a.label();
  a.bind(loop);
  a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
  a.i_r(Op::DEC, REG_RCX);
  a.i_rr(Op::CMP64, REG_RCX, REG_RDX);
  a.i_j(Op::JCC_NZ, loop);
  a.i0(Op::HALT);

  CHECK_EQ(run(ctx, a), (int)ST_HALT);
  CHECK_U64(ctx.r[vsl(REG_RAX)], 5050);
  CHECK_U64(ctx.r[vsl(REG_RCX)], 0);
  CHECK_U64(ctx.r[vsl(REG_RSP)], stack_top());
}

static void test_call_ret() {
  VMContext ctx;
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 5);

  size_t sub = a.label();
  a.i_j(Op::CALL, sub);
  a.i0(Op::HALT);

  a.bind(sub);
  a.i_rr(Op::ADD64, REG_RAX, REG_RAX);
  a.i0(Op::RET);

  CHECK_EQ(run(ctx, a), (int)ST_HALT);
  CHECK_U64(ctx.r[vsl(REG_RAX)], 10);
  CHECK_U64(ctx.r[vsl(REG_RSP)], stack_top());

  VMContext ctx2;
  Asm b;
  b.i_q(Op::PUSH_IMM, 7);
  b.i_q(Op::PUSH_IMM, 9);
  b.i_rq(Op::MOV_RI, REG_RSI, 40);
  b.i_rq(Op::MOV_RI, REG_RDI, 2);
  size_t f = b.label();
  b.i_j(Op::CALL, f);
  b.i_r(Op::POP_R, REG_RDX);
  b.i_r(Op::POP_R, REG_RBX);
  b.i0(Op::HALT);
  b.bind(f);
  b.i_rr(Op::MOV_RR, REG_RAX, REG_RSI);
  b.i_rr(Op::ADD64, REG_RAX, REG_RDI);
  b.i0(Op::RET);

  CHECK_EQ(run(ctx2, b), (int)ST_HALT);
  CHECK_U64(ctx2.r[vsl(REG_RAX)], 42);
  CHECK_U64(ctx2.r[vsl(REG_RDX)], 9);
  CHECK_U64(ctx2.r[vsl(REG_RBX)], 7);
  CHECK_U64(ctx2.r[vsl(REG_RSP)], stack_top());
}

static void test_memory() {
  VMContext ctx;
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RBX, (int64_t)(intptr_t)g_data);
  a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0x1122334455667788ull);
  a.i_mem(Op::MOV_MR, REG_RAX, REG_RBX, NO_MEM, 1, 0);
  a.i_rq(Op::MOV_RI, REG_RAX, 42);
  a.i_mem(Op::MOV_MR, REG_RAX, REG_RBX, NO_MEM, 1, 8);
  a.i_rq(Op::MOV_RI, REG_RCX, 1);
  a.i_mem(Op::MOV_RM, REG_RDX, REG_RBX, REG_RCX, 8, 0);
  a.i_mem(Op::MOV_RM, REG_RSI, REG_RBX, NO_MEM, 1, 0);
  a.i_mem(Op::LEA, REG_RDI, REG_RBX, REG_RCX, 8, 16);
  a.i0(Op::HALT);

  CHECK_EQ(run(ctx, a), (int)ST_HALT);
  CHECK_U64(ctx.r[vsl(REG_RDX)], 42);
  CHECK_U64(ctx.r[vsl(REG_RSI)], 0x1122334455667788ull);
  CHECK_U64(ctx.r[vsl(REG_RDI)], (uint64_t)(uintptr_t)(g_data + 24));
  CHECK_U64(*(uint64_t*)g_data, 0x1122334455667788ull);
}

static void test_size_semantics() {
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0xABCDEF00FFull);
    a.i_rq(Op::MOV_RI, REG_RCX, 1);
    a.i_rr(Op::ADD8, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 0xABCDEF0000ull);
    CHECK_TRUE(flag(ctx, F_CF));
    CHECK_TRUE(flag(ctx, F_ZF));
  }
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0xFFFFFFFFull);
    a.i_rq(Op::MOV_RI, REG_RCX, 1);
    a.i_rr(Op::ADD32, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 0);
    CHECK_TRUE(flag(ctx, F_CF));
    CHECK_TRUE(flag(ctx, F_ZF));
  }
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0xFFFFFFFFFFFFFFFFull);
    a.i_rq(Op::MOV_RI, REG_RCX, 1);
    a.i_rr(Op::ADD16, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 0xFFFFFFFFFFFF0000ull);
    CHECK_TRUE(flag(ctx, F_CF));
    CHECK_TRUE(flag(ctx, F_ZF));
  }
  {

    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 0x80);
    a.i_rr(Op::MOVSX8, REG_RDX, REG_RAX);
    a.i_rr(Op::MOVZX8, REG_RSI, REG_RAX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RDX)], 0xFFFFFFFFFFFFFF80ull);
    CHECK_U64(ctx.r[vsl(REG_RSI)], 0x80);
  }
}

static uint64_t shift_once(Op op, uint64_t v, int cnt) {
  VMContext ctx;
  Asm a;
  reset(ctx);
  ctx.r[vsl(REG_RAX)] = v;
  a.i_rb(op, REG_RAX, cnt);
  a.i0(Op::HALT);
  a.finalize();
  vm_exec(ctx, a.code.data(), a.code.size());
  return ctx.r[vsl(REG_RAX)];
}

static void test_shifts() {
  CHECK_U64(shift_once(Op::SHL, 1, 4), 16);
  CHECK_U64(shift_once(Op::SHL, 0x8000000000000000ull, 1), 0);
  CHECK_U64(shift_once(Op::SHR, 0xF000000000000000ull, 60), 0xF);
  CHECK_U64(shift_once(Op::SAR, 0x8000000000000000ull, 63), 0xFFFFFFFFFFFFFFFFull);
  CHECK_U64(shift_once(Op::SAR, 0x4000000000000000ull, 1), 0x2000000000000000ull);
  CHECK_U64(shift_once(Op::ROL, 1, 1), 2);
  CHECK_U64(shift_once(Op::ROR, 1, 1), 0x8000000000000000ull);
  CHECK_U64(shift_once(Op::ROL, 0x8000000000000000ull, 1), 1);
  CHECK_U64(shift_once(Op::SHL, 0x1234, 0), 0x1234);

  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0x8000000000000000ull);
    a.i_rb(Op::SHL, REG_RAX, 1);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_TRUE(flag(ctx, F_CF));
    CHECK_TRUE(flag(ctx, F_OF));
  }
}

static void test_mul_div() {
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 100);
    a.i_rq(Op::MOV_RI, REG_RCX, 7);
    a.i0(Op::CQO);
    a.i_r(Op::IDIV, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 14);
    CHECK_U64(ctx.r[vsl(REG_RDX)], 2);
  }
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0xFFFFFFFFFFFFFFFFull);
    a.i_rq(Op::MOV_RI, REG_RCX, 3);
    a.i_r(Op::MUL, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 0xFFFFFFFFFFFFFFFDull);
    CHECK_U64(ctx.r[vsl(REG_RDX)], 2);
    CHECK_TRUE(flag(ctx, F_CF));
  }
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0xFFFFFFFE00000000ull);
    a.i_rq(Op::MOV_RI, REG_RCX, 2);
    a.i_r(Op::MUL, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RDX)], 1);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 0xFFFFFFFC00000000ull);
  }
  {

    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)(uint64_t)(-100));
    a.i0(Op::CQO);
    a.i_rq(Op::MOV_RI, REG_RCX, 7);
    a.i_r(Op::IDIV, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], (uint64_t)(int64_t)(-14));
    CHECK_U64(ctx.r[vsl(REG_RDX)], (uint64_t)(int64_t)(-2));
  }
  {

    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 1);
    a.i_rq(Op::MOV_RI, REG_RCX, 0);
    a.i_r(Op::DIV, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_DIV0);
  }
}

static void test_cmov() {
  VMContext ctx;
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 5);
  a.i_rq(Op::MOV_RI, REG_RCX, 9);
  a.i_rr(Op::CMP64, REG_RAX, REG_RAX);
  a.i_rrb(Op::CMOV, REG_RAX, REG_RCX, 4);
  a.i0(Op::HALT);
  CHECK_EQ(run(ctx, a), (int)ST_HALT);
  CHECK_U64(ctx.r[vsl(REG_RAX)], 9);

  VMContext ctx2;
  Asm b;
  b.i_rq(Op::MOV_RI, REG_RAX, 5);
  b.i_rq(Op::MOV_RI, REG_RCX, 9);
  b.i_rr(Op::CMP64, REG_RAX, REG_RAX);
  b.i_rrb(Op::CMOV, REG_RAX, REG_RCX, 5);
  b.i0(Op::HALT);
  CHECK_EQ(run(ctx2, b), (int)ST_HALT);
  CHECK_U64(ctx2.r[vsl(REG_RAX)], 5);
}

static void ref_add(uint64_t a, uint64_t b, uint64_t ci, unsigned bits,
                    uint64_t& res, bool& cf, bool& of, bool& zf, bool& sf, bool& pf) {
  const uint64_t m = mask_bits(bits);
  const uint64_t sb = sign_bit(bits);
  const uint64_t am = a & m, bm = b & m;
  const unsigned __int128 wide = (unsigned __int128)am + bm + ci;
  const uint64_t r = (uint64_t)wide & m;

  res = r;
  cf = wide > m;
  of = ((am & sb) == (bm & sb)) && ((r & sb) != (am & sb));
  zf = (r == 0);
  sf = (r & sb) != 0;
  pf = parity_even(r);
}

static void ref_sub(uint64_t a, uint64_t b, uint64_t bi, unsigned bits,
                    uint64_t& res, bool& cf, bool& of, bool& zf, bool& sf, bool& pf) {
  const uint64_t m = mask_bits(bits);
  const uint64_t sb = sign_bit(bits);
  const uint64_t am = a & m, bm = b & m;
  const unsigned __int128 sub = (unsigned __int128)bm + bi;
  const uint64_t r = (uint64_t)((unsigned __int128)am - sub) & m;

  res = r;
  cf = (unsigned __int128)am < sub;
  of = ((am & sb) != (bm & sb)) && ((r & sb) != (am & sb));
  zf = (r == 0);
  sf = (r & sb) != 0;
  pf = parity_even(r);
}

struct AluObs {
  uint64_t reg = 0;
  uint64_t flags = 0;
  uint32_t status = 0;
};

static AluObs observe_alu(Op op, uint64_t a, uint64_t b, bool cf_in) {
  VMContext ctx;
  Asm p;
  reset(ctx);
  ctx.r[vsl(REG_RAX)] = a;
  ctx.r[vsl(REG_RCX)] = b;
  if (cf_in) set_flag(ctx, F_CF, true);
  p.i_rr(op, REG_RAX, REG_RCX);
  p.i0(Op::HALT);
  p.finalize();
  AluObs o;
  o.status = vm_exec(ctx, p.code.data(), p.code.size());
  o.reg = ctx.r[vsl(REG_RAX)];
  o.flags = ctx.r[vsl(REG_RFLAGS)];
  return o;
}

static void check_flags(const char* what, uint64_t a, uint64_t b, bool cf_in,
                        Op op, unsigned bits, uint64_t want_res,
                        bool cf, bool of, bool zf, bool sf, bool pf) {
  const AluObs o = observe_alu(op, a, b, cf_in);
  g_rep->check(o.status == ST_HALT, std::string(what) + ": vm status", __FILE__,
               __LINE__);
  if (o.status != ST_HALT) return;

  struct { const char* n; bool got, want; } f[5] = {
      {"CF", flag_bit(o.flags, F_CF), cf},
      {"OF", flag_bit(o.flags, F_OF), of},
      {"ZF", flag_bit(o.flags, F_ZF), zf},
      {"SF", flag_bit(o.flags, F_SF), sf},
      {"PF", flag_bit(o.flags, F_PF), pf},
  };
  for (int i = 0; i < 5; ++i) {
    g_rep->check(f[i].got == f[i].want, std::string(what) + ": " + f[i].n + " flag",
                 __FILE__, __LINE__);
  }

  const uint64_t m = mask_bits(bits);
  CHECK_U64(o.reg & m, want_res & m);
  if (bits < 32) {
    CHECK_U64(o.reg & ~m, a & ~m);
  } else {
    CHECK_U64(o.reg, want_res & m);
  }
}

static void test_flag_reference() {
  uint64_t seed = 0xDEADBEEFCAFEBABEull;

  for (int i = 0; i < 1500; ++i) {
    const uint64_t a = splitmix64(seed);
    const uint64_t b = splitmix64(seed);

    uint64_t r = 0;
    bool cf = false, of = false, zf = false, sf = false, pf = false;

    ref_add(a, b, 0, 64, r, cf, of, zf, sf, pf);
    check_flags("ADD64", a, b, false, Op::ADD64, 64, r, cf, of, zf, sf, pf);

    ref_sub(a, b, 0, 64, r, cf, of, zf, sf, pf);
    check_flags("SUB64", a, b, false, Op::SUB64, 64, r, cf, of, zf, sf, pf);

    if (i % 4 == 0) {
      ref_add(a, b, 1, 64, r, cf, of, zf, sf, pf);
      check_flags("ADC64", a, b, true, Op::ADC64, 64, r, cf, of, zf, sf, pf);

      ref_sub(a, b, 1, 64, r, cf, of, zf, sf, pf);
      check_flags("SBB64", a, b, true, Op::SBB64, 64, r, cf, of, zf, sf, pf);
    }
  }

  for (int i = 0; i < 600; ++i) {
    const uint64_t a = splitmix64(seed);
    const uint64_t b = splitmix64(seed);
    uint64_t r = 0;
    bool cf = false, of = false, zf = false, sf = false, pf = false;

    ref_add(a, b, 0, 32, r, cf, of, zf, sf, pf);
    check_flags("ADD32", a, b, false, Op::ADD32, 32, r, cf, of, zf, sf, pf);
    ref_sub(a, b, 0, 32, r, cf, of, zf, sf, pf);
    check_flags("SUB32", a, b, false, Op::SUB32, 32, r, cf, of, zf, sf, pf);

    ref_add(a, b, 0, 16, r, cf, of, zf, sf, pf);
    check_flags("ADD16", a, b, false, Op::ADD16, 16, r, cf, of, zf, sf, pf);
    ref_sub(a, b, 0, 16, r, cf, of, zf, sf, pf);
    check_flags("SUB16", a, b, false, Op::SUB16, 16, r, cf, of, zf, sf, pf);

    ref_add(a, b, 0, 8, r, cf, of, zf, sf, pf);
    check_flags("ADD8", a, b, false, Op::ADD8, 8, r, cf, of, zf, sf, pf);
    ref_sub(a, b, 0, 8, r, cf, of, zf, sf, pf);
    check_flags("SUB8", a, b, false, Op::SUB8, 8, r, cf, of, zf, sf, pf);
  }

  for (int i = 0; i < 600; ++i) {
    const uint64_t a = splitmix64(seed);
    const uint64_t b = splitmix64(seed);
    const struct { Op op; int kind; } ops[3] = {
        {Op::AND64, 0}, {Op::OR64, 1}, {Op::XOR64, 2}};
    for (int k = 0; k < 3; ++k) {
      const AluObs o = observe_alu(ops[k].op, a, b, false);
      const uint64_t want = (ops[k].kind == 0) ? (a & b) : (ops[k].kind == 1) ? (a | b) : (a ^ b);
      CHECK_U64(o.reg, want);
      CHECK_TRUE(!flag_bit(o.flags, F_CF));
      CHECK_TRUE(!flag_bit(o.flags, F_OF));
      CHECK_EQ(flag_bit(o.flags, F_ZF), want == 0);
      CHECK_EQ(flag_bit(o.flags, F_SF), (want >> 63) != 0);
      CHECK_EQ(flag_bit(o.flags, F_PF), parity_even(want));
    }
  }
}

static void test_errors() {
  {
    uint8_t buf[kHeaderBytes] = {0, 0};
    for (size_t i = 0; i < kSlotCount; ++i) {
      if (opcode_map().op_of_slot[i] == BAD_SLOT) {
        buf[0] = static_cast<uint8_t>(i & 0xFFu);
        buf[1] = static_cast<uint8_t>(i >> 8);
        break;
      }
    }
    VMContext ctx;
    reset(ctx);
    CHECK_EQ(vm_exec(ctx, buf, kHeaderBytes), (int)ST_BAD_OPCODE);
  }
  {
    VMContext ctx;
    Asm a;
    size_t l = a.label();
    a.bind(l);
    a.i_j(Op::JMP, l);
    CHECK_EQ(run(ctx, a, 1000), (int)ST_STEP_LIMIT);
  }
  {
    VMContext ctx;
    reset(ctx);
    CHECK_EQ(vm_exec(ctx, nullptr, 0), (int)ST_FAULT);
  }
}

static uint32_t run_bounded(VMContext& ctx, Asm& a, uint64_t base, uint64_t limit,
                            uint64_t top) {
  a.finalize();
  vm_init(ctx, top);
  vm_set_stack(ctx, base, limit);
  return vm_exec(ctx, a.code.data(), a.code.size());
}

static void test_stack_guard() {
  const uint64_t top = stack_top();
  const uint64_t base = top - 32;

  {
    VMContext ctx;
    Asm a;
    for (int i = 0; i < 4; ++i) a.i_q(Op::PUSH_IMM, 0x11);
    a.i0(Op::HALT);
    CHECK_EQ(run_bounded(ctx, a, base, top, top), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RSP)], base);
  }
  {
    VMContext ctx;
    Asm a;
    for (int i = 0; i < 5; ++i) a.i_q(Op::PUSH_IMM, 0x11);
    a.i0(Op::HALT);
    CHECK_EQ(run_bounded(ctx, a, base, top, top), (int)ST_FAULT);
    CHECK_U64(ctx.r[vsl(REG_RSP)], base);
  }
  {
    VMContext ctx;
    Asm a;
    a.i0(Op::RET);
    CHECK_EQ(run_bounded(ctx, a, base, top, top), (int)ST_FAULT);
    CHECK_U64(ctx.r[vsl(REG_RSP)], top);
  }
  {
    VMContext ctx;
    Asm a;
    for (int i = 0; i < 5; ++i) a.i_q(Op::PUSH_IMM, 0x11);
    a.i0(Op::HALT);
    a.finalize();
    vm_init(ctx, top);
    CHECK_EQ(vm_exec(ctx, a.code.data(), a.code.size()), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RSP)], top - 40);
  }
  {
    VMContext ctx;
    Asm a;
    a.i_q(Op::PUSH_IMM, 5);
    size_t f = a.label();
    a.i_j(Op::CALL, f);
    a.i_r(Op::POP_R, REG_RAX);
    a.i0(Op::HALT);
    a.bind(f);
    a.i0(Op::RET);
    CHECK_EQ(run_bounded(ctx, a, base, top, top), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 5);
    CHECK_U64(ctx.r[vsl(REG_RSP)], top);
  }
  std::printf("  stack limit   : push/pop outside range -> ST_FAULT, inside allowed\n");
}

static void test_disasm_walk() {
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 0);
  a.i_rq(Op::MOV_RI, REG_RCX, 10);
  size_t l = a.label();
  a.bind(l);
  a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
  a.i_r(Op::DEC, REG_RCX);
  a.i_rrb(Op::CMOV, REG_RAX, REG_RCX, 5);
  a.i_mem(Op::MOV_MR, REG_RAX, REG_RSP, NO_MEM, 1, -8);
  a.i_j(Op::JCC_NZ, l);
  a.i0(Op::HALT);
  a.finalize();

  size_t off = 0;
  int count = 0;
  while (off < a.code.size()) {
    const uint16_t op = opcode_map().op_of_slot[bc_slot(a.code.data(), off)];
    CHECK_TRUE(op != BAD_SLOT);
    off += kHeaderBytes + op_size(static_cast<Op>(op));
    ++count;
  }
  CHECK_EQ(off, a.code.size());
  CHECK_EQ(count, 8);
}

static void demo_disassembly() {
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 0);
  a.i_rq(Op::MOV_RI, REG_RCX, 100);
  a.i_rq(Op::MOV_RI, REG_RDX, 0);
  size_t l = a.label();
  a.bind(l);
  a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
  a.i_r(Op::DEC, REG_RCX);
  a.i_rr(Op::CMP64, REG_RCX, REG_RDX);
  a.i_j(Op::JCC_NZ, l);
  a.i0(Op::HALT);
  a.finalize();

  std::printf("\n--- 1..100 sum, VM bytecode dump (%zu bytes)\n", a.code.size());
  std::printf("    slot bytes are opcodes permuted by the theme seed\n");
  disasm(a.code.data(), a.code.size());

  VMContext ctx;
  reset(ctx);
  vm_exec(ctx, a.code.data(), a.code.size());
  std::printf("    result: rax = %llu\n\n", (unsigned long long)ctx.r[vsl(REG_RAX)]);
}

static IRProgram mutate_sample_prog() {
  IRProgram p;
  IRMem m;
  m.base = REG_RBX;

  p.add(IRCommand::mov(IROperand::R(REG_RBX),
                       IROperand::I(static_cast<int64_t>(reinterpret_cast<intptr_t>(g_data)))));
  p.add(IRCommand::mov(IROperand::R(REG_RCX), IROperand::I(5)));
  p.add(IRCommand::mov(IROperand::R(REG_RDX), IROperand::I(0)));

  const int loop = p.new_label();
  p.bind(loop);
  p.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RAX), IROperand::R(REG_RCX)));
  p.add(IRCommand::mov(IROperand::M(m), IROperand::R(REG_RAX)));
  p.add(IRCommand::mov(IROperand::R(REG_RDX), IROperand::M(m)));
  p.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RDX), IROperand::R(REG_RDX)));
  p.add(IRCommand::unary(UnaryOp::Dec, REG_RCX));
  p.add(IRCommand::br(IROp::Jcc, loop));
  p.cmds.back().sub = 5;
  p.add(IRCommand::mov(IROperand::R(REG_RAX), IROperand::R(REG_RDX)));
  p.add(IRCommand::none(IROp::Ret));
  return p;
}

static uint32_t run_ir_prog(const IRProgram& src, uint64_t arg, uint64_t* rax_out) {
  IRProgram p = src;
  ir_wrap_callable(p);
  Asm a;
  const CodegenResult cg = ir_codegen(p, a);
  if (!cg.ok) return 0xDEAD;
  VMContext ctx;
  reset(ctx);
  ctx.r[vsl(REG_RAX)] = arg;
  vm_set_entry(ctx, cg.entry_offset);
  const uint32_t st = vm_exec(ctx, a.code.data(), a.code.size());
  if (rax_out) *rax_out = ctx.r[vsl(REG_RAX)];
  return st;
}

static void test_mutate() {
  const IRProgram base = mutate_sample_prog();

  MutateOptions off;
  off.inverse = false;
  off.junk_pct = 100;
  off.noise_pct = 100;
  {
    IRProgram p = base;
    const MutateStats st = ir_mutate(p, off);
    CHECK_TRUE(st.junk > 0);
    CHECK_TRUE(st.noise > 0);
    CHECK_EQ(st.inv_r, (size_t)0);
    CHECK_EQ(st.cmds_after, p.cmds.size());
    CHECK_TRUE(st.cmds_after > st.cmds_before);
    for (uint64_t arg = 0; arg <= 8; ++arg) {
      uint64_t want = 0, got = 0;
      CHECK_EQ(run_ir_prog(base, arg, &want), (int)ST_HALT);
      CHECK_EQ(run_ir_prog(p, arg, &got), (int)ST_HALT);
      CHECK_U64(got, want);
    }
  }

  MutateOptions on;
  on.junk_pct = 100;
  on.noise_pct = 100;
  on.inverse_pct = 100;
  MutateStats st;
  {
    IRProgram p = base;
    st = ir_mutate(p, on);
    CHECK_TRUE(st.inv_r > 0);
    CHECK_TRUE(st.inverted_stores > 0);
    CHECK_TRUE(!st.inverse_disabled);
    for (uint64_t arg = 0; arg <= 8; ++arg) {
      uint64_t want = 0, got = 0;
      CHECK_EQ(run_ir_prog(base, arg, &want), (int)ST_HALT);
      CHECK_EQ(run_ir_prog(p, arg, &got), (int)ST_HALT);
      CHECK_U64(got, want);
    }

    CHECK_U64(*(uint64_t*)g_data, 8 + 15);
  }

  for (uint64_t seed : {0x1111ull, 0x2222ull, 0xDEADBEEFull, 0x8F3A5C71D2E6B904ull}) {
    MutateOptions mo = on;
    mo.seed = seed;
    IRProgram p = base;
    const MutateStats s2 = ir_mutate(p, mo);
    CHECK_TRUE(!s2.inverse_disabled);
    for (uint64_t arg = 0; arg <= 8; ++arg) {
      uint64_t want = 0, got = 0;
      CHECK_EQ(run_ir_prog(base, arg, &want), (int)ST_HALT);
      CHECK_EQ(run_ir_prog(p, arg, &got), (int)ST_HALT);
      CHECK_U64(got, want);
    }
  }

  {
    MutateOptions a1 = on, a2 = on;
    a1.seed = a2.seed = 0xABCDEF;
    IRProgram p1 = base, p2 = base;
    ir_mutate(p1, a1);
    ir_mutate(p2, a2);
    CHECK_EQ(p1.cmds.size(), p2.cmds.size());
    CHECK_EQ(p1.label_mark.size(), p2.label_mark.size());
    bool same = p1.cmds.size() == p2.cmds.size();
    for (size_t i = 0; same && i < p1.cmds.size(); ++i) {
      same = p1.cmds[i].op == p2.cmds[i].op &&
             p1.cmds[i].dst.reg == p2.cmds[i].dst.reg &&
             p1.cmds[i].src.imm == p2.cmds[i].src.imm &&
             p1.cmds[i].label == p2.cmds[i].label;
    }
    CHECK_TRUE(same);

    MutateOptions a3 = on;
    a3.seed = 0x123456;
    IRProgram p3 = base;
    ir_mutate(p3, a3);
    bool differs = p3.cmds.size() != p1.cmds.size();
    for (size_t i = 0; !differs && i < p3.cmds.size() && i < p1.cmds.size(); ++i) {
      differs = p3.cmds[i].src.imm != p1.cmds[i].src.imm ||
                p3.cmds[i].op != p1.cmds[i].op;
    }
    CHECK_TRUE(differs);
  }

  {
    IRProgram p = base;
    IRCommand j; j.op = IROp::JmpIndirect; j.dst = IROperand::R(REG_RSI);
    p.cmds.push_back(j);
    const MutateStats s2 = ir_mutate(p, on);
    CHECK_TRUE(s2.inverse_disabled);
    CHECK_EQ(s2.inv_r, (size_t)0);
    CHECK_TRUE(s2.junk > 0);
    bool has_inv = false;
    for (const IRCommand& c : p.cmds) has_inv = has_inv || c.op == IROp::InvR;
    CHECK_TRUE(!has_inv);
  }

  {
    IRProgram p = base;
    ir_mutate(p, on);
    const MutateStats s2 = ir_mutate(p, on);
    CHECK_TRUE(s2.inverse_disabled);
    CHECK_EQ(s2.inv_r, (size_t)0);
  }

  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 0x0F0F0F0F0F0F0F0Full);
    a.i_rr(Op::TEST, REG_RAX, REG_RAX);
    a.i_rq(Op::MOV_RI, REG_RCX, 1);
    a.i_r(Op::INV_R, REG_RAX);
    const size_t skip = a.label();
    a.i_j(Op::JCC_Z, skip);
    a.i_rq(Op::MOV_RI, REG_RCX, 2);
    a.i0(Op::HALT);
    a.bind(skip);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], ~0x0F0F0F0F0F0F0F0Full);
    CHECK_U64(ctx.r[vsl(REG_RCX)], 2);
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_ZF));
  }
  std::printf("  mutation      : %zu junk, %zu noise, %zu inverse (%zu store)\n",
              st.junk, st.noise, st.inv_r, st.inverted_stores);
}

extern "C" void hyda_vm_set_dispatch_profile(uint32_t index_mask,
                                            uint32_t key_variant,
                                            uint32_t base_variant,
                                            uint32_t entry_shift,
                                            uint32_t call_style,
                                            uint32_t crypt_variant);

static void test_dispatch_profiles() {
  Asm a;
  const size_t loop = a.label();
  a.i_rq(Op::MOV_RI, REG_RAX, 1);
  a.i_rq(Op::MOV_RI, REG_RDX, 25);
  a.i_rq(Op::MOV_RI, REG_RCX, 7);
  a.bind(loop);
  a.i_rr(Op::IMUL2, REG_RAX, REG_RCX);
  a.i_r(Op::DEC, REG_RDX);
  a.i_j(Op::JCC_NZ, loop);
  a.i0(Op::HALT);
  a.finalize();

  const uint64_t kMax = 100000;
  const uint64_t key = crypt_key_for(0x57100);

  VMContext ctx0;
  reset(ctx0, kMax);
  const uint32_t st0 = vm_exec(ctx0, a.code.data(), a.code.size());
  const uint64_t rax0 = ctx0.r[vsl(REG_RAX)];
  CHECK_EQ(st0, (int)ST_HALT);
  CHECK_TRUE(rax0 != 0);

  unsigned checked = 0;
  for (unsigned mask = 0; mask < 4; ++mask) {
    for (unsigned keyv = 0; keyv < 2; ++keyv) {
      for (unsigned basev = 0; basev < 4; ++basev) {
        for (unsigned shift = 3; shift <= 4; ++shift) {
          for (unsigned call = 0; call < 2; ++call) {
            for (unsigned cv = 0; cv < 2; ++cv) {
              const uint32_t m = (mask * 37u + 11u) & 0xFFu;
              hyda_vm_set_dispatch_profile(m, keyv, basev, shift, call, cv);

              std::vector<uint8_t> enc = a.code;
              crypt_operands_encrypt_v(enc.data(), enc.size(), key, cv);
              VMContext c;
              reset(c, kMax);
              const uint32_t st = vm_exec(c, enc.data(), enc.size(), key);
              if (st != st0 || c.r[vsl(REG_RAX)] != rax0) {
                CHECK_TRUE(false);
                return;
              }
              ++checked;
            }
          }
        }
      }
    }
  }
  CHECK_TRUE(checked >= 64);

  hyda_vm_set_dispatch_profile(0, 0, 0, 3, 0, 0);
  std::printf("  OK   dispatch profiles: %u combinations produced the same result\n",
              checked);
}

static void test_operand_crypt() {

  Asm a;
  const size_t loop = a.label();
  a.i_rq(Op::MOV_RI, REG_RAX, 1);
  a.i_rq(Op::MOV_RI, REG_RDX, 40);
  a.i_rq(Op::MOV_RI, REG_RCX, 7);
  a.bind(loop);
  a.i_rr(Op::IMUL2, REG_RAX, REG_RCX);
  a.i_r(Op::DEC, REG_RDX);
  a.i_j(Op::JCC_NZ, loop);
  a.i0(Op::HALT);
  a.finalize();

  const uint64_t kMax = 100000;

  VMContext ctx;
  reset(ctx, kMax);
  const uint32_t st_plain = vm_exec(ctx, a.code.data(), a.code.size());
  const uint64_t rax_plain = ctx.r[vsl(REG_RAX)];
  CHECK_EQ(st_plain, (int)ST_HALT);
  CHECK_TRUE(rax_plain != 0);

  const uint64_t key = crypt_key_for(0x57000);
  CHECK_TRUE(key != 0);

  CHECK_TRUE(crypt_key_for(0x57000) != crypt_key_for(0x58000));

  std::vector<uint8_t> enc = a.code;
  crypt_operands_encrypt(enc.data(), enc.size(), key);
  CHECK_TRUE(enc != a.code);

  VMContext ctx2;
  reset(ctx2, kMax);
  const uint32_t st_enc = vm_exec(ctx2, enc.data(), enc.size(), key);
  CHECK_EQ(st_enc, (int)st_plain);
  CHECK_EQ(ctx2.r[vsl(REG_RAX)], rax_plain);

  std::vector<uint8_t> wrong = enc;
  crypt_operands_decrypt(wrong.data(), wrong.size(), crypt_key_for(0x58000));
  std::vector<uint8_t> right = enc;
  crypt_operands_decrypt(right.data(), right.size(), key);
  CHECK_TRUE(right == a.code);
  CHECK_TRUE(wrong != a.code);
  CHECK_TRUE(wrong != right);

  std::vector<uint8_t> twice = a.code;
  crypt_operands_encrypt(twice.data(), twice.size(), key);
  const std::vector<uint8_t> once = twice;
  crypt_operands_encrypt(twice.data(), twice.size(), key);
  CHECK_TRUE(twice != a.code);
  std::vector<uint8_t> round = once;
  crypt_operands_decrypt(round.data(), round.size(), key);
  CHECK_TRUE(round == a.code);

  {
    const OpcodeMap& m = opcode_map();
    size_t vip = 0, at = 0;
    unsigned opsz = 0;
    while (vip < a.code.size()) {
      const uint16_t op = m.op_of_slot[bc_slot(a.code.data(), vip)];
      if (op == BAD_SLOT) break;
      const unsigned n = op_size(static_cast<Op>(op));
      if (n >= 2) { at = vip + kHeaderBytes; opsz = n; break; }
      vip += kHeaderBytes + n;
    }
    CHECK_TRUE(opsz >= 2);
    std::vector<uint8_t> p1 = a.code;
    crypt_operands_encrypt(p1.data(), p1.size(), key);
    std::vector<uint8_t> p2 = a.code;
    p2[at] = static_cast<uint8_t>(p2[at] ^ 0x01);
    crypt_operands_encrypt(p2.data(), p2.size(), key);
    unsigned changed_in = 0, changed_out = 0;
    for (size_t o = 0; o < p1.size(); ++o) {
      const bool in = (o >= at && o < at + opsz);
      if (p1[o] != p2[o]) { if (in) ++changed_in; else ++changed_out; }
    }
    CHECK_EQ(changed_in, opsz);
    CHECK_EQ(changed_out, 0);
  }

  std::vector<uint8_t> off = a.code;
  crypt_operands_encrypt(off.data(), off.size(), 0);
  CHECK_TRUE(off == a.code);
}

static void test_codec() {
  std::printf("\n[8t] opcode encoding v2 (tableless, 2 bytes, position-bound)\n");

  {
    unsigned bad = 0;
    for (unsigned k = 0; k < 256; ++k) {
      for (unsigned v = 0; v < 256; ++v) {
        const uint8_t r = codec_mix8(static_cast<uint8_t>(v),
                                     static_cast<uint8_t>(k));
        if (codec_unmix8(r, static_cast<uint8_t>(k)) != static_cast<uint8_t>(v)) {
          ++bad;
        }
      }
    }
    CHECK_EQ(bad, 0u);
    for (unsigned k = 0; k < 256; k += 17) {
      bool seen[256] = {};
      for (unsigned v = 0; v < 256; ++v) {
        seen[codec_mix8(static_cast<uint8_t>(v), static_cast<uint8_t>(k))] = true;
      }
      unsigned n = 0;
      for (unsigned i = 0; i < 256; ++i) n += seen[i] ? 1u : 0u;
      CHECK_EQ(n, 256u);
    }
  }

  const uint64_t key = crypt_key_for(0x8A000);
  CodecKey ck;
  codec_init(ck, detail::codec_stream_key(key, 0));

  {
    const uint64_t z = crypt_mix(0x1234, key);
    const CodecMask m = codec_mask(ck, z);
    const uint16_t slot = 42;
    const uint8_t xl = static_cast<uint8_t>((slot & 0xFFu) ^ m.fb);
    const uint8_t h0 = static_cast<uint8_t>(codec_unmix8(xl, m.ka) ^ m.rol);
    unsigned ok = 0;
    for (unsigned f = 0; f < 64; ++f) {
      const uint8_t y =
          static_cast<uint8_t>(((slot >> 8) & 0x03u) | (f << 2));
      const uint8_t h1 = codec_unmix8(y, m.kb);
      if (codec_decode(ck, h0, h1, z) == slot) ++ok;
    }
    CHECK_EQ(ok, 64u);
  }

  {
    unsigned distinct = 0;
    bool seen[256] = {};
    for (unsigned ip = 0; ip < 512; ++ip) {
      uint32_t rnd = 0x1234567u;
      uint8_t h0 = 0, h1 = 0;
      codec_encode(ck, 7, crypt_mix(ip, key), rnd, &h0, &h1);
      seen[h1] = true;
    }
    for (unsigned i = 0; i < 256; ++i) distinct += seen[i] ? 1u : 0u;
    CHECK_TRUE(distinct >= 200);
  }

  {
    CodecKey ck2;
    codec_init(ck2, detail::codec_stream_key(crypt_key_for(0x8B000), 0));
    const uint64_t z = crypt_mix(0x40, key);
    uint8_t a0 = 0, a1 = 0, b0 = 0, b1 = 0;
    uint32_t r1 = 5, r2 = 5;
    codec_encode(ck, 3, z, r1, &a0, &a1);
    codec_encode(ck2, 3, z, r2, &b0, &b1);
    CHECK_TRUE(codec_decode(ck, a0, a1, z) == 3);
    CHECK_TRUE(codec_decode(ck2, b0, b1, z) == 3);
    CHECK_TRUE(a0 != b0 || a1 != b1);
  }

  {
    const uint64_t z = crypt_mix(0x99, key);
    uint8_t h0 = 0, h1 = 0;
    uint32_t rnd = 0xABCDEF01u;
    codec_encode(ck, 200, z, rnd, &h0, &h1);
    unsigned h0_changed = 0;
    for (unsigned bit = 0; bit < 8; ++bit) {
      const uint8_t a = static_cast<uint8_t>(h0 ^ (1u << bit));
      if (codec_decode(ck, a, h1, z) != 200) ++h0_changed;
    }
    CHECK_EQ(h0_changed, 8u);
    unsigned h1_effective = 0;
    for (unsigned bit = 0; bit < 8; ++bit) {
      const uint8_t b = static_cast<uint8_t>(h1 ^ (1u << bit));
      if (codec_decode(ck, h0, b, z) != 200) ++h1_effective;
    }
    CHECK_TRUE(h1_effective >= 1);
  }

  {
    Asm a;
    const size_t loop = a.label();
    a.i_rq(Op::MOV_RI, REG_RAX, 1);
    a.i_rq(Op::MOV_RI, REG_RCX, 3);
    a.bind(loop);
    a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
    a.i_r(Op::DEC, REG_RCX);
    a.i_j(Op::JCC_NZ, loop);
    a.i0(Op::HALT);
    a.finalize();

    std::vector<uint8_t> enc = a.code;
    crypt_operands_encrypt(enc.data(), enc.size(), key);
    CHECK_TRUE(enc != a.code);

    std::vector<uint8_t> enc2 = a.code;
    crypt_operands_encrypt(enc2.data(), enc2.size(), key);
    CHECK_TRUE(enc == enc2);

    std::vector<uint8_t> dec = enc;
    crypt_operands_decrypt(dec.data(), dec.size(), key);
    CHECK_TRUE(dec == a.code);

    VMContext c1;
    reset(c1, 100000);
    CHECK_EQ(vm_exec(c1, enc.data(), enc.size(), key), (int)ST_HALT);
    VMContext c0;
    reset(c0, 100000);
    CHECK_EQ(vm_exec(c0, a.code.data(), a.code.size(), 0), (int)ST_HALT);
    CHECK_EQ(c1.r[vsl(REG_RAX)], c0.r[vsl(REG_RAX)]);

    std::FILE* fa = std::tmpfile();
    std::FILE* fb = std::tmpfile();
    if (fa != nullptr && fb != nullptr) {
      disasm(a.code.data(), a.code.size(), fa);
      disasm_encrypted(enc.data(), enc.size(), key, 0, fb);
      std::rewind(fa);
      std::rewind(fb);
      char ba[1024] = {};
      char bb[1024] = {};
      const size_t na = std::fread(ba, 1, sizeof(ba) - 1, fa);
      const size_t nb = std::fread(bb, 1, sizeof(bb) - 1, fb);
      CHECK_EQ(na, nb);
      CHECK_TRUE(na != 0);
      CHECK_TRUE(std::memcmp(ba, bb, na) == 0);
      std::fclose(fa);
      std::fclose(fb);
    }
  }

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 1);
    a.i_rq(Op::MOV_RI, REG_RCX, 2);
    a.i0(Op::HALT);
    a.finalize();
    size_t ninstr = 0, off = 0;
    while (off < a.code.size()) {
      const uint16_t op = opcode_map().op_of_slot[bc_slot(a.code.data(), off)];
      CHECK_TRUE(op != BAD_SLOT);
      off += kHeaderBytes + op_size(static_cast<Op>(op));
      ++ninstr;
    }
    CHECK_EQ(ninstr, 3u);
    CHECK_EQ(a.code.size(), ninstr * kHeaderBytes + 9u + 9u + 0u);
    std::vector<uint8_t> enc = a.code;
    crypt_operands_encrypt(enc.data(), enc.size(), key);
    CHECK_EQ(enc.size(), a.code.size());
  }

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 11);
    a.i0(Op::HALT);
    a.finalize();
    std::vector<uint8_t> noisy = a.code;
    for (size_t off = 0; off < noisy.size();) {
      const uint16_t op = opcode_map().op_of_slot[bc_slot(noisy.data(), off)];
      CHECK_TRUE(op != BAD_SLOT);
      off += kHeaderBytes + op_size(static_cast<Op>(op));
    }
    VMContext c;
    reset(c, 100);
    CHECK_EQ(vm_exec(c, noisy.data(), noisy.size(), 0), (int)ST_HALT);
    CHECK_EQ(c.r[vsl(REG_RAX)], 11u);
  }
}

static void test_dead_flags() {

  const uint64_t seed_flags = 0x202ull | (1ull << F_ZF) | (1ull << F_CF) |
                             (1ull << F_AF);
  {
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RFLAGS, static_cast<int64_t>(seed_flags));
    a.i_rq(Op::MOV_RI, REG_RAX, 100);
    a.i_rq(Op::MOV_RI, REG_RCX, 200);
    a.i_rr(Op::ADD64_NF, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 300);
    CHECK_U64(ctx.r[vsl(REG_RFLAGS)], seed_flags);
  }
  {

    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RFLAGS, static_cast<int64_t>(seed_flags));
    a.i_rq(Op::MOV_RI, REG_RAX, 100);
    a.i_rq(Op::MOV_RI, REG_RCX, 200);
    a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 300);
    CHECK_TRUE(ctx.r[vsl(REG_RFLAGS)] != seed_flags);
    CHECK_TRUE((ctx.r[vsl(REG_RFLAGS)] & (1ull << F_CF)) == 0);
  }
  {

    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RFLAGS, static_cast<int64_t>(seed_flags));
    a.i_rq(Op::MOV_RI, REG_RAX, 0x1234);
    a.i_rq(Op::MOV_RI, REG_RCX, 0x00FF);
    a.i_rr(Op::ADD8_NF, REG_RAX, REG_RCX);
    a.i_r(Op::INC64_NF, REG_RCX);
    a.i_r(Op::NEG64_NF, REG_RDX);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RAX)], 0x1233);
    CHECK_U64(ctx.r[vsl(REG_RCX)], 0x100);
    CHECK_U64(ctx.r[vsl(REG_RDX)], 0);
    CHECK_U64(ctx.r[vsl(REG_RFLAGS)], seed_flags);
  }

  auto dead = [](std::vector<IRCommand>& c, size_t i) {
    return (c[i].flags & IRF_NO_FLAGS) != 0;
  };
  auto alu = [](AluOp k, int d, int s) {
    return IRCommand::alu(k, IROperand::R(d), IROperand::R(s));
  };
  {

    std::vector<IRCommand> c = {alu(AluOp::Cmp, 0, 1),
                                IRCommand::br(IROp::Jcc, 0)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(!dead(c, 0));
  }
  {

    std::vector<IRCommand> c = {alu(AluOp::Cmp, 0, 1), alu(AluOp::Add, 2, 3)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(dead(c, 0));
    CHECK_TRUE(!dead(c, 1));
  }
  {

    std::vector<IRCommand> c = {alu(AluOp::Add, 0, 1),
                                IRCommand::mov(IROperand::R(2), IROperand::R(3)),
                                alu(AluOp::Sub, 4, 5)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(dead(c, 0));
    CHECK_TRUE(!dead(c, 1));
  }
  {

    std::vector<IRCommand> c = {IRCommand::unary(UnaryOp::Inc, 0),
                                alu(AluOp::And, 1, 2)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(!dead(c, 0));
  }
  {

    std::vector<IRCommand> c = {alu(AluOp::Add, 0, 1), alu(AluOp::And, 2, 3)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(!dead(c, 0));
  }
  {

    std::vector<IRCommand> c = {alu(AluOp::And, 0, 1), alu(AluOp::Add, 2, 3)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(dead(c, 0));
  }
  {

    std::vector<IRCommand> c = {IRCommand::unary(UnaryOp::Inc, 0),
                                alu(AluOp::Add, 1, 2)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(dead(c, 0));
  }
  {

    std::vector<IRCommand> c = {alu(AluOp::Add, 0, 1),
                                IRCommand::shift(ShiftOp::Shl, 2, 1)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(!dead(c, 0));
    std::vector<IRCommand> d = {IRCommand::shift(ShiftOp::Shl, 2, 1),
                                alu(AluOp::Add, 0, 1)};
    ir_mark_dead_flags(d);
    CHECK_TRUE(dead(d, 0));
  }
  {

    std::vector<IRCommand> c = {alu(AluOp::Add, 0, 1), IRCommand::br(IROp::Ret, -1)};
    ir_mark_dead_flags(c);
    CHECK_TRUE(!dead(c, 0));
    std::vector<IRCommand> d = {alu(AluOp::Add, 0, 1),
                                IRCommand::none(IROp::Pushf), alu(AluOp::Sub, 2, 3)};
    ir_mark_dead_flags(d);
    CHECK_TRUE(!dead(d, 0));
    std::vector<IRCommand> e = {alu(AluOp::Add, 0, 1),
                                IRCommand::none(IROp::Popf), alu(AluOp::Sub, 2, 3)};
    ir_mark_dead_flags(e);
    CHECK_TRUE(dead(e, 0));
  }

  {

    IRProgram p;
    p.cmds.push_back(alu(AluOp::Add, REG_RAX, REG_RCX));
    p.cmds.push_back(alu(AluOp::Sub, REG_RAX, REG_RDX));
    p.cmds.push_back(IRCommand::none(IROp::Halt));
    p.entry_cmd = 0;
    Asm out;
    CodegenResult r = ir_codegen(p, out);
    CHECK_TRUE(r.ok);
    const OpcodeMap& m = opcode_map();

    CHECK_TRUE(!out.code.empty());
    CHECK_EQ((int)m.op_of_slot[bc_slot(out.code.data(), 0)], (int)Op::ADD64_NF);
    const size_t second = kHeaderBytes + op_size(Op::ADD64_NF);

    const Op sub = static_cast<Op>(m.op_of_slot[bc_slot(out.code.data(), second)]);
    CHECK_TRUE(sub == Op::SUB64 || sub == Op::SUB64_B || sub == Op::SUB64_B2 || sub == Op::SUB64_B3);
  }
  {

    IRProgram p;
    p.cmds.push_back(alu(AluOp::Cmp, REG_RAX, REG_RCX));
    p.cmds.push_back(alu(AluOp::Sub, REG_RAX, REG_RDX));
    p.cmds.push_back(IRCommand::none(IROp::Halt));
    p.entry_cmd = 0;
    Asm out;
    CodegenResult r = ir_codegen(p, out);
    CHECK_TRUE(r.ok);
    const OpcodeMap& m = opcode_map();
    const Op sub = static_cast<Op>(m.op_of_slot[bc_slot(out.code.data(), 0)]);
    CHECK_TRUE(sub == Op::SUB64 || sub == Op::SUB64_B || sub == Op::SUB64_B2 || sub == Op::SUB64_B3);
  }
  {

    IRProgram p;
    const int L = p.new_label();
    p.cmds.push_back(alu(AluOp::Cmp, REG_RAX, REG_RCX));
    p.cmds.push_back(IRCommand::br(IROp::Jcc, L));
    p.cmds.push_back(IRCommand::none(IROp::Halt));
    p.bind_at(L, 2);
    p.entry_cmd = 0;
    Asm out;
    CodegenResult r = ir_codegen(p, out);
    CHECK_TRUE(r.ok);
    const OpcodeMap& m = opcode_map();
    CHECK_EQ((int)m.op_of_slot[bc_slot(out.code.data(), 0)], (int)Op::CMP64);
  }

  for (size_t i = 0; i < OP_COUNT; ++i) {
    const Op base = static_cast<Op>(i);
    const Op nf = nf_variant(base);
    if (nf == base) continue;
    g_rep->check(std::memcmp(&OP_SIGS[i], &OP_SIGS[static_cast<size_t>(nf)],
                             sizeof(Sig)) == 0,
                 "nf_variant keeps the same operand signature", __FILE__, __LINE__);
    CHECK_TRUE(nf_variant(nf) == nf);
  }
}

static uint64_t test_rng(uint64_t& s) {
  s ^= s << 13;
  s ^= s >> 7;
  s ^= s << 17;
  return s;
}

static void test_mba_identities() {
  static const uint64_t edge[] = {
      0ull, 1ull, 2ull, 3ull, 0x7Full, 0x80ull, 0xFFull, 0x100ull,
      0x7FFFull, 0x8000ull, 0xFFFFull, 0x7FFFFFFFull, 0x80000000ull,
      0xFFFFFFFFull, 0x7FFFFFFFFFFFFFFFull, 0x8000000000000000ull,
      0xFFFFFFFFFFFFFFFFull, 0x0123456789ABCDEFull, 0xFEDCBA9876543210ull,
      0xAAAAAAAAAAAAAAAAull, 0x5555555555555555ull};
  const size_t ne = sizeof(edge) / sizeof(edge[0]);
  for (size_t i = 0; i < ne; ++i) {
    for (size_t j = 0; j < ne; ++j) {
      const uint64_t a = edge[i], b = edge[j];
      CHECK_U64(mba_add(a, b), a + b);
      CHECK_U64(mba_sub(a, b), a - b);
      CHECK_U64(mba_and(a, b), a & b);
      CHECK_U64(mba_or(a, b), a | b);
      CHECK_U64(mba_xor(a, b), a ^ b);
    }
  }

  uint64_t s = 0x51ED2701B3F4A9C7ull;
  uint64_t mism = 0;
  for (int i = 0; i < 500000; ++i) {
    const uint64_t a = test_rng(s), b = test_rng(s);
    mism += (mba_add(a, b) != a + b) ? 1u : 0u;
    mism += (mba_sub(a, b) != a - b) ? 1u : 0u;
    mism += (mba_and(a, b) != (a & b)) ? 1u : 0u;
    mism += (mba_or(a, b) != (a | b)) ? 1u : 0u;
    mism += (mba_xor(a, b) != (a ^ b)) ? 1u : 0u;
  }
  CHECK_EQ(mism, 0);

  CHECK_TRUE(mba_add(0x100, 0x23) == 0x123);
  CHECK_TRUE(mba_sub(0x100, 0x23) != mba_add(0x100, 0x23));

  VMContext c;
  reset(c);
  for (int i = 0; i < 64; ++i) {
    c.status = (i % 2 == 0) ? 0u : static_cast<uint32_t>(ST_FAULT);
    const uint64_t a = test_rng(s), b = test_rng(s);
    CHECK_U64(mba_opaque(c, mba_add(a, b), a + b), a + b);
    CHECK_U64(mba_opaque(c, mba_sub(a, b), a - b), a - b);
  }
  c.status = 0;
}

static void run_bin_op(Op op, uint64_t x, uint64_t y, uint64_t* val,
                       uint64_t* flags, uint32_t* st) {
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, x);
  a.i_rq(Op::MOV_RI, REG_RCX, y);
  a.i_rr(op, REG_RAX, REG_RCX);
  a.i0(Op::HALT);
  VMContext c;
  *st = run(c, a);
  *val = c.r[vsl(REG_RAX)];
  *flags = c.r[vsl(REG_RFLAGS)];
}

static void run_un_op(Op op, uint64_t x, uint64_t* val, uint64_t* flags,
                      uint32_t* st) {
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, x);
  a.i_r(op, REG_RAX);
  a.i0(Op::HALT);
  VMContext c;
  *st = run(c, a);
  *val = c.r[vsl(REG_RAX)];
  *flags = c.r[vsl(REG_RFLAGS)];
}

static void test_mba_bodies() {
  struct Pair {
    Op plain;
    Op variant;
    bool unary;
  };
  static const Pair pairs[] = {
      {Op::ADD32, Op::ADD32_B, false}, {Op::ADD64, Op::ADD64_B, false},
      {Op::SUB32, Op::SUB32_B, false}, {Op::SUB64, Op::SUB64_B, false},
      {Op::AND32, Op::AND32_B, false}, {Op::AND64, Op::AND64_B, false},
      {Op::OR32, Op::OR32_B, false},   {Op::OR64, Op::OR64_B, false},
      {Op::XOR32, Op::XOR32_B, false}, {Op::XOR64, Op::XOR64_B, false},
      {Op::INC, Op::INC_B, true},
      {Op::DEC32, Op::DEC32_B, true},  {Op::DEC, Op::DEC_B, true}};

  uint64_t s = 0x8F3A5C71D2E6B904ull;
  uint64_t val_diff = 0, flag_diff = 0, st_diff = 0;
  for (const Pair& p : pairs) {
    for (int it = 0; it < 256; ++it) {
      const uint64_t x = test_rng(s);
      const uint64_t y = test_rng(s);
      uint64_t v1 = 0, v2 = 0, f1 = 0, f2 = 0;
      uint32_t s1 = 0, s2 = 0;
      if (p.unary) {
        run_un_op(p.plain, x, &v1, &f1, &s1);
        run_un_op(p.variant, x, &v2, &f2, &s2);
      } else {
        run_bin_op(p.plain, x, y, &v1, &f1, &s1);
        run_bin_op(p.variant, x, y, &v2, &f2, &s2);
      }
      val_diff += (v1 != v2) ? 1u : 0u;
      flag_diff += (f1 != f2) ? 1u : 0u;
      st_diff += (s1 != s2) ? 1u : 0u;
    }
  }
  CHECK_EQ(val_diff, 0);
  CHECK_EQ(flag_diff, 0);
  CHECK_EQ(st_diff, 0);

  static const Pair pairs2[] = {
      {Op::ADD32, Op::ADD32_B2, false}, {Op::ADD64, Op::ADD64_B2, false},
      {Op::SUB32, Op::SUB32_B2, false}, {Op::SUB64, Op::SUB64_B2, false},
      {Op::AND32, Op::AND32_B2, false}, {Op::AND64, Op::AND64_B2, false},
      {Op::OR32, Op::OR32_B2, false},   {Op::OR64, Op::OR64_B2, false},
      {Op::XOR32, Op::XOR32_B2, false}, {Op::XOR64, Op::XOR64_B2, false},
      {Op::INC, Op::INC_B2, true},
      {Op::DEC32, Op::DEC32_B2, true},  {Op::DEC, Op::DEC_B2, true}};
  uint64_t vd2 = 0, fd2 = 0, sd2 = 0;
  for (const Pair& p : pairs2) {
    for (int it = 0; it < 256; ++it) {
      const uint64_t x = test_rng(s);
      const uint64_t y = test_rng(s);
      uint64_t v1 = 0, v2 = 0, f1 = 0, f2 = 0;
      uint32_t s1 = 0, s2 = 0;
      if (p.unary) {
        run_un_op(p.plain, x, &v1, &f1, &s1);
        run_un_op(p.variant, x, &v2, &f2, &s2);
      } else {
        run_bin_op(p.plain, x, y, &v1, &f1, &s1);
        run_bin_op(p.variant, x, y, &v2, &f2, &s2);
      }
      vd2 += (v1 != v2) ? 1u : 0u;
      fd2 += (f1 != f2) ? 1u : 0u;
      sd2 += (s1 != s2) ? 1u : 0u;
    }
  }
  CHECK_EQ(vd2, 0);
  CHECK_EQ(fd2, 0);
  CHECK_EQ(sd2, 0);

  static const Pair pairs3[] = {
      {Op::ADD32, Op::ADD32_B3, false}, {Op::ADD64, Op::ADD64_B3, false},
      {Op::SUB32, Op::SUB32_B3, false}, {Op::SUB64, Op::SUB64_B3, false},
      {Op::AND32, Op::AND32_B3, false}, {Op::AND64, Op::AND64_B3, false},
      {Op::OR32, Op::OR32_B3, false},   {Op::OR64, Op::OR64_B3, false},
      {Op::XOR32, Op::XOR32_B3, false}, {Op::XOR64, Op::XOR64_B3, false},
      {Op::INC, Op::INC_B3, true},
      {Op::DEC32, Op::DEC32_B3, true},  {Op::DEC, Op::DEC_B3, true}};
  uint64_t vd3 = 0, fd3 = 0, sd3 = 0;
  for (const Pair& p : pairs3) {
    for (int it = 0; it < 256; ++it) {
      const uint64_t x = test_rng(s);
      const uint64_t y = test_rng(s);
      uint64_t v1 = 0, v2 = 0, f1 = 0, f2 = 0;
      uint32_t s1 = 0, s2 = 0;
      if (p.unary) {
        run_un_op(p.plain, x, &v1, &f1, &s1);
        run_un_op(p.variant, x, &v2, &f2, &s2);
      } else {
        run_bin_op(p.plain, x, y, &v1, &f1, &s1);
        run_bin_op(p.variant, x, y, &v2, &f2, &s2);
      }
      vd3 += (v1 != v2) ? 1u : 0u;
      fd3 += (f1 != f2) ? 1u : 0u;
      sd3 += (s1 != s2) ? 1u : 0u;
    }
  }
  CHECK_EQ(vd3, 0);
  CHECK_EQ(fd3, 0);
  CHECK_EQ(sd3, 0);

  uint64_t v = 0, f = 0;
  uint32_t st = 0;
  run_bin_op(Op::SUB64_B, 0, 0, &v, &f, &st);
  CHECK_TRUE(flag_bit(f, 6));
  CHECK_TRUE(!flag_bit(f, 0));
  run_bin_op(Op::SUB64_B, 0, 1, &v, &f, &st);
  CHECK_TRUE(flag_bit(f, 0));
  CHECK_U64(v, ~0ull);
}

static void test_body_split() {
  IRProgram p;

  for (int i = 0; i < 24; ++i) {
    p.cmds.push_back(IRCommand::alu(AluOp::And, IROperand::R(REG_RAX),
                                    IROperand::R(REG_RCX)));
    const int L = p.new_label();
    IRCommand j = IRCommand::br(IROp::Jcc, L);
    j.sub = 5;
    p.cmds.push_back(j);
    p.bind(L);
  }
  p.cmds.push_back(IRCommand::none(IROp::Halt));
  p.entry_cmd = 0;

  Asm out;
  const CodegenResult r = ir_codegen(p, out);
  CHECK_TRUE(r.ok);

  bool seen_plain = false, seen_b = false, seen_b2 = false;
  const OpcodeMap& m = opcode_map();
  size_t off = 0;
  while (off < out.code.size()) {
    const uint16_t op = m.op_of_slot[bc_slot(out.code.data(), off)];
    if (op == static_cast<uint16_t>(Op::AND64)) seen_plain = true;
    else if (op == static_cast<uint16_t>(Op::AND64_B)) seen_b = true;
    else if (op == static_cast<uint16_t>(Op::AND64_B2)) seen_b2 = true;
    off += kHeaderBytes + op_size(static_cast<Op>(op));
  }
  const int distinct = (seen_plain ? 1 : 0) + (seen_b ? 1 : 0) + (seen_b2 ? 1 : 0);
  CHECK_TRUE(distinct >= 2);
  CHECK_TRUE(r.body_variant_count > 0);
}

static void test_vm2_core() {
  vm2_build();

  int used = 0;
  for (int i = 0; i < 256; ++i) {
    if (hyda_vm2_map[i] != 0xFF) ++used;
  }
  CHECK_EQ(used, (int)kV2Count);
  bool seen[256] = {};
  for (size_t op = 0; op < kV2Count; ++op) {
    const uint8_t slot = hyda_vm2_slot[op];
    CHECK_TRUE(!seen[slot]);
    seen[slot] = true;
    CHECK_EQ((int)hyda_vm2_map[slot], (int)op);
  }

  const OpcodeMap& m1 = opcode_map();
  CHECK_TRUE(hyda_vm2_slot[static_cast<size_t>(V2::ADD)] !=
             m1.slot_of_op[static_cast<size_t>(Op::ADD64)]);
  CHECK_TRUE(hyda_vm2_slot[static_cast<size_t>(V2::XOR)] !=
             m1.slot_of_op[static_cast<size_t>(Op::XOR64)]);

  auto run_prog = [](const V2Insn* ins, size_t n, uint64_t a, uint64_t b,
                     uint64_t* out, uint32_t* st) {
    uint8_t buf[320];
    const uint32_t len = vm2_encode(ins, n, buf, sizeof(buf));
    Vm2Context c{};
    for (unsigned i = 0; i < kV2Regs; ++i) c.r[i] = 0;
    c.r[0] = a;
    c.r[1] = b;
    *st = (len == 0) ? 1u : vm2_run(c, buf, len);
    *out = c.r[0];
  };

  uint64_t a = 0x123456789ABCDEF0ull, b = 0x0FEDCBA987654321ull, v = 0;
  uint32_t st = 0;
  {
    const V2Insn ins[] = {{V2::MOV_RR, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_EQ((int)st, (int)V2_OK);
    CHECK_U64(v, b);
  }
  {
    const V2Insn ins[] = {{V2::MOV_RI, 2, 0, 0xDEADBEEFCAFEBABEull},
                          {V2::MOV_RR, 0, 2},
                          {V2::HALT, 0, 0}};
    run_prog(ins, 3, a, b, &v, &st);
    CHECK_EQ((int)st, (int)V2_OK);
    CHECK_U64(v, 0xDEADBEEFCAFEBABEull);
  }
  {
    const V2Insn ins[] = {{V2::ADD, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a + b);
  }
  {
    const V2Insn ins[] = {{V2::SUB, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a - b);
  }
  {
    const V2Insn ins[] = {{V2::XOR, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a ^ b);
  }
  {
    const V2Insn ins[] = {{V2::AND, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a & b);
  }
  {
    const V2Insn ins[] = {{V2::OR, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a | b);
  }
  {
    const V2Insn ins[] = {{V2::MUL, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a * b);
  }
  {
    const V2Insn ins[] = {{V2::NOT, 0, 0}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, ~a);
  }
  {
    const V2Insn ins[] = {{V2::SHL, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, 5, &v, &st);
    CHECK_U64(v, a << 5);
  }
  {
    const V2Insn ins[] = {{V2::SHR, 0, 1}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, 5, &v, &st);
    CHECK_U64(v, a >> 5);
  }
  {
    const V2Insn ins[] = {{V2::NOP, 0, 0}, {V2::HALT, 0, 0}};
    run_prog(ins, 2, a, b, &v, &st);
    CHECK_U64(v, a);
  }

  {
    Vm2Context c{};
    CHECK_EQ((int)vm2_run(c, nullptr, 0), (int)V2_BAD_LEN);
  }
  {

    const V2Insn ins[] = {{V2::HALT, 0, 0}};
    uint8_t buf[64];
    const uint32_t len = vm2_encode(ins, 1, buf, sizeof(buf));
    CHECK_EQ((int)len, 12);
    Vm2Context c{};
    CHECK_EQ((int)vm2_run(c, buf, 13), (int)V2_BAD_LEN);
  }
  {

    const V2Insn ins[] = {{V2::NOP, 0, 0}};
    uint8_t buf[64];
    const uint32_t len = vm2_encode(ins, 1, buf, sizeof(buf));
    Vm2Context c{};
    CHECK_EQ((int)vm2_run(c, buf, len), (int)V2_NO_HALT);
  }
  {

    uint8_t bad = 0;
    while (bad < 255 && hyda_vm2_map[bad] != 0xFF) ++bad;
    CHECK_EQ((int)hyda_vm2_map[bad], 0xFF);
    const V2Insn ins[] = {{V2::HALT, 0, 0}};
    uint8_t buf[64];
    const uint32_t len = vm2_encode(ins, 1, buf, sizeof(buf));
    CHECK_EQ((int)len, 12);
    buf[0] = bad;
    Vm2Context c{};
    CHECK_EQ((int)vm2_run(c, buf, len), (int)V2_BAD_SLOT);
  }
  {

    const V2Insn ins[] = {{V2::ADD, 0, 1}, {V2::HALT, 0, 0}};
    uint8_t buf[64];
    const uint32_t len = vm2_encode(ins, 2, buf, sizeof(buf));
    CHECK_EQ((int)len, 24);
    buf[1] = 9;
    Vm2Context c{};
    CHECK_EQ((int)vm2_run(c, buf, len), (int)V2_BAD_REG);
  }

  static const uint64_t edge[] = {0ull, 1ull, 2ull, 0x7Full, 0x80ull,
                                  0xFFFFFFFFFFFFFFFFull,
                                  0x8000000000000000ull,
                                  0x7FFFFFFFFFFFFFFFull,
                                  0x0123456789ABCDEFull};
  const size_t ne = sizeof(edge) / sizeof(edge[0]);
  uint64_t s = 0xC0FFEE1234567890ull;
  for (unsigned id = 0; id < kV2ProgCount; ++id) {
    for (unsigned form = 0; form < 2; ++form) {
      uint8_t buf[192];
      const uint32_t len = vm2_make_program(id, form, buf, sizeof(buf));
      CHECK_TRUE(len > 0 && (len % 12) == 0);
      for (size_t i = 0; i < ne; ++i) {
        for (size_t j = 0; j < ne; ++j) {
          Vm2Context c{};
          for (unsigned r = 0; r < kV2Regs; ++r) c.r[r] = 0;
          c.r[0] = edge[i];
          c.r[1] = edge[j];
          const uint32_t rc = vm2_run(c, buf, len);
          CHECK_EQ((int)rc, (int)V2_OK);
          const uint64_t want = (id == kV2ProgAdd)
                                    ? edge[i] + edge[j]
                                    : (id == kV2ProgSub ? edge[i] - edge[j]
                                                        : edge[i] ^ edge[j]);
          CHECK_U64(c.r[0], want);
        }
      }

      uint64_t mism = 0;
      for (int k = 0; k < 20000; ++k) {
        const uint64_t x = test_rng(s), y = test_rng(s);
        Vm2Context c{};
        for (unsigned r = 0; r < kV2Regs; ++r) c.r[r] = 0;
        c.r[0] = x;
        c.r[1] = y;
        if (vm2_run(c, buf, len) != V2_OK) { ++mism; continue; }
        const uint64_t want = (id == kV2ProgAdd)
                                  ? x + y
                                  : (id == kV2ProgSub ? x - y : x ^ y);
        mism += (c.r[0] != want) ? 1u : 0u;
      }
      CHECK_EQ(mism, 0);
    }
  }

  for (unsigned id = 0; id < kV2ProgCount; ++id) {
    CHECK_TRUE(hyda_vm2_len[id] > 0);
    uint64_t out = 0;
    CHECK_EQ((int)vm2_eval(id, 0x1234, 0x00FF, &out), (int)V2_OK);
  }
  CHECK_TRUE(hyda_vm2_runs > 0);
}

static void test_instance_seed() {

  const uint64_t saved = ::g_vm_seed;
  hyda::opmap_rebuild();

  const OpcodeMap& m0 = hyda::opcode_map();
  for (size_t op = 0; op < OP_COUNT; ++op) {
    CHECK_EQ((int)m0.op_of_slot[m0.slot_of_op[op]], (int)op);
  }
  uint16_t base_slots[OP_COUNT];
  std::memcpy(base_slots, m0.slot_of_op, sizeof(base_slots));

  ::g_vm_seed = 0xA1B2C3D4E5F60718ull;
  const OpcodeMap& m1 = hyda::opcode_map();
  unsigned diff = 0;
  unsigned used = 0;
  for (size_t op = 0; op < OP_COUNT; ++op) {
    CHECK_EQ((int)m1.op_of_slot[m1.slot_of_op[op]], (int)op);
    CHECK_TRUE(m1.slot_of_op[op] < kSlotCount);
    if (m1.slot_of_op[op] != base_slots[op]) ++diff;
  }
  for (size_t s = 0; s < kSlotCount; ++s) {
    if (m1.op_of_slot[s] != BAD_SLOT) ++used;
  }
  CHECK_EQ(used, static_cast<unsigned>(OP_COUNT));
  CHECK_TRUE(diff > OP_COUNT / 2);

  const DispatchProfile p = ::g_dispatch_profile;
  hyda_vm_set_dispatch_profile(p.index_mask, p.key_variant, p.base_variant,
                               p.entry_shift, p.call_style, p.crypt_variant);
  VMContext ctx;
  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 7);
  a.i_rq(Op::MOV_RI, REG_RCX, 35);
  a.i_rr(Op::IMUL2, REG_RAX, REG_RCX);
  a.i0(Op::HALT);
  CHECK_EQ(run(ctx, a), (int)ST_HALT);
  CHECK_U64(ctx.r[vsl(REG_RAX)], 245);

  ::g_vm_seed = saved;
  const uint64_t k1 = hyda::crypt_key_for(0x1000);
  const uint64_t h1 = hyda::hydak_key_for(0x2000);
  const uint64_t i1 = hyda::integrity_key_for(0x33, 0x4000);
  ::g_vm_seed = 0xA1B2C3D4E5F60718ull;
  CHECK_TRUE(hyda::crypt_key_for(0x1000) != k1);
  CHECK_TRUE(hyda::hydak_key_for(0x2000) != h1);
  CHECK_TRUE(hyda::integrity_key_for(0x33, 0x4000) != i1);
  CHECK_TRUE(hyda::island_key_for(0x11, 0x5000) != 0);

  ::g_vm_seed = saved;
  hyda::opmap_rebuild();
  hyda_vm_set_dispatch_profile(p.index_mask, p.key_variant, p.base_variant,
                               p.entry_shift, p.call_style, p.crypt_variant);
}

static void test_nested_vm() {

  const Op pick = nested_op(kCodegenSeed);
  CHECK_TRUE(pick == Op::ADD64 || pick == Op::SUB64 || pick == Op::XOR64);
  CHECK_TRUE(nested_variant(pick) != pick);
  CHECK_TRUE(nested_variant(Op::ADD32) == Op::ADD32);

  AluOp sub = AluOp::Add;
  if (pick == Op::SUB64) sub = AluOp::Sub;
  else if (pick == Op::XOR64) sub = AluOp::Xor;
  {
    IRProgram p;
    p.cmds.push_back(IRCommand::alu(sub, IROperand::R(REG_RAX),
                                    IROperand::R(REG_RCX)));
    p.cmds.push_back(IRCommand::none(IROp::Halt));
    p.entry_cmd = 0;
    Asm out;
    CodegenResult r = ir_codegen(p, out);
    CHECK_TRUE(r.ok);
    CHECK_EQ((int)r.nested_count, 1);
    const OpcodeMap& m = opcode_map();
    CHECK_TRUE(!out.code.empty());
    CHECK_EQ((int)m.op_of_slot[bc_slot(out.code.data(), 0)], (int)nested_variant(pick));
  }

  struct Pair {
    Op plain;
    Op nested;
  };
  static const Pair pairs[] = {{Op::ADD64, Op::ADD64_N},
                               {Op::SUB64, Op::SUB64_N},
                               {Op::XOR64, Op::XOR64_N}};
  uint64_t s = 0x8F3A5C71D2E6B904ull;
  uint64_t val_diff = 0, flag_diff = 0, st_diff = 0;
  const uint32_t runs_before = hyda_vm2_runs;
  for (const Pair& p : pairs) {
    for (int it = 0; it < 256; ++it) {
      const uint64_t x = test_rng(s), y = test_rng(s);
      uint64_t v1 = 0, v2 = 0, f1 = 0, f2 = 0;
      uint32_t s1 = 0, s2 = 0;
      run_bin_op(p.plain, x, y, &v1, &f1, &s1);
      run_bin_op(p.nested, x, y, &v2, &f2, &s2);
      val_diff += (v1 != v2) ? 1u : 0u;
      flag_diff += (f1 != f2) ? 1u : 0u;
      st_diff += (s1 != s2) ? 1u : 0u;
    }
  }
  CHECK_EQ(val_diff, 0);
  CHECK_EQ(flag_diff, 0);
  CHECK_EQ(st_diff, 0);

  CHECK_TRUE(hyda_vm2_runs >= runs_before + 768u);

  uint8_t save[192];
  std::memcpy(save, hyda_vm2_prog[kV2ProgAdd], sizeof(save));
  const uint32_t save_len = hyda_vm2_len[kV2ProgAdd];
  uint8_t bad = 0;
  while (bad < 255 && hyda_vm2_map[bad] != 0xFF) ++bad;
  hyda_vm2_len[kV2ProgAdd] = 12;
  hyda_vm2_prog[kV2ProgAdd][0] = bad;
  {
    uint64_t v = 0, f = 0;
    uint32_t st = 0, runs0 = 0;
    runs0 = hyda_vm2_runs;
    run_bin_op(Op::ADD64_N, 5, 7, &v, &f, &st);
    CHECK_EQ((int)st, (int)ST_FAULT);
    CHECK_EQ((int)hyda_vm2_runs, (int)runs0);
  }
  std::memcpy(hyda_vm2_prog[kV2ProgAdd], save, sizeof(save));
  hyda_vm2_len[kV2ProgAdd] = save_len;
  {
    uint64_t v = 0, f = 0;
    uint32_t st = 0;
    run_bin_op(Op::ADD64_N, 5, 7, &v, &f, &st);
    CHECK_EQ((int)st, (int)ST_HALT);
    CHECK_U64(v, 12);
  }
}

static void test_blob_header() {

  CHECK_EQ((int)sizeof(BlobHeader), 48);

  BlobHeader h;
  h.magic = blob_magic();
  h.code_size = 8;
  h.entry_offset = 0;
  h.code_crc32 = 0;
  h.version = HYDA_BLOB_VERSION;
  h.flags = 0;
  h.islands_rva = 0;
  h.island_count = 0;
  h.island_span = 0;
  h.import_tab_rva = 0;
  h.shard_mask = 0;
  CHECK_TRUE(blob_header_check(h));
  CHECK_TRUE(!blob_no_crypt(h));

  h.flags = HYDA_BLOB_NO_CRYPT;
  CHECK_TRUE(blob_header_check(h));
  CHECK_TRUE(blob_no_crypt(h));

  h.flags = HYDA_BLOB_KNOWN_FLAGS | 0x80000000u;
  CHECK_TRUE(!blob_header_check(h));

  h.flags = 0;
  h.version = HYDA_BLOB_VERSION + 1;
  CHECK_TRUE(!blob_header_check(h));
  h.version = HYDA_BLOB_VERSION;

  h.magic = 0x12345678u;
  CHECK_TRUE(!blob_header_check(h));
  h.magic = blob_magic();

  h.code_size = 0;
  CHECK_TRUE(!blob_header_check(h));
  h.code_size = HYDA_BLOB_MAX_CODE + 1;
  CHECK_TRUE(!blob_header_check(h));
  h.code_size = 8;

  h.islands_rva = 0x90000;
  h.island_count = 2;
  h.island_span = 128;
  CHECK_TRUE(blob_header_check(h));
  h.island_count = 0;
  CHECK_TRUE(!blob_header_check(h));
  h.island_count = 2;
  h.island_span = 0;
  CHECK_TRUE(!blob_header_check(h));
  h.islands_rva = 0;
  h.island_count = 1;
  h.island_span = 64;
  CHECK_TRUE(!blob_header_check(h));
  h.islands_rva = 0;
  h.island_count = 0;
  h.island_span = 0;

  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 7);
  a.i_rq(Op::MOV_RI, REG_RCX, 35);
  a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
  a.i_rq(Op::MOV_RI, REG_RDX, 5);
  a.i_rr(Op::IMUL2, REG_RAX, REG_RDX);
  a.i0(Op::HALT);
  a.finalize();

  const uint32_t blob_rva = 0x86000;
  const uint64_t key = crypt_key_for(blob_rva);
  CHECK_TRUE(key != 0);

  std::vector<uint8_t> enc = a.code;
  crypt_operands_encrypt(enc.data(), enc.size(), key);
  BlobHeader he = h;
  he.code_size = static_cast<uint32_t>(enc.size());
  he.code_crc32 = crc32(enc.data(), static_cast<uint32_t>(enc.size()));
  CHECK_TRUE(blob_header_check(he));

  const uint64_t key_e = blob_no_crypt(he) ? 0 : key;
  CHECK_EQ(key_e, key);

  std::vector<uint8_t> plain = a.code;
  BlobHeader hn = h;
  hn.flags = HYDA_BLOB_NO_CRYPT;
  hn.code_size = static_cast<uint32_t>(plain.size());
  hn.code_crc32 = crc32(plain.data(), static_cast<uint32_t>(plain.size()));
  CHECK_TRUE(blob_header_check(hn));
  const uint64_t key_n = blob_no_crypt(hn) ? 0 : key;
  CHECK_U64(key_n, 0);

  auto gate = [](const BlobHeader& bh, const uint8_t* code) {
    return blob_header_check(bh) &&
           crc32(code, bh.code_size) == bh.code_crc32;
  };
  CHECK_TRUE(gate(he, enc.data()));
  CHECK_TRUE(gate(hn, plain.data()));
  {
    BlobHeader bad = he;
    bad.version = HYDA_BLOB_VERSION + 1;
    CHECK_TRUE(!gate(bad, enc.data()));
  }
  {
    std::vector<uint8_t> t = enc;
    t[2] ^= 0xFF;
    CHECK_TRUE(!gate(he, t.data()));
  }

  VMContext c1;
  reset(c1);
  CHECK_EQ((int)vm_exec(c1, enc.data(), enc.size(), key_e), (int)ST_HALT);
  CHECK_U64(c1.r[vsl(REG_RAX)], 210);

  VMContext c2;
  reset(c2);
  CHECK_EQ((int)vm_exec(c2, plain.data(), plain.size(), key_n), (int)ST_HALT);
  CHECK_U64(c2.r[vsl(REG_RAX)], 210);

  VMContext c3;
  reset(c3);
  const uint32_t st3 = vm_exec(c3, plain.data(), plain.size(), key);
  CHECK_TRUE(st3 != ST_HALT || c3.r[vsl(REG_RAX)] != 210);
}

static void test_bad_register() {

  Asm a;
  a.i_rq(Op::MOV_RI, 200, 0x1234);
  a.i0(Op::HALT);
  a.finalize();
  VMContext ctx;
  reset(ctx, 1000);
  CHECK_EQ(vm_exec(ctx, a.code.data(), a.code.size()), (int)ST_BAD_REG);

  Asm b;
  b.i_rq(Op::MOV_RI, NO_MEM, 0x1234);
  b.i_rq(Op::MOV_RI, REG_RAX, 7);
  b.i0(Op::HALT);
  b.finalize();
  VMContext ctx2;
  reset(ctx2, 1000);
  CHECK_EQ(vm_exec(ctx2, b.code.data(), b.code.size()), (int)ST_HALT);
  CHECK_EQ(ctx2.r[vsl(REG_RAX)], 7);

  Asm c;
  c.i_rq(Op::MOV_RI, NVREG - 1, 0x55);
  c.i0(Op::HALT);
  c.finalize();
  VMContext ctx3;
  reset(ctx3, 1000);
  CHECK_EQ(vm_exec(ctx3, c.code.data(), c.code.size()), (int)ST_HALT);
}

extern "C" uint64_t hyda_ring_tab[hyda::kRingTables][hyda::kRingTableWords];
extern "C" uint16_t hyda_ring_perm[hyda::kRingTables][hyda::kSlotCount];
extern "C" uint64_t hyda_ring_call[hyda::kRingTables][hyda::kSlotCount];
extern "C" uint64_t hyda_ring_decoy_tab[hyda::kRingDecoys][hyda::kRingTableWords];
extern "C" uint16_t hyda_ring_decoy_perm[hyda::kRingDecoys][hyda::kSlotCount];
extern "C" uint64_t hyda_handler_lo;
extern "C" uint64_t hyda_handler_hi;

static size_t ring_word_at(uint16_t idx) {
  const DispatchProfile& p = g_dispatch_profile;
  return static_cast<size_t>(idx) << (p.entry_shift - 3u);
}

static uint64_t ring_tab_addr(int e) {
  return static_cast<uint64_t>(
      reinterpret_cast<uintptr_t>(hyda_ring_tab[e]));
}

static void test_handler_table_hiding() {
  CHECK_TRUE(hyda_handler_lo != 0);
  CHECK_TRUE(hyda_handler_hi > hyda_handler_lo);

  const OpcodeMap& m = opcode_map();
  const DispatchProfile& prof = g_dispatch_profile;

  int encrypted = 0;
  for (int e = 0; e < (int)kRingTables; ++e) {
    const uint64_t tab_addr = ring_tab_addr(e);
    for (size_t slot = 0; slot < kSlotCount; ++slot) {
      const uint16_t idx = hyda_ring_perm[e][slot];
      const uint64_t raw = hyda_ring_tab[e][ring_word_at(idx)];
      const DecodedEntry d = decode_ring_entry(raw, tab_addr, idx, prof);
      CHECK_TRUE(d.handler >= hyda_handler_lo && d.handler < hyda_handler_hi);
      if (raw != d.handler) ++encrypted;
    }
  }
  CHECK_EQ(encrypted, (int)kRingTables * (int)kSlotCount);

  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint16_t slot = m.slot_of_op[op];
    uint64_t h0 = 0;
    for (int e = 0; e < (int)kRingTables; ++e) {
      const uint16_t idx = hyda_ring_perm[e][slot];
      const DecodedEntry d = decode_ring_entry(
          hyda_ring_tab[e][ring_word_at(idx)], ring_tab_addr(e), idx, prof);
      CHECK_EQ(d.opsz, static_cast<int>(op_size(static_cast<Op>(op))));
      CHECK_EQ(d.regcnt, static_cast<int>(leading_reg_count(OP_SIGS[op])));
      if (e == 0) h0 = d.handler;
      CHECK_TRUE(d.handler == h0);
    }

    for (int e = 0; e < (int)kRingTables; ++e) {
      const uint16_t idx = hyda_ring_perm[e][slot];
      const uint64_t addr = hyda_ring_call[e][idx] ^
                            dispatch_key_idx(prof, ring_tab_addr(e), idx);
      CHECK_TRUE(addr == h0);
    }
  }

  {
    int differ = 0;
    for (int e = 1; e < (int)kRingTables; ++e) {
      for (size_t slot = 0; slot < kSlotCount; ++slot) {
        if (hyda_ring_perm[e][slot] != hyda_ring_perm[0][slot]) ++differ;
      }
    }
    CHECK_TRUE(differ > 1000);
  }

  {
    int wrong = 0;
    const uint64_t tab_addr = ring_tab_addr(0);
    for (size_t slot = 0; slot < kSlotCount; ++slot) {
      const uint16_t idx = hyda_ring_perm[0][slot];
      const uint64_t raw = hyda_ring_tab[0][ring_word_at(idx)];
      const DecodedEntry bad = decode_ring_entry(raw, tab_addr + 0x1000, idx, prof);
      const DecodedEntry good = decode_ring_entry(raw, tab_addr, idx, prof);
      if (bad.handler != good.handler || bad.opsz != good.opsz) ++wrong;
    }
    CHECK_TRUE(wrong > 250);
  }

  {
    const uint64_t dec_addr = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(hyda_ring_decoy_tab[0]));
    int differs = 0;
    int valid = 0;
    for (size_t slot = 0; slot < kSlotCount; ++slot) {
      const uint16_t idx = hyda_ring_decoy_perm[0][slot];
      const uint64_t raw = hyda_ring_decoy_tab[0][ring_word_at(idx)];
      if (hyda_ring_decoy_perm[0][slot] != hyda_ring_perm[0][slot]) ++differs;
      const DecodedEntry d = decode_ring_entry(raw, dec_addr, idx, prof);
      if (d.handler >= hyda_handler_lo && d.handler < hyda_handler_hi) ++valid;
    }
    CHECK_TRUE(differs > 240);
    CHECK_EQ(valid, (int)kSlotCount);
  }

  {
    bool seen[kRingTables] = {};
    bool any_diff = false;
    for (uint64_t ip = 0; ip < 64; ++ip) {
      const uint32_t e0 = ring_select(ip, 0x1234);
      seen[e0] = true;
      if (ring_select(ip, 0x1234) != ring_select(ip, 0x9999)) any_diff = true;
    }
    int used = 0;
    for (uint32_t e = 0; e < kRingTables; ++e) if (seen[e]) ++used;
    CHECK_EQ(used, (int)kRingTables);
    CHECK_TRUE(any_diff);
  }

  {
    uint16_t bad_slot = 0;
    for (size_t i = 0; i < kSlotCount; ++i) {
      if (m.op_of_slot[i] == BAD_SLOT) { bad_slot = static_cast<uint16_t>(i); break; }
    }
    std::vector<uint8_t> code;
    code.push_back(static_cast<uint8_t>(bad_slot & 0xFFu));
    code.push_back(static_cast<uint8_t>(bad_slot >> 8));
    const uint16_t halt_slot = m.slot_of_op[static_cast<size_t>(Op::HALT)];
    code.push_back(static_cast<uint8_t>(halt_slot & 0xFFu));
    code.push_back(static_cast<uint8_t>(halt_slot >> 8));
    VMContext c0;
    reset(c0, 1000);
    CHECK_EQ(vm_exec(c0, code.data(), code.size()), (int)ST_BAD_OPCODE);

    uint64_t saved[kRingTables];
    for (int e = 0; e < (int)kRingTables; ++e) {
      const uint16_t idx = hyda_ring_perm[e][bad_slot];
      saved[e] = hyda_ring_tab[e][ring_word_at(idx)];

      hyda_ring_tab[e][ring_word_at(idx)] =
          dispatch_key_idx(prof, ring_tab_addr(e), idx) ^ 0xFFFFFFFFull;
    }
    VMContext c1;
    reset(c1, 1000);
    const uint32_t st = vm_exec(c1, code.data(), code.size());
    for (int e = 0; e < (int)kRingTables; ++e) {
      const uint16_t idx = hyda_ring_perm[e][bad_slot];
      hyda_ring_tab[e][ring_word_at(idx)] = saved[e];
    }
    CHECK_EQ(st, (int)ST_FAULT);
  }

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 6);
    a.i_rq(Op::MOV_RI, REG_RCX, 7);
    a.i_rr(Op::IMUL2, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    a.finalize();
    VMContext ctx;
    reset(ctx, 1000);
    CHECK_EQ(vm_exec(ctx, a.code.data(), a.code.size()), static_cast<int>(ST_HALT));
    CHECK_EQ(ctx.r[vsl(REG_RAX)], 42);
  }
}

static void test_hydak_shard() {

  const uint64_t k1 = hydak_key_for(0x85c000);
  const uint64_t k2 = hydak_key_for(0x860000);
  CHECK_TRUE(k1 != 0 && k2 != 0 && k1 != k2);

  {
    std::vector<uint8_t> buf(1024);
    for (size_t i = 0; i < buf.size(); ++i) {
      buf[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    const std::vector<uint8_t> orig = buf;
    hydak_xor(buf.data(), static_cast<uint32_t>(buf.size()), k1);
    CHECK_TRUE(buf != orig);
    hydak_xor(buf.data(), static_cast<uint32_t>(buf.size()), k1);
    CHECK_TRUE(buf == orig);
    hydak_xor(buf.data(), static_cast<uint32_t>(buf.size()), 0);
    CHECK_TRUE(buf == orig);
  }

  const uint32_t shard_rva = 0x85c000;
  const uint32_t chunk_count = 3;
  const uint32_t chunks_off = 0x80;
  const uint32_t opmap_off = chunks_off + chunk_count * 12;
  const uint32_t total = (opmap_off + OP_COUNT * 2 + 15u) & ~15u;

  auto build = [&](std::vector<uint8_t>* out, uint16_t bad_chunk,
                   uint16_t version, uint32_t size_override) {
    std::vector<uint8_t> b(total, 0);
    for (uint32_t i = 0; i < total; ++i) b[i] = static_cast<uint8_t>(0xA0 ^ i);
    auto w32 = [&](uint32_t off, uint32_t v) {
      b[off] = static_cast<uint8_t>(v);
      b[off + 1] = static_cast<uint8_t>(v >> 8);
      b[off + 2] = static_cast<uint8_t>(v >> 16);
      b[off + 3] = static_cast<uint8_t>(v >> 24);
    };
    auto w16 = [&](uint32_t off, uint16_t v) {
      b[off] = static_cast<uint8_t>(v);
      b[off + 1] = static_cast<uint8_t>(v >> 8);
    };
    w32(0, hydak_magic());
    w32(4, size_override ? size_override : total);
    w32(8, chunks_off - HYDA_HYDAK_CODE_OFF);
    w32(12, chunk_count);
    w32(16, chunks_off);
    w32(20, opmap_off);
    w16(24, bad_chunk);
    w16(26, version);
    for (uint32_t i = 0; i < chunk_count; ++i) {
      w32(chunks_off + i * 12 + 0, HYDA_HYDAK_CODE_OFF + i * 16);
      w32(chunks_off + i * 12 + 4, 16);
      w32(chunks_off + i * 12 + 8, 0x2000 + i * 16);
    }
    for (size_t op = 0; op < OP_COUNT; ++op) {
      w16(opmap_off + static_cast<uint32_t>(op) * 2,
          static_cast<uint16_t>(op % chunk_count));
    }
    const uint32_t crc = crc32(b.data() + sizeof(HydakHeader),
                               total - static_cast<uint32_t>(sizeof(HydakHeader)));
    w32(28, crc);
    hydak_xor(b.data(), total, hydak_key_for(shard_rva));
    *out = std::move(b);
  };

  HydakView v;
  uint32_t err = 0xDEADBEEF;
  {
    std::vector<uint8_t> b;
    build(&b, 0, HYDA_HYDAK_VERSION, 0);
    CHECK_TRUE(hydak_open(b.data(), total, hydak_key_for(shard_rva), &v, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_OK));
    CHECK_EQ(v.h->chunk_count, static_cast<int>(chunk_count));
    CHECK_EQ(v.chunks[1].off, static_cast<int>(HYDA_HYDAK_CODE_OFF + 16));
    CHECK_EQ(v.chunks[2].orig_rva, 0x2020);

    CHECK_EQ(v.h->bad_chunk, 0);
  }

  {
    std::vector<uint8_t> b;
    build(&b, 0, HYDA_HYDAK_VERSION, 0);
    hydak_xor(b.data(), total, hydak_key_for(shard_rva));  // decrypt
    CHECK_TRUE(hydak_verify_plain(b.data(), total));

    b[HYDA_HYDAK_CODE_OFF] ^= 0x01;
    CHECK_TRUE(!hydak_verify_plain(b.data(), total));
    b[HYDA_HYDAK_CODE_OFF] ^= 0x01;

    b[0] ^= 0xFF;
    CHECK_TRUE(!hydak_verify_plain(b.data(), total));
    b[0] ^= 0xFF;

    CHECK_TRUE(!hydak_verify_plain(b.data(), total - 16));
  }

  {
    std::vector<uint8_t> b;
    build(&b, 0, HYDA_HYDAK_VERSION, 0);

    b[0] ^= 0xFF;
    err = 0;
    CHECK_TRUE(!hydak_open(b.data(), total, hydak_key_for(shard_rva), &v, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_MAGIC));

    build(&b, 0, HYDA_HYDAK_VERSION, 0);
    err = 0;
    CHECK_TRUE(!hydak_open(b.data(), total - 16, hydak_key_for(shard_rva), &v, &err));
    CHECK_TRUE(err == HYDAK_ERR_MAGIC || err == HYDAK_ERR_SIZE);

    build(&b, 0, static_cast<uint16_t>(HYDA_HYDAK_VERSION + 1), 0);
    err = 0;
    CHECK_TRUE(!hydak_open(b.data(), total, hydak_key_for(shard_rva), &v, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_VERSION));

    {
      std::vector<uint8_t> c;
      build(&c, 0, HYDA_HYDAK_VERSION, 0);
      hydak_xor(c.data(), total, hydak_key_for(shard_rva));
      c[24] = 0xFF;
      c[25] = 0x00;
      const uint32_t crc = crc32(c.data() + sizeof(HydakHeader),
                                 total - static_cast<uint32_t>(sizeof(HydakHeader)));
      c[28] = static_cast<uint8_t>(crc);
      c[29] = static_cast<uint8_t>(crc >> 8);
      c[30] = static_cast<uint8_t>(crc >> 16);
      c[31] = static_cast<uint8_t>(crc >> 24);
      hydak_xor(c.data(), total, hydak_key_for(shard_rva));
      err = 0;
      CHECK_TRUE(!hydak_open(c.data(), total, hydak_key_for(shard_rva), &v, &err));
      CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
    }

    build(&b, 0, HYDA_HYDAK_VERSION, 0);
    hydak_xor(b.data(), total, hydak_key_for(shard_rva));
    b[opmap_off] ^= 0x5A;
    hydak_xor(b.data(), total, hydak_key_for(shard_rva));
    err = 0;
    CHECK_TRUE(!hydak_open(b.data(), total, hydak_key_for(shard_rva), &v, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_CRC));
  }

  CHECK_TRUE(hydak_key_for(0) != 0);
  CHECK_TRUE(hydak_key_for(0xFFFFFFFFu) != hydak_key_for(0));
}

static void test_hydak_catalog() {
  auto build = [](std::vector<uint8_t>* out, uint32_t rva, uint32_t chunk_count,
                  uint16_t bad_chunk,
                  const std::vector<uint16_t>& op_chunk) {
    const uint32_t chunks_off = 0x80;
    const uint32_t opmap_off = chunks_off + chunk_count * 12;
    const uint32_t total = (opmap_off + OP_COUNT * 2 + 15u) & ~15u;
    std::vector<uint8_t> b(total, 0);
    for (uint32_t i = 0; i < total; ++i) b[i] = static_cast<uint8_t>(0x5C ^ i);
    auto w32 = [&](uint32_t off, uint32_t v) {
      b[off] = static_cast<uint8_t>(v);
      b[off + 1] = static_cast<uint8_t>(v >> 8);
      b[off + 2] = static_cast<uint8_t>(v >> 16);
      b[off + 3] = static_cast<uint8_t>(v >> 24);
    };
    auto w16 = [&](uint32_t off, uint16_t v) {
      b[off] = static_cast<uint8_t>(v);
      b[off + 1] = static_cast<uint8_t>(v >> 8);
    };
    w32(0, hydak_magic());
    w32(4, total);
    w32(8, chunks_off - HYDA_HYDAK_CODE_OFF);
    w32(12, chunk_count);
    w32(16, chunks_off);
    w32(20, opmap_off);
    w16(24, bad_chunk);
    w16(26, static_cast<uint16_t>(HYDA_HYDAK_VERSION));
    for (uint32_t i = 0; i < chunk_count; ++i) {
      w32(chunks_off + i * 12 + 0, HYDA_HYDAK_CODE_OFF + i * 16);
      w32(chunks_off + i * 12 + 4, 16);
      w32(chunks_off + i * 12 + 8, 0x3000 + i * 16);
    }
    for (size_t op = 0; op < OP_COUNT; ++op) {
      w16(opmap_off + static_cast<uint32_t>(op) * 2, op_chunk[op]);
    }
    const uint32_t crc = crc32(b.data() + sizeof(HydakHeader),
                               total - static_cast<uint32_t>(sizeof(HydakHeader)));
    w32(28, crc);
    hydak_xor(b.data(), total, hydak_key_for(rva));
    *out = std::move(b);
  };

  auto open_view = [](std::vector<uint8_t>& b, uint32_t rva, HydakView* v,
                      uint32_t* err) {
    *err = 0;
    return hydak_open(b.data(), static_cast<uint32_t>(b.size()),
                      hydak_key_for(rva), v, err);
  };

  {
    std::vector<uint16_t> a(OP_COUNT, HYDA_HYDAK_NO_CHUNK);
    std::vector<uint16_t> bb(OP_COUNT, HYDA_HYDAK_NO_CHUNK);
    for (size_t op = 0; op < OP_COUNT; ++op) {
      if (op % 2 == 0) {
        a[op] = static_cast<uint16_t>((op % 4 == 0) ? 0 : 1);
      } else {
        bb[op] = static_cast<uint16_t>((op % 4 == 1) ? 0 : 1);
      }
    }
    std::vector<uint8_t> sa, sb;
    build(&sa, 0x85c000, 2, 1, a);
    build(&sb, 0x85d000, 2, HYDA_HYDAK_NO_CHUNK, bb);

    HydakView va, vb;
    uint32_t err = 0;
    CHECK_TRUE(open_view(sa, 0x85c000, &va, &err));
    CHECK_TRUE(open_view(sb, 0x85d000, &vb, &err));

    HydakCatalog cat;
    CHECK_TRUE(hydak_catalog_add(&cat, va, &err));
    CHECK_TRUE(hydak_catalog_add(&cat, vb, &err));
    CHECK_TRUE(hydak_catalog_finish(&cat, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_OK));
    CHECK_EQ(cat.shards, 2);

    const uint64_t abase = reinterpret_cast<uint64_t>(sa.data());
    const uint64_t bbase = reinterpret_cast<uint64_t>(sb.data());
    CHECK_U64(cat.addrs[0], abase + HYDA_HYDAK_CODE_OFF);
    CHECK_U64(cat.addrs[1], bbase + HYDA_HYDAK_CODE_OFF);
    CHECK_U64(cat.bad, abase + HYDA_HYDAK_CODE_OFF + 16);

    std::vector<uint8_t> bad_copy = sb;
    hydak_xor(bad_copy.data(), static_cast<uint32_t>(bad_copy.size()),
              hydak_key_for(0x85d000));
    bad_copy[0] ^= 0xFF;
    hydak_xor(bad_copy.data(), static_cast<uint32_t>(bad_copy.size()),
              hydak_key_for(0x85d000));
    HydakView vbad;
    err = 0;
    CHECK_TRUE(!hydak_open(bad_copy.data(), static_cast<uint32_t>(bad_copy.size()),
                           hydak_key_for(0x85d000), &vbad, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_MAGIC));
  }

  {
    std::vector<uint16_t> all(OP_COUNT, 0);
    std::vector<uint8_t> sa, sb;
    build(&sa, 0x85c000, 1, 0, all);
    build(&sb, 0x85d000, 1, HYDA_HYDAK_NO_CHUNK, all);
    HydakView va, vb;
    uint32_t err = 0;
    CHECK_TRUE(open_view(sa, 0x85c000, &va, &err));
    CHECK_TRUE(open_view(sb, 0x85d000, &vb, &err));
    HydakCatalog cat;
    CHECK_TRUE(hydak_catalog_add(&cat, va, &err));
    err = 0;
    CHECK_TRUE(!hydak_catalog_add(&cat, vb, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    std::vector<uint16_t> half(OP_COUNT, HYDA_HYDAK_NO_CHUNK);
    for (size_t op = 0; op + 1 < OP_COUNT; ++op) {
      half[op] = 0;
    }
    std::vector<uint8_t> sa;
    build(&sa, 0x85c000, 1, 0, half);
    HydakView va;
    uint32_t err = 0;
    CHECK_TRUE(open_view(sa, 0x85c000, &va, &err));
    HydakCatalog cat;
    CHECK_TRUE(hydak_catalog_add(&cat, va, &err));
    err = 0;
    CHECK_TRUE(!hydak_catalog_finish(&cat, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    std::vector<uint16_t> m(OP_COUNT, 0);
    std::vector<uint8_t> sa;
    build(&sa, 0x85c000, 3, 0, m);
    HydakView va;
    uint32_t err = 0;
    CHECK_TRUE(open_view(sa, 0x85c000, &va, &err));
    HydakCatalog cat;
    err = 0;
    CHECK_TRUE(!hydak_catalog_add(&cat, va, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    std::vector<uint16_t> a(OP_COUNT, HYDA_HYDAK_NO_CHUNK);
    std::vector<uint16_t> bb(OP_COUNT, HYDA_HYDAK_NO_CHUNK);
    for (size_t op = 0; op < OP_COUNT; ++op) {
      if (op % 2 == 0) a[op] = 0; else bb[op] = 0;
    }
    std::vector<uint8_t> sa, sb;
    build(&sa, 0x85c000, 1, 0, a);
    build(&sb, 0x85d000, 1, 0, bb);
    HydakView va, vb;
    uint32_t err = 0;
    CHECK_TRUE(open_view(sa, 0x85c000, &va, &err));
    CHECK_TRUE(open_view(sb, 0x85d000, &vb, &err));
    HydakCatalog cat;
    CHECK_TRUE(hydak_catalog_add(&cat, va, &err));
    err = 0;
    CHECK_TRUE(!hydak_catalog_add(&cat, vb, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    std::vector<uint16_t> m(OP_COUNT, 0);
    std::vector<uint8_t> sa;
    build(&sa, 0x85c000, static_cast<uint32_t>(OP_COUNT) + 2, 0, m);
    HydakView va;
    uint32_t err = 0;
    CHECK_TRUE(!open_view(sa, 0x85c000, &va, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    std::vector<uint16_t> m(OP_COUNT, 0);
    m[OP_COUNT - 1] = 7;
    std::vector<uint8_t> sa;
    build(&sa, 0x85c000, 1, 0, m);
    HydakView va;
    uint32_t err = 0;
    CHECK_TRUE(open_view(sa, 0x85c000, &va, &err));
    HydakCatalog cat;
    err = 0;
    CHECK_TRUE(!hydak_catalog_add(&cat, va, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    HydakCatalog cat;
    uint32_t err = 0;
    CHECK_TRUE(!hydak_catalog_finish(&cat, &err));
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }
}

static void test_hydak_scan() {
  const uint32_t base_rva = 0x85c000;

  auto make_part = [](uint32_t rva, uint32_t chunk_count) {
    const uint32_t chunks_off = 0x40;
    const uint32_t opmap_off = chunks_off + chunk_count * 12;
    const uint32_t total = (opmap_off + OP_COUNT * 2 + 15u) & ~15u;
    std::vector<uint8_t> b(total, 0);
    for (uint32_t i = 0; i < total; ++i) {
      b[i] = static_cast<uint8_t>(0x3C ^ (i * 5));
    }
    auto w32 = [&](uint32_t off, uint32_t val) {
      b[off] = static_cast<uint8_t>(val);
      b[off + 1] = static_cast<uint8_t>(val >> 8);
      b[off + 2] = static_cast<uint8_t>(val >> 16);
      b[off + 3] = static_cast<uint8_t>(val >> 24);
    };
    auto w16 = [&](uint32_t off, uint16_t val) {
      b[off] = static_cast<uint8_t>(val);
      b[off + 1] = static_cast<uint8_t>(val >> 8);
    };
    w32(0, hydak_magic());
    w32(4, total);
    w32(8, chunks_off - HYDA_HYDAK_CODE_OFF);
    w32(12, chunk_count);
    w32(16, chunks_off);
    w32(20, opmap_off);
    w16(24, HYDA_HYDAK_NO_CHUNK);
    w16(26, static_cast<uint16_t>(HYDA_HYDAK_VERSION));
    for (uint32_t i = 0; i < chunk_count; ++i) {
      w32(chunks_off + i * 12 + 0, HYDA_HYDAK_CODE_OFF + 16 * i);
      w32(chunks_off + i * 12 + 4, 16);
      w32(chunks_off + i * 12 + 8, 0x4000 + 16 * i);
    }
    for (size_t op = 0; op < OP_COUNT; ++op) {
      w16(opmap_off + static_cast<uint32_t>(op) * 2,
          static_cast<uint16_t>(op % chunk_count));
    }
    const uint32_t crc =
        crc32(b.data() + sizeof(HydakHeader),
              total - static_cast<uint32_t>(sizeof(HydakHeader)));
    w32(28, crc);
    hydak_xor(b.data(), total, hydak_key_for(rva));
    return b;
  };

  const uint32_t cont_total = 0x4000;
  const uint32_t off_a = 0x20;
  const uint32_t off_b = 0x1000;
  std::vector<uint8_t> pa = make_part(base_rva + off_a, 1);
  std::vector<uint8_t> pb = make_part(base_rva + off_b, 2);
  std::vector<uint8_t> cont(cont_total, 0);
  {
    uint64_t r = 0x1234;
    for (uint32_t i = 0; i < cont_total; ++i) {
      cont[i] = static_cast<uint8_t>(splitmix64(r) & 0xFFu);
    }
  }
  std::memcpy(cont.data() + off_a, pa.data(), pa.size());
  std::memcpy(cont.data() + off_b, pb.data(), pb.size());
  const std::vector<uint8_t> cont_orig = cont;

  {
    std::vector<uint8_t> probe = pa;
    uint32_t total = 0;
    CHECK_TRUE(hydak_probe(probe.data(), static_cast<uint32_t>(probe.size()),
                           hydak_key_for(base_rva + off_a), &total));
    CHECK_EQ(total, static_cast<int>(pa.size()));
    CHECK_TRUE(probe == pa);
    total = 0;
    CHECK_TRUE(!hydak_probe(probe.data(), static_cast<uint32_t>(probe.size()),
                            hydak_key_for(base_rva + off_a + 16), &total));
    CHECK_TRUE(probe == pa);
  }

  {
    std::vector<uint8_t> buf = cont;
    HandlerShardDesc got[HYDA_HYDAK_MAX_PARTS];
    uint32_t err = 0xDEADBEEF;
    const unsigned n = hydak_scan_parts(buf.data(), cont_total, base_rva, got,
                                        HYDA_HYDAK_MAX_PARTS, &err);
    CHECK_EQ(n, 2);
    CHECK_EQ(err, static_cast<int>(HYDAK_OK));
    CHECK_EQ(got[0].rva, static_cast<int>(base_rva + off_a));
    CHECK_EQ(got[0].size, static_cast<int>(pa.size()));
    CHECK_EQ(got[1].rva, static_cast<int>(base_rva + off_b));
    CHECK_EQ(got[1].size, static_cast<int>(pb.size()));
    CHECK_TRUE(buf == cont_orig);
  }

  {
    std::vector<uint8_t> buf(0x2000);
    uint64_t r = 0xBEEF;
    for (size_t i = 0; i < buf.size(); ++i) {
      buf[i] = static_cast<uint8_t>(splitmix64(r) & 0xFFu);
    }
    const std::vector<uint8_t> orig = buf;
    HandlerShardDesc got[HYDA_HYDAK_MAX_PARTS];
    uint32_t err = 0xDEADBEEF;
    const unsigned n = hydak_scan_parts(buf.data(), 0x2000, base_rva + 0x20000,
                                        got, HYDA_HYDAK_MAX_PARTS, &err);
    CHECK_EQ(n, 0);
    CHECK_EQ(err, static_cast<int>(HYDAK_OK));
    CHECK_TRUE(buf == orig);
  }

  {
    std::vector<uint8_t> buf = cont;
    HandlerShardDesc got[1];
    uint32_t err = 0;
    const unsigned n =
        hydak_scan_parts(buf.data(), cont_total, base_rva, got, 1, &err);
    CHECK_EQ(n, 0);
    CHECK_EQ(err, static_cast<int>(HYDAK_ERR_LAYOUT));
  }

  {
    std::vector<uint8_t> buf = cont;
    buf[off_a] ^= 0xFFu;
    HandlerShardDesc got[HYDA_HYDAK_MAX_PARTS];
    uint32_t err = 0;
    const unsigned n = hydak_scan_parts(buf.data(), cont_total, base_rva, got,
                                        HYDA_HYDAK_MAX_PARTS, &err);
    CHECK_EQ(n, 1);
    CHECK_EQ(err, static_cast<int>(HYDAK_OK));
    CHECK_EQ(got[0].rva, static_cast<int>(base_rva + off_b));
  }
}

static void test_integrity() {

  {
    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i) {
      data[i] = static_cast<uint8_t>(i * 37 + 11);
    }
    CHECK_EQ(hyda::integrity_crc32(data.data(), data.size()),
             hyda::crc32(data.data(), data.size()));

    CHECK_EQ(hyda::integrity_crc32(nullptr, 0), hyda::crc32(nullptr, 0));
  }

  {
    hyda::RelocHole holes[2];
    holes[0].rva = 0x1000 + 100;
    holes[0].size = 8;
    holes[1].rva = 0x1000 + 300;
    holes[1].size = 8;
    hyda::IntegrityChunk chunks[16];
    const uint32_t n = hyda::integrity_split_region(
        0x1000, 0x1000 + 400, holes, 2, chunks, 16);

    CHECK_EQ(n, 3);
    CHECK_EQ(chunks[0].rva, 0x1000);
    CHECK_EQ(chunks[0].size, 100);
    CHECK_EQ(chunks[1].rva, 0x1000 + 108);
    CHECK_EQ(chunks[1].size, 192);
    CHECK_EQ(chunks[2].rva, 0x1000 + 308);
    CHECK_EQ(chunks[2].size, 92);
  }

  {
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) {
      data[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    const std::vector<uint8_t> orig = data;
    const uint64_t key = hyda::integrity_key_for(0x1234u, 0x86cce0u);
    hyda::integrity_crypt(data.data(), static_cast<uint32_t>(data.size()), key,
                           true);
    CHECK_TRUE(data != orig);
    hyda::integrity_crypt(data.data(), static_cast<uint32_t>(data.size()), key,
                           false);
    CHECK_TRUE(data == orig);
  }

  {
    const uint32_t kManRva = 0x1000;
    const uint32_t kDatRva = 0x1100;
    const uint32_t base_rva = 0;
    std::vector<uint8_t> img(kManRva, 0);
    for (uint32_t i = 0; i < 0x100; ++i) {
      img[base_rva + i] = static_cast<uint8_t>(i * 13 + 5);
    }

    hyda::RelocHole holes[1];
    holes[0].rva = base_rva + 0x80;
    holes[0].size = 8;
    hyda::IntegrityChunk chunks[8];
    const uint32_t n = hyda::integrity_split_region(
        base_rva, base_rva + 0x100, holes, 1, chunks, 8);
    CHECK_EQ(n, 2);
    for (uint32_t i = 0; i < n; ++i) {
      const uint32_t off = chunks[i].rva - base_rva;
      chunks[i].crc32 = hyda::integrity_crc32(&img[off], chunks[i].size);
    }

    const uint32_t salt = 0xA5A5A5A5u;
    hyda::IntegrityManifest man;
    std::memset(&man, 0, sizeof(man));
    man.magic = hyda::integrity_magic();
    man.version = hyda::HYDA_INTEGRITY_VERSION;
    man.count = n;
    man.chunks_rva = kDatRva;
    man.salt = salt;
    std::vector<uint8_t> plain(n * sizeof(hyda::IntegrityChunk));
    for (uint32_t i = 0; i < n; ++i) {
      std::memcpy(&plain[i * sizeof(hyda::IntegrityChunk)], &chunks[i],
                  sizeof(hyda::IntegrityChunk));
    }
    man.self_crc32 = hyda::integrity_chunks_crc(chunks, n);
    CHECK_EQ(man.self_crc32,
             hyda::integrity_crc32(plain.data(), plain.size()));
    const uint64_t key = hyda::integrity_key_for(salt, kManRva);
    hyda::integrity_crypt(plain.data(), static_cast<uint32_t>(plain.size()), key,
                           true);

    const uint32_t dat_total = static_cast<uint32_t>(sizeof(hyda::DatHeader)) +
                               static_cast<uint32_t>(plain.size());
    img.resize(kDatRva + dat_total, 0);
    hyda::DatHeader dh;
    std::memset(&dh, 0, sizeof(dh));
    dh.magic = hyda::dat_magic();
    dh.version = hyda::HYDA_DAT_VERSION;
    dh.total_size = dat_total;
    dh.count = n;
    dh.salt = salt;
    dh.self_crc32 = man.self_crc32;
    std::memcpy(&img[kDatRva], &dh, sizeof(dh));
    std::memcpy(&img[kDatRva + sizeof(dh)], plain.data(), plain.size());
    hyda::hydak_xor(&img[kDatRva], dat_total, hyda::dat_key_for(kDatRva));
    std::memcpy(&img[kManRva], &man, sizeof(man));

    const uint8_t* base = img.data();

    CHECK_TRUE(std::memcmp(&img[kDatRva + sizeof(dh)], plain.data(),
                           plain.size()) != 0);

    {
      std::vector<uint8_t> copy(img.begin() + kDatRva, img.end());
      hyda::DatHeader bad;
      CHECK_TRUE(!hyda::dat_open(copy.data(), dat_total,
                                 hyda::dat_key_for(kDatRva + 0x100), &bad));

      CHECK_TRUE(std::memcmp(copy.data(), &img[kDatRva], dat_total) == 0);
    }

    hyda::DatHeader got;
    CHECK_TRUE(hyda::dat_open(&img[kDatRva], dat_total,
                              hyda::dat_key_for(kDatRva), &got));
    CHECK_EQ(got.count, n);
    CHECK_EQ(got.salt, salt);
    CHECK_EQ(got.self_crc32, man.self_crc32);

    std::vector<uint8_t> whole(n * sizeof(hyda::IntegrityChunk));
    {
      const uint8_t* payload = &img[kDatRva + sizeof(got)];
      uint32_t running = 0;
      for (uint32_t i = 0; i < n; ++i) {
        const uint32_t off = i * static_cast<uint32_t>(sizeof(hyda::IntegrityChunk));
        hyda::integrity_crypt_range(payload, off,
                                    static_cast<uint32_t>(sizeof(hyda::IntegrityChunk)),
                                    key, whole.data() + off);
        hyda::IntegrityChunk one;
        std::memcpy(&one, whole.data() + off, sizeof(one));
        CHECK_EQ(one.rva, chunks[i].rva);
        CHECK_EQ(one.size, chunks[i].size);
        CHECK_EQ(one.crc32, chunks[i].crc32);
        running = hyda::integrity_crc32(
            reinterpret_cast<const uint8_t*>(&one), sizeof(one), running);

        const hyda::AuditMask mk = hyda::audit_mask_for(i);
        CHECK_TRUE(mk.crc != 0);
      }
      CHECK_EQ(running, man.self_crc32);
      hyda::IntegrityChunk cc;
      std::memcpy(&cc, whole.data(), sizeof(cc));
      CHECK_TRUE(hyda::integrity_check_chunk(base, cc));
    }
    hyda::dat_close(&img[kDatRva], got.total_size, hyda::dat_key_for(kDatRva));

    {
      std::vector<uint8_t> copy(img.begin() + kDatRva, img.end());
      hyda::hydak_xor(copy.data(), dat_total, hyda::dat_key_for(kDatRva));
      auto* hp = reinterpret_cast<hyda::DatHeader*>(copy.data());
      hp->self_crc32 ^= 1u;
      hyda::hydak_xor(copy.data(), dat_total, hyda::dat_key_for(kDatRva));
      hyda::DatHeader bad;

      CHECK_TRUE(hyda::dat_open(copy.data(), dat_total,
                                hyda::dat_key_for(kDatRva), &bad));
      CHECK_TRUE(bad.self_crc32 != man.self_crc32);
    }

    img[base_rva + 0x40] ^= 0xFFu;
    {
      hyda::IntegrityChunk cc;
      std::memcpy(&cc, whole.data(), sizeof(cc));
      CHECK_TRUE(!hyda::integrity_check_chunk(base, cc));
    }
  }

  {
    std::vector<uint8_t> blk(sizeof(hyda::DatHeader) + 16, 0);
    hyda::DatHeader h;
    std::memset(&h, 0, sizeof(h));
    h.magic = 0xDEADBEEFu;
    h.version = hyda::HYDA_DAT_VERSION;
    h.total_size = static_cast<uint32_t>(blk.size());
    h.count = 1;
    std::memcpy(blk.data(), &h, sizeof(h));
    hyda::hydak_xor(blk.data(), static_cast<uint32_t>(blk.size()),
                    hyda::dat_key_for(0x2000));
    hyda::DatHeader out;
    CHECK_TRUE(!hyda::dat_open(blk.data(), static_cast<uint32_t>(blk.size()),
                               hyda::dat_key_for(0x2000), &out));

    h.magic = hyda::dat_magic();
    h.version = hyda::HYDA_DAT_VERSION + 1u;
    std::memcpy(blk.data(), &h, sizeof(h));
    hyda::hydak_xor(blk.data(), static_cast<uint32_t>(blk.size()),
                    hyda::dat_key_for(0x2000));
    CHECK_TRUE(!hyda::dat_open(blk.data(), static_cast<uint32_t>(blk.size()),
                               hyda::dat_key_for(0x2000), &out));
  }
}

static void test_vreg_perm() {
  bool seen[16] = {};
  bool moved = false;
  for (int i = 0; i < 16; ++i) {
    const int p = vsl(i);
    CHECK_TRUE(p >= 0 && p < 16);
    if (p < 0 || p >= 16) continue;
    CHECK_TRUE(!seen[p]);
    seen[p] = true;
    if (p != i) moved = true;
  }
  for (int i = 16; i < NVREG; ++i) CHECK_EQ(vsl(i), i);
  CHECK_TRUE(moved);
}

static IRProgram fuse_sample_prog() {
  IRProgram p;
  p.add(IRCommand::mov(IROperand::R(REG_RCX), IROperand::I(0)));
  p.add(IRCommand::mov(IROperand::R(REG_RAX), IROperand::I(0)));
  p.add(IRCommand::mov(IROperand::R(REG_RDX), IROperand::I(10)));
  const int loop = p.new_label();
  p.bind(loop);
  p.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RAX), IROperand::R(REG_RCX)));
  p.add(IRCommand::unary(UnaryOp::Inc, REG_RCX));
  p.add(IRCommand::alu(AluOp::Cmp, IROperand::R(REG_RCX), IROperand::R(REG_RDX)));
  p.add(IRCommand::br(IROp::Jcc, loop));
  p.cmds.back().sub = 5;
  p.add(IRCommand::none(IROp::Ret));
  return p;
}

static void test_fuse() {
  const IRProgram base = fuse_sample_prog();
  uint64_t want = 0;
  CHECK_EQ(run_ir_prog(base, 0, &want), (int)ST_HALT);
  CHECK_U64(want, 45);

  IRProgram p = base;
  const FuseStats st = ir_fuse(p);
  CHECK_TRUE(st.fused >= 1);
  CHECK_EQ(st.cmds_after + st.fused, st.cmds_before);

  size_t cmp_jcc = 0;
  for (const IRCommand& c : p.cmds) {
    if (c.op == IROp::CmpJcc) ++cmp_jcc;
    CHECK_TRUE(c.op != IROp::Jcc);
  }
  CHECK_EQ(cmp_jcc, (size_t)1);

  uint64_t got = 0;
  CHECK_EQ(run_ir_prog(p, 0, &got), (int)ST_HALT);
  CHECK_U64(got, want);

  {
    IRProgram q;
    q.add(IRCommand::mov(IROperand::R(REG_RBX), IROperand::I(7)));
    q.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RAX), IROperand::R(REG_RBX)));
    q.add(IRCommand::mov(IROperand::R(REG_RCX), IROperand::R(REG_RAX)));
    q.add(IRCommand::none(IROp::Ret));
    uint64_t a = 0, b = 0;
    CHECK_EQ(run_ir_prog(q, 0, &a), (int)ST_HALT);
    const FuseStats s2 = ir_fuse(q);
    CHECK_TRUE(s2.fused >= 1);
    CHECK_EQ(run_ir_prog(q, 0, &b), (int)ST_HALT);
    CHECK_U64(b, a);
    CHECK_U64(b, 7);
  }

  {
    IRProgram q;
    q.add(IRCommand::mov(IROperand::R(REG_RCX), IROperand::I(0)));
    q.add(IRCommand::mov(IROperand::R(REG_RAX), IROperand::I(0)));
    const int loop = q.new_label();
    q.bind(loop);
    q.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RAX), IROperand::R(REG_RCX)));
    q.add(IRCommand::unary(UnaryOp::Inc, REG_RCX));
    q.add(IRCommand::alu(AluOp::Cmp, IROperand::R(REG_RCX), IROperand::I(10)));
    q.add(IRCommand::br(IROp::Jcc, loop));
    q.cmds.back().sub = 5;
    q.add(IRCommand::none(IROp::Ret));
    uint64_t want2 = 0, got2 = 0;
    CHECK_EQ(run_ir_prog(q, 0, &want2), (int)ST_HALT);
    const FuseStats s3 = ir_fuse(q);
    CHECK_TRUE(s3.fused >= 1);
    bool imm_src = false;
    for (const IRCommand& cc : q.cmds) {
      if (cc.op == IROp::CmpJcc && cc.src.kind == IRKind::Imm) imm_src = true;
    }
    CHECK_TRUE(imm_src);
    CHECK_EQ(run_ir_prog(q, 0, &got2), (int)ST_HALT);
    CHECK_U64(got2, want2);
    CHECK_U64(got2, 45);
  }
}

static void test_antidbg() {

  {
    const char* names[] = {"NtQueryInformationProcess", "ntdll.dll",
                           "RtlAddVectoredExceptionHandler", "kernel32.dll",
                           "ExitProcess"};
    for (const char* n : names) {
      CHECK_U64(hyda::api_hash_c(n), hyda::api_name_hash(n));
    }
  }

  {
    const uint64_t seeds[] = {0x2C7A1B4E9D3F5A86ull, 1ull,
                              0xA1B2C3D4E5F60718ull, 0xFFFFFFFFFFFFFFFFull,
                              0x8000000000000001ull};
    for (uint64_t s : seeds) {
      const uint64_t saved = ::g_vm_seed;
      ::g_vm_seed = s;
      bool seen[hyda::HYDA_ADBG_CHECK_COUNT] = {};
      for (uint32_t i = 0; i < hyda::HYDA_ADBG_CHECK_COUNT; ++i) {
        const uint32_t sel = hyda::adbg_sel_at(i);
        CHECK_TRUE(sel < hyda::HYDA_ADBG_CHECK_COUNT);
        seen[sel] = true;
      }
      for (uint32_t k = 0; k < hyda::HYDA_ADBG_CHECK_COUNT; ++k) {
        CHECK_TRUE(seen[k]);
      }
      ::g_vm_seed = saved;
    }
  }

  {
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_PEB_BEING, 0, 0), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_PEB_BEING, 0, 1),
             hyda::HYDA_ADBG_WEIGHT_HARD);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_NTGLOBAL, 0, 0x70),
             hyda::HYDA_ADBG_WEIGHT_HARD);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_HEAP_FORCE, 0, 0), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_DEBUG_PORT, 0, 0), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_DEBUG_OBJ, 0, hyda::HYDA_ADBG_SENTINEL), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_DEBUG_FLAGS, 0, 1), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_DEBUG_FLAGS, 0, 0),
             hyda::HYDA_ADBG_WEIGHT_HARD);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_DR, 0, 0), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_DR, 2, 0x1),
             hyda::HYDA_ADBG_WEIGHT_HARD);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_TF, 0, 0), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_INT3, 0, 1), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_INT3, 0, 0),
             hyda::HYDA_ADBG_WEIGHT_HARD);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_MODULE_SCAN, 0, 0), 0);
    CHECK_EQ(hyda::adbg_eval(hyda::ADBG_MODULE_SCAN, 0, 1),
             hyda::HYDA_ADBG_WEIGHT_SOFT);
    CHECK_EQ(hyda::adbg_eval(999u, 0, 0), hyda::HYDA_ADBG_WEIGHT_HARD);
  }

  {

    auto clean_obs = [](uint32_t sel, uint32_t arg) -> uint64_t {
      switch (sel) {
        case hyda::ADBG_DEBUG_FLAGS:
        case hyda::ADBG_INT3:
          return 1;
        case hyda::ADBG_NTDLL_CRC:
          return hyda::adbg_ntdll_want(arg);
        default:
          return 0;
      }
    };
    uint32_t cursor = hyda::adbg_cursor_mask();
    uint64_t poison = hyda::adbg_poison_mask();
    int dirty = 0;
    for (int i = 0; i < 200; ++i) {
      dirty += hyda::audit_adbg_phase(clean_obs, hyda::HYDA_ADBG_TICK_BATCH,
                                      cursor, poison) != 0;
    }
    CHECK_EQ(dirty, 0);
    CHECK_U64(poison ^ hyda::adbg_poison_mask(), 0);

    CHECK_TRUE((cursor ^ hyda::adbg_cursor_mask()) < hyda::HYDA_ADBG_CHECK_COUNT);

    cursor = hyda::adbg_cursor_mask();
    poison = hyda::adbg_poison_mask();
    uint32_t sanction = 0;
    for (int i = 0; i < 200 && sanction == 0; ++i) {
      sanction = hyda::audit_adbg_phase(
          [](uint32_t, uint32_t) -> uint64_t { return hyda::HYDA_ADBG_SENTINEL; },
          hyda::HYDA_ADBG_TICK_BATCH, cursor, poison);
    }
    CHECK_EQ(sanction, hyda::HYDA_ADBG_FAIL_CODE);

    cursor = hyda::adbg_cursor_mask();
    poison = hyda::adbg_poison_mask();
    sanction = 0;
    for (int i = 0; i < 400 && sanction == 0; ++i) {
      sanction = hyda::audit_adbg_phase(
          [&clean_obs](uint32_t sel, uint32_t arg) -> uint64_t {
            return sel == hyda::ADBG_MODULE_SCAN ? 1ull : clean_obs(sel, arg);
          },
          hyda::HYDA_ADBG_TICK_BATCH, cursor, poison);
    }
    CHECK_EQ(sanction, hyda::HYDA_ADBG_LATENT_CODE);
  }
}

static void test_hydak_speed_paths() {

  auto ref = [](uint8_t* p, uint32_t n, uint64_t key) {
    uint64_t idx = 0;
    uint32_t i = 0;
    while (i < n) {
      const uint64_t z = hyda::crypt_mix(idx, key);
      for (unsigned b = 0; b < 8 && i < n; ++b, ++i) {
        p[i] = static_cast<uint8_t>(p[i] ^ static_cast<uint8_t>(z >> (8 * b)));
      }
      ++idx;
    }
  };

  std::printf("  KAP hizli yol: avx2=%s\n",
              hyda::detail::hydak_avx2_ok() ? "VAR" : "absent (portable)");

  const uint32_t sizes[] = {0,   1,   7,    8,    9,    31,   32,   33,
                            63,  64,  65,   127,  128,  129,  255,  256,
                            257, 1023, 4096, 51296};
  int bad = 0;
  for (uint32_t n : sizes) {
    for (int ki = 0; ki < 4; ++ki) {
      const uint64_t key = hyda::hydak_key_for(0x85c000u + ki * 0x1000u);
      std::vector<uint8_t> a(n), b(n), c(n);
      for (uint32_t i = 0; i < n; ++i) {
        a[i] = static_cast<uint8_t>(i * 131u + 7u);
      }
      b = a;
      c = a;
      ref(b.data(), n, key);
      hyda::detail::hydak_xor_scalar(c.data(), n, key);
      hyda::hydak_xor(a.data(), n, key);
      if (a != b || c != b) ++bad;
    }
  }
  CHECK_TRUE(bad == 0);

  {
    std::vector<uint8_t> buf(4096);
    for (size_t i = 0; i < buf.size(); ++i) {
      buf[i] = static_cast<uint8_t>(i * 17u + 5u);
    }
    const std::vector<uint8_t> orig = buf;
    const uint64_t key = hyda::hydak_key_for(0x2a0000u);
    hyda::hydak_xor(buf.data(), static_cast<uint32_t>(buf.size()), key);
    CHECK_TRUE(buf != orig);
    hyda::hydak_xor(buf.data(), static_cast<uint32_t>(buf.size()), key);
    CHECK_TRUE(buf == orig);
  }

  {
    std::vector<uint8_t> buf(64, 0xA5);
    const std::vector<uint8_t> orig = buf;
    hyda::hydak_xor(buf.data(), static_cast<uint32_t>(buf.size()), 0);
    CHECK_TRUE(buf == orig);
  }
}

static void set_xmm(int n, const void* p) {
  std::memcpy(hyda::fp_state()->xmm(n), p, 16);
}
static void get_xmm(int n, void* p) {
  std::memcpy(p, hyda::fp_state()->xmm(n), 16);
}
static bool f_isnan(float f) { return f != f; }

static void test_sse() {
  alignas(16) static float fm[32];

  {
    VMContext ctx;
    Asm a;
    for (int i = 0; i < 32; ++i) fm[i] = 0.0f;
    fm[0] = 2.5f;
    fm[1] = 1.5f;
    const float v0[4] = {10.0f, 20.0f, 30.0f, 40.0f};
    set_xmm(0, v0);
    a.i_rq(Op::MOV_RI, REG_RBX, (int64_t)(uintptr_t)fm);
    a.i_mem(Op::SSE_LD4, 1, REG_RBX, NO_MEM, 1, 0);
    a.i_rrb(Op::SSE_MOV, 2, 1, kSseMovFull);
    a.i_rrb(Op::SSE_BIN, 0, 1, (int)SseBin::AddSS);
    a.i_rrb(Op::SSE_BIN, 2, 0, (int)SseBin::MulSS);
    a.i_mem(Op::SSE_ST4, 2, REG_RBX, NO_MEM, 1, 8);
    a.i_mem(Op::SSE_ST16, 0, REG_RBX, NO_MEM, 1, 16);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_TRUE(fm[2] == 31.25f);
    float out16[4];
    std::memcpy(out16, &fm[4], 16);
    CHECK_TRUE(out16[0] == 12.5f && out16[1] == 20.0f && out16[2] == 30.0f &&
               out16[3] == 40.0f);
    float o2[4];
    get_xmm(2, o2);
    CHECK_TRUE(o2[0] == 31.25f && o2[1] == 0.0f && o2[2] == 0.0f && o2[3] == 0.0f);
  }

  {
    VMContext ctx;
    Asm a;
    const float p0[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    const float p1[4] = {0.5f, 0.25f, 0.125f, 2.0f};
    set_xmm(0, p0);
    set_xmm(1, p1);
    a.i_rrb(Op::SSE_BIN, 0, 1, (int)SseBin::AddPS);
    a.i_rrb(Op::SSE_BIN, 0, 1, (int)SseBin::MulPS);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    float r[4];
    get_xmm(0, r);
    CHECK_TRUE(r[0] == 0.75f && r[1] == 0.5625f && r[2] == 0.390625f &&
               r[3] == 12.0f);

    const double d0[2] = {8.0, 9.0};
    const double d1[2] = {2.0, 4.0};
    set_xmm(2, d0);
    set_xmm(3, d1);
    Asm b;
    b.i_rrb(Op::SSE_BIN, 2, 3, (int)SseBin::AddPD);
    b.i_rrb(Op::SSE_BIN, 2, 3, (int)SseBin::DivPD);
    b.i0(Op::HALT);
    CHECK_EQ(run(ctx, b), (int)ST_HALT);
    double dr[2];
    get_xmm(2, dr);
    CHECK_TRUE(dr[0] == 5.0 && dr[1] == 3.25);
  }

  {
    const uint64_t q0[2] = {0x0F0F0F0F0F0F0F0Full, 0xFFFFFFFF00000000ull};
    const uint64_t q1[2] = {0x00FF00FF00FF00FFull, 0x00000000FFFFFFFFull};
    struct Case {
      SseBin op;
      uint64_t want[2];
    };
    const Case cases[] = {
        {SseBin::PAnd, {q0[0] & q1[0], q0[1] & q1[1]}},
        {SseBin::AndNPS, {~q0[0] & q1[0], ~q0[1] & q1[1]}},
        {SseBin::OrPS, {q0[0] | q1[0], q0[1] | q1[1]}},
        {SseBin::XorPD, {q0[0] ^ q1[0], q0[1] ^ q1[1]}},
    };
    for (const Case& c : cases) {
      VMContext ctx;
      Asm a;
      set_xmm(4, q0);
      set_xmm(5, q1);
      a.i_rrb(Op::SSE_BIN, 4, 5, (int)c.op);
      a.i0(Op::HALT);
      CHECK_EQ(run(ctx, a), (int)ST_HALT);
      uint64_t out[2];
      get_xmm(4, out);
      CHECK_U64(out[0], c.want[0]);
      CHECK_U64(out[1], c.want[1]);
    }
  }

  {
    const uint8_t b0[16] = {250, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    const uint8_t b1[16] = {10, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    set_xmm(6, b0);
    set_xmm(7, b1);
    VMContext ctx;
    Asm a;
    a.i_rrb(Op::SSE_BIN, 6, 7, (int)SseBin::PAddB);
    a.i_rrb(Op::SSE_BIN, 6, 7, (int)SseBin::PSubB);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    uint8_t out[16];
    get_xmm(6, out);
    CHECK_EQ(out[0], 250);
    CHECK_EQ(out[1], 10);
    for (int i = 2; i < 16; ++i) CHECK_EQ(out[i], b0[i]);

    const uint64_t q0[2] = {~0ull, 5};
    const uint64_t q1[2] = {1, 0xFFFFFFFFFFFFFFFFull};
    set_xmm(8, q0);
    set_xmm(9, q1);
    VMContext c2;
    Asm b;
    b.i_rrb(Op::SSE_BIN, 8, 9, (int)SseBin::PAddQ);
    b.i_rrb(Op::SSE_BIN, 8, 9, (int)SseBin::PSubD);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_HALT);
    uint64_t oq[2];
    get_xmm(8, oq);

    CHECK_U64(oq[0], 0x0000000100000000ull - 1ull);
    CHECK_U64(oq[1], 0x0000000100000005ull);
  }

  {
    const float nan = __builtin_nanf("");
    const float a0[4] = {nan, 1.0f, 5.0f, 3.0f};
    const float b0[4] = {2.0f, nan, 2.0f, 4.0f};
    set_xmm(0, a0);
    set_xmm(1, b0);
    VMContext ctx;
    Asm a;
    a.i_rrb(Op::SSE_BIN, 0, 1, (int)SseBin::MinSS);
    a.i_rrb(Op::SSE_BIN, 1, 0, (int)SseBin::MaxSS);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    float r0[4], r1[4];
    get_xmm(0, r0);
    get_xmm(1, r1);
    CHECK_TRUE(r0[0] == 2.0f && !f_isnan(r0[0]));
    CHECK_TRUE(r1[0] == 2.0f && !f_isnan(r1[0]));

    set_xmm(2, b0);
    set_xmm(3, a0);
    VMContext c2;
    Asm b;
    b.i_rrb(Op::SSE_BIN, 2, 3, (int)SseBin::MaxPS);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_HALT);
    float r2[4];
    get_xmm(2, r2);
    CHECK_TRUE(f_isnan(r2[0]));
    CHECK_TRUE(r2[1] == 1.0f && r2[2] == 5.0f && r2[3] == 4.0f);
  }

  {
    const float v[4] = {4.0f, 9.0f, 16.0f, 25.0f};
    set_xmm(0, v);
    VMContext ctx;
    Asm a;
    a.i_rb(Op::SSE_UN, 0, (int)SseUn::SqrtPS);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    float r[4];
    get_xmm(0, r);
    CHECK_TRUE(r[0] == 2.0f && r[1] == 3.0f && r[2] == 4.0f && r[3] == 5.0f);

    const float s0[4] = {2.25f, 7.0f, 8.0f, 9.0f};
    set_xmm(1, s0);
    VMContext c2;
    Asm b;
    b.i_rb(Op::SSE_UN, 1, (int)SseUn::SqrtSS);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_HALT);
    float s1[4];
    get_xmm(1, s1);
    CHECK_TRUE(s1[0] == 1.5f && s1[1] == 7.0f && s1[2] == 8.0f && s1[3] == 9.0f);

    const double d0[2] = {0.25, 81.0};
    set_xmm(2, d0);
    VMContext c3;
    Asm c;
    c.i_rb(Op::SSE_UN, 2, (int)SseUn::SqrtPD);
    c.i0(Op::HALT);
    CHECK_EQ(run(c3, c), (int)ST_HALT);
    double dr[2];
    get_xmm(2, dr);
    CHECK_TRUE(dr[0] == 0.5 && dr[1] == 9.0);
  }

  {
    struct Case {
      float x, y;
      bool cf, pf, zf;
    };
    const Case cases[] = {
        {1.0f, 2.0f, true, false, false},
        {2.0f, 1.0f, false, false, false},
        {3.0f, 3.0f, false, false, true},
        {__builtin_nanf(""), 1.0f, true, true, true},
        {1.0f, __builtin_nanf(""), true, true, true},
    };
    for (const Case& c : cases) {
      const float x[4] = {c.x, 0, 0, 0};
      const float y[4] = {c.y, 0, 0, 0};
      set_xmm(0, x);
      set_xmm(1, y);
      VMContext ctx;
      Asm a;
      a.i_rrb(Op::SSE_CMP, 0, 1, (int)SseCmp::UcomiSS);
      a.i0(Op::HALT);
      CHECK_EQ(run(ctx, a), (int)ST_HALT);
      const uint64_t fl = ctx.r[vsl(REG_RFLAGS)];
      CHECK_EQ(flag_bit(fl, F_CF), c.cf);
      CHECK_EQ(flag_bit(fl, F_PF), c.pf);
      CHECK_EQ(flag_bit(fl, F_ZF), c.zf);
      CHECK_EQ(flag_bit(fl, F_OF), 0);
      CHECK_EQ(flag_bit(fl, F_SF), 0);
      CHECK_EQ(flag_bit(fl, F_AF), 0);
    }
    const double dx[2] = {-1.5, 0}, dy[2] = {-2.5, 0};
    set_xmm(0, dx);
    set_xmm(1, dy);
    VMContext ctx;
    Asm a;
    a.i_rrb(Op::SSE_CMP, 0, 1, (int)SseCmp::ComiSD);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_CF));
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_ZF));
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_PF));
  }

  {
    const float x0[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    set_xmm(0, x0);
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RBX, (uint64_t)(int64_t)-16777217);
    a.i_rrb_cvt(Op::SSE_CVT, 0, false, REG_RBX, true, (int)SseCvt::Si2SD64);
    a.i_rrb_cvt(Op::SSE_CVT, REG_RCX, true, 0, false, (int)SseCvt::TtSD2Si64);
    a.i_rq(Op::MOV_RI, REG_RDX, 200);
    a.i_rrb_cvt(Op::SSE_CVT, 1, false, REG_RDX, true, (int)SseCvt::Si2SS32);
    a.i_rrb_cvt(Op::SSE_CVT, REG_RSI, true, 1, false, (int)SseCvt::TtSS2Si32);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    CHECK_U64(ctx.r[vsl(REG_RCX)], (uint64_t)(int64_t)-16777217);
    CHECK_U64(ctx.r[vsl(REG_RSI)], 200);
    double d[2];
    get_xmm(0, d);
    CHECK_TRUE(d[0] == -16777217.0);
    float f[4];
    get_xmm(1, f);
    CHECK_TRUE(f[0] == 200.0f);
    float up[4];
    get_xmm(0, up);
    CHECK_TRUE(up[2] == 3.0f && up[3] == 4.0f);

    const uint64_t q[2] = {0xAAAAAAAAAAAAAAAAull, 0xBBBBBBBBBBBBBBBBull};
    set_xmm(2, q);
    VMContext c2;
    Asm b;
    b.i_rq(Op::MOV_RI, REG_RBX, 0x1122334455667788ull);
    b.i_rrb_cvt(Op::SSE_CVT, 2, false, REG_RBX, true, (int)SseCvt::MovqToX);
    b.i_rrb_cvt(Op::SSE_CVT, REG_RCX, true, 2, false, (int)SseCvt::MovqFromX);
    b.i_rrb_cvt(Op::SSE_CVT, 3, false, REG_RBX, true, (int)SseCvt::MovdToX);
    b.i_rrb_cvt(Op::SSE_CVT, REG_RDX, true, 3, false, (int)SseCvt::MovdFromX);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_HALT);
    CHECK_U64(c2.r[vsl(REG_RCX)], 0x1122334455667788ull);
    CHECK_U64(c2.r[vsl(REG_RDX)], 0x55667788ull);
    uint64_t mq[2], md[2];
    get_xmm(2, mq);
    get_xmm(3, md);
    CHECK_U64(mq[0], 0x1122334455667788ull);
    CHECK_U64(mq[1], 0ull);
    CHECK_U64(md[0], 0x55667788ull);
    CHECK_U64(md[1], 0ull);

    const double dsrc[2] = {6.5, 42.0};
    set_xmm(4, dsrc);
    VMContext c3;
    Asm c;
    c.i_rrb_cvt(Op::SSE_CVT, 4, false, 4, false, (int)SseCvt::Sd2Ss);
    c.i0(Op::HALT);
    CHECK_EQ(run(c3, c), (int)ST_HALT);
    float sd[4];
    get_xmm(4, sd);
    CHECK_TRUE(sd[0] == 6.5f);
    double dd[2];
    get_xmm(4, dd);
    CHECK_TRUE(dd[1] == 42.0);

    const float big[4] = {1e30f, 0, 0, 0};
    set_xmm(5, big);
    VMContext c4;
    Asm e;
    e.i_rrb_cvt(Op::SSE_CVT, REG_RAX, true, 5, false, (int)SseCvt::TtSS2Si64);
    e.i_rrb_cvt(Op::SSE_CVT, REG_RCX, true, 5, false, (int)SseCvt::TtSS2Si32);
    e.i0(Op::HALT);
    CHECK_EQ(run(c4, e), (int)ST_HALT);
    CHECK_U64(c4.r[vsl(REG_RAX)], 0x8000000000000000ull);
    CHECK_U64(c4.r[vsl(REG_RCX)], 0x80000000ull);
  }

  {
    const uint32_t s[4] = {11, 22, 33, 44};
    const uint32_t t[4] = {55, 66, 77, 88};
    set_xmm(0, s);
    set_xmm(1, t);
    VMContext ctx;
    Asm a;
    a.i_rrb(Op::SSE_SHUF, 2, 1, 0x1B);
    a.u8((uint8_t)SseShuf::Pshufd);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    uint32_t sh[4];
    get_xmm(2, sh);
    CHECK_EQ(sh[0], 88);
    CHECK_EQ(sh[1], 77);
    CHECK_EQ(sh[2], 66);
    CHECK_EQ(sh[3], 55);

    set_xmm(0, s);
    set_xmm(1, t);
    VMContext c2;
    Asm b;
    b.i_rrb(Op::SSE_SHUF, 0, 1, 0x1B);
    b.u8((uint8_t)SseShuf::ShufPS);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_HALT);
    uint32_t sp[4];
    get_xmm(0, sp);

    CHECK_EQ(sp[0], 44);
    CHECK_EQ(sp[1], 33);
    CHECK_EQ(sp[2], 66);
    CHECK_EQ(sp[3], 55);

    set_xmm(0, s);
    set_xmm(1, t);
    VMContext c3;
    Asm c;
    c.i_rrb(Op::SSE_SHUF, 0, 1, 0);
    c.u8((uint8_t)SseShuf::UnpckLPS);
    c.i0(Op::HALT);
    CHECK_EQ(run(c3, c), (int)ST_HALT);
    uint32_t up[4];
    get_xmm(0, up);
    CHECK_EQ(up[0], 11);
    CHECK_EQ(up[1], 55);
    CHECK_EQ(up[2], 22);
    CHECK_EQ(up[3], 66);

    const uint64_t aq[2] = {0x1111, 0x2222};
    const uint64_t bq[2] = {0x3333, 0x4444};
    set_xmm(0, aq);
    set_xmm(1, bq);
    VMContext c4;
    Asm d;
    d.i_rrb(Op::SSE_SHUF, 0, 1, 0);
    d.u8((uint8_t)SseShuf::UnpckHQDQ);
    d.i0(Op::HALT);
    CHECK_EQ(run(c4, d), (int)ST_HALT);
    uint64_t uq[2];
    get_xmm(0, uq);
    CHECK_U64(uq[0], 0x2222);
    CHECK_U64(uq[1], 0x4444);
  }

  {
    const float d0[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    const float s0[4] = {9.0f, 8.0f, 7.0f, 6.0f};
    set_xmm(0, d0);
    set_xmm(1, s0);
    VMContext ctx;
    Asm a;
    a.i_rrb(Op::SSE_MOV, 0, 1, kSseMovSS);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    float r[4];
    get_xmm(0, r);
    CHECK_TRUE(r[0] == 9.0f && r[1] == 2.0f && r[2] == 3.0f && r[3] == 4.0f);

    const double dd[2] = {5.5, 6.5};
    set_xmm(2, dd);
    set_xmm(3, s0);
    double before[2];
    get_xmm(3, before);
    VMContext c2;
    Asm b;
    b.i_rrb(Op::SSE_MOV, 3, 2, kSseMovSD);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_HALT);
    double rd[2];
    get_xmm(3, rd);
    CHECK_TRUE(rd[0] == 5.5 && rd[1] == before[1]);

    set_xmm(3, s0);
    VMContext c3;
    Asm c;
    c.i_rrb(Op::SSE_MOV, 3, 2, kSseMovQ);
    c.i0(Op::HALT);
    CHECK_EQ(run(c3, c), (int)ST_HALT);
    double rq[2];
    get_xmm(3, rq);
    CHECK_TRUE(rq[0] == 5.5 && rq[1] == 0.0);

    set_xmm(3, s0);
    VMContext c4;
    Asm d;
    d.i_rrb(Op::SSE_MOV, 3, 0, kSseMovFull);
    d.i0(Op::HALT);
    CHECK_EQ(run(c4, d), (int)ST_HALT);
    float rf[4];
    get_xmm(3, rf);
    CHECK_TRUE(rf[0] == 9.0f && rf[1] == 2.0f && rf[2] == 3.0f && rf[3] == 4.0f);
  }

  {
    for (int i = 0; i < 32; ++i) fm[i] = 0.0f;
    fm[3] = 0.5f;
    fm[10] = 2.0f;
    const float acc[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    set_xmm(0, acc);
    VMContext ctx;
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RBX, (int64_t)(uintptr_t)fm);
    a.i_rq(Op::MOV_RI, REG_RCX, 3);
    a.i_mem(Op::SSE_LD4, 1, REG_RBX, REG_RCX, 4, 0);
    a.i_rrb(Op::SSE_BIN, 0, 1, (int)SseBin::DivSS);
    a.raw(Op::SSE_BINM);
    a.u8(0);
    a.u8((uint8_t)vsl(REG_RBX));
    a.u8(NO_MEM);
    a.sb(1);
    a.s32(40);
    a.u8((uint8_t)SseBin::MulSS);
    a.raw(Op::SSE_CMPM);
    a.u8(0);
    a.u8((uint8_t)vsl(REG_RBX));
    a.u8(NO_MEM);
    a.sb(1);
    a.s32(12);
    a.u8((uint8_t)SseCmp::UcomiSS);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_HALT);
    float r[4];
    get_xmm(0, r);
    CHECK_TRUE(r[0] == 4.0f && r[1] == 2.0f && r[2] == 3.0f && r[3] == 4.0f);
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_CF));
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_ZF));
    CHECK_TRUE(!flag_bit(ctx.r[vsl(REG_RFLAGS)], F_PF));
  }

  {
    VMContext ctx;
    Asm a;
    a.i_rrb(Op::SSE_BIN, 16, 0, (int)SseBin::AddSS);
    a.i0(Op::HALT);
    CHECK_EQ(run(ctx, a), (int)ST_BAD_REG);

    VMContext c2;
    Asm b;
    b.i_rq(Op::MOV_RI, REG_RBX, (int64_t)(uintptr_t)fm);
    b.i_mem(Op::SSE_LD16, 24, REG_RBX, NO_MEM, 1, 0);
    b.i0(Op::HALT);
    CHECK_EQ(run(c2, b), (int)ST_BAD_REG);

    VMContext c3;
    Asm c;
    c.i_rb(Op::SSE_UN, 20, (int)SseUn::SqrtSS);
    c.i0(Op::HALT);
    CHECK_EQ(run(c3, c), (int)ST_BAD_REG);
  }
}

// The per-build opcode permutation is a bijection.
HYDA_TEST(Vm, permutation, "Every opcode slot maps to its own handler") {
  g_rep = &r;
  test_permutation();
}

// The dispatcher runs a straight-line block and returns the sum.
HYDA_TEST(Vm, basic_arith, "MOV/ADD/SUB/XOR through the dispatcher") {
  g_rep = &r;
  test_basic_arith();
}

// Conditional jumps loop until the counter runs out.
HYDA_TEST(Vm, loop_sum, "Branch loop accumulates the expected sum") {
  g_rep = &r;
  test_loop_sum();
}

// A nested call returns to the instruction after it.
HYDA_TEST(Vm, call_ret, "CALL/RET round-trip inside the bytecode") {
  g_rep = &r;
  test_call_ret();
}

// Memory operands read and write the same bytes as native.
HYDA_TEST(Vm, memory, "Loads and stores with base+index addressing") {
  g_rep = &r;
  test_memory();
}

// Partial writes must not disturb the rest of the slot.
HYDA_TEST(Vm, size_semantics, "8/16/32-bit writes keep the upper bits") {
  g_rep = &r;
  test_size_semantics();
}

// Count 0, 1, width-1 and width are compared against C.
HYDA_TEST(Vm, shifts, "Shift opcodes match the reference on edge counts") {
  g_rep = &r;
  test_shifts();
}

// RDX:RAX results and the flags line up with the host.
HYDA_TEST(Vm, mul_div, "Signed and unsigned multiply/divide") {
  g_rep = &r;
  test_mul_div();
}

// All 16 condition codes are exercised.
HYDA_TEST(Vm, cmov, "CMOV honours every condition code") {
  g_rep = &r;
  test_cmov();
}

// CF/OF/ZF/SF/PF are compared for add, sub, adc, sbb, logic, inc/dec and neg.
HYDA_TEST(Flags, flag_reference, "ALU flags match a reference implementation") {
  g_rep = &r;
  test_flag_reference();
}

// Malformed bytecode is rejected instead of executed.
HYDA_TEST(Vm, errors, "Bad opcode/register/fault set the right status") {
  g_rep = &r;
  test_errors();
}

// The guest stack bounds are enforced.
HYDA_TEST(Vm, stack_guard, "Push/pop outside the stack limits fault") {
  g_rep = &r;
  test_stack_guard();
}

// Decoding every slot consumes the bytecode exactly.
HYDA_TEST(Report, disassembly, "The disassembler walks the whole program") {
  g_rep = &r;
  test_disasm_walk();
}

// Mutated programs answer the same as the clean one.
HYDA_TEST(Mutate, mutation, "Junk/noise/inverse keep results identical") {
  g_rep = &r;
  test_mutate();
}

// Index mask, key/base variants, entry shift and call style are all covered.
HYDA_TEST(Dispatch, profiles, "Every dispatch profile executes the same") {
  g_rep = &r;
  test_dispatch_profiles();
}

// Each instruction carries its own key material.
HYDA_TEST(Codec, operand_crypt, "Operands decrypt per instruction") {
  g_rep = &r;
  test_operand_crypt();
}

// Assemble, encode, decode and compare.
HYDA_TEST(Codec, codec, "Bytecode encoder/decoder round-trip") {
  g_rep = &r;
  test_codec();
}

// The dead-flag pass only removes unobservable work.
HYDA_TEST(Flags, dead_flags, "Dropped flag writes never change a branch") {
  g_rep = &r;
  test_dead_flags();
}

// Mixed boolean-arithmetic forms are checked against the plain expression.
HYDA_TEST(Mutate, mba_identities, "MBA rewrites are algebraically identical") {
  g_rep = &r;
  test_mba_identities();
}

// Every generated body is compared with the base opcode.
HYDA_TEST(Mutate, mba_bodies, "MBA bodies compute the same value and flags") {
  g_rep = &r;
  test_mba_bodies();
}

// Split bodies are reassembled into an equivalent opcode.
HYDA_TEST(Mutate, body_split, "Handler bodies split without changing results") {
  g_rep = &r;
  test_body_split();
}

// The alternate dispatch loop is result-identical.
HYDA_TEST(Vm2, core, "Second dispatcher runs the same bytecode") {
  g_rep = &r;
  test_vm2_core();
}

// Packed and scalar operations are compared against native.
HYDA_TEST(Sse, simd, "SSE subset matches the host") {
  g_rep = &r;
  test_sse();
}

// A nested run must not disturb the outer frame.
HYDA_TEST(Vm2, nested, "Nested VM entry keeps its own stack") {
  g_rep = &r;
  test_nested_vm();
}

// Two instances run the same program with different keys.
HYDA_TEST(Vm2, instance_seed, "Per-instance seeds differ but agree on results") {
  g_rep = &r;
  test_instance_seed();
}

// Header fields survive a write/read cycle.
HYDA_TEST(Codec, blob_header, "Blob header parse/serialize round-trip") {
  g_rep = &r;
  test_blob_header();
}

// A corrupt register index stops the VM with a status.
HYDA_TEST(Vm, bad_register, "Out-of-range register slots are rejected") {
  g_rep = &r;
  test_bad_register();
}

// The dispatch table never holds absolute handler addresses.
HYDA_TEST(Dispatch, handler_hiding, "Handler offsets are stored relative and obscured") {
  g_rep = &r;
  test_handler_table_hiding();
}

// A modified shard must fail verification.
HYDA_TEST(Hydak, shard, "Shard build/verify round-trip and tamper detection") {
  g_rep = &r;
  test_hydak_shard();
}

// Every section is described and resolvable.
HYDA_TEST(Hydak, catalog, "Catalog lookup and layout") {
  g_rep = &r;
  test_hydak_catalog();
}

// The scanner reports the same set the catalog holds.
HYDA_TEST(Hydak, scan, "Catalog scan finds every section") {
  g_rep = &r;
  test_hydak_scan();
}

// The fast path and the full path agree.
HYDA_TEST(Hydak, fast_paths, "Cached decrypt paths stay correct") {
  g_rep = &r;
  test_hydak_speed_paths();
}

// Integrity chunks cover the image without gaps.
HYDA_TEST(Guard, integrity, "CRC over regions and hole splitting") {
  g_rep = &r;
  test_integrity();
}

// The anti-debug policy reacts to each flag set.
HYDA_TEST(Guard, antidbg, "Debug flag detection and policy") {
  g_rep = &r;
  test_antidbg();
}

// Fusion only merges instructions with identical effects.
HYDA_TEST(Mutate, fusion, "Fused pairs match the unfused results") {
  g_rep = &r;
  test_fuse();
}

// Every logical register maps to a distinct slot.
HYDA_TEST(Dispatch, vreg_perm, "Register slot permutation is a bijection") {
  g_rep = &r;
  test_vreg_perm();
}

// Prints a sample program; never fails.
HYDA_TEST(Report, demo, "Informational disassembly dump") {
  g_rep = &r;
  demo_disassembly();
}

int main(int argc, char** argv) {
  return hyda::test::Registry::instance().run(argc, argv);
}
