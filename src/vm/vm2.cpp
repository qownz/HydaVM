#include "hyda/vm/vm2.hpp"

#include <cstring>

#include "hyda/core/config.hpp"
#include "hyda/core/opcodes.hpp"

extern "C" {

__attribute__((used)) uint8_t hyda_vm2_map[256];

__attribute__((used)) uint8_t hyda_vm2_slot[hyda::kV2Count];

__attribute__((used)) uint8_t hyda_vm2_prog[hyda::kV2ProgCount][192];
__attribute__((used)) uint32_t hyda_vm2_len[hyda::kV2ProgCount];
__attribute__((used)) uint32_t hyda_vm2_runs;
__attribute__((used)) uint8_t hyda_vm2_ready;

}

namespace hyda {
namespace {

constexpr uint8_t kV2Bad = 0xFF;

struct Builder {
  V2Insn ins[24];
  size_t n = 0;

  void add(V2 op, uint8_t d = 0, uint8_t s = 0, uint64_t imm = 0) {
    if (n >= sizeof(ins) / sizeof(ins[0])) return;
    ins[n].op = op;
    ins[n].dst = d;
    ins[n].src = s;
    ins[n].imm = imm;
    ++n;
  }
};

void build_program(unsigned id, unsigned form, Builder& b) {
  switch (id) {
    case kV2ProgAdd:
      if (form == 0) {
        b.add(V2::ADD, 0, 1);
      } else {

        b.add(V2::MOV_RR, 2, 0);
        b.add(V2::AND, 2, 1);
        b.add(V2::MOV_RR, 3, 0);
        b.add(V2::XOR, 3, 1);
        b.add(V2::ADD, 2, 2);
        b.add(V2::ADD, 3, 2);
        b.add(V2::MOV_RR, 0, 3);
      }
      break;
    case kV2ProgSub:
      if (form == 0) {
        b.add(V2::SUB, 0, 1);
      } else {

        b.add(V2::NOT, 1, 1);
        b.add(V2::MOV_RR, 2, 0);
        b.add(V2::AND, 2, 1);
        b.add(V2::ADD, 2, 2);
        b.add(V2::MOV_RR, 3, 0);
        b.add(V2::XOR, 3, 1);
        b.add(V2::ADD, 3, 2);
        b.add(V2::MOV_RI, 4, 0, 1);
        b.add(V2::ADD, 3, 4);
        b.add(V2::MOV_RR, 0, 3);
      }
      break;
    case kV2ProgXor:
    default:
      if (form == 0) {
        b.add(V2::XOR, 0, 1);
      } else {

        b.add(V2::MOV_RR, 2, 0);
        b.add(V2::OR, 2, 1);
        b.add(V2::MOV_RR, 3, 0);
        b.add(V2::AND, 3, 1);
        b.add(V2::SUB, 2, 3);
        b.add(V2::MOV_RR, 0, 2);
      }
      break;
  }
  b.add(V2::HALT);
}

}

uint32_t vm2_encode(const V2Insn* ins, size_t n, uint8_t* out, size_t cap) {
  if (ins == nullptr || out == nullptr || n == 0) return 0;
  if (!hyda_vm2_ready) vm2_build();
  if (cap < n * kV2InsnSize) return 0;
  for (size_t i = 0; i < n; ++i) {
    const size_t op = static_cast<size_t>(ins[i].op);
    if (op >= kV2Count || ins[i].dst >= kV2Regs || ins[i].src >= kV2Regs) {
      return 0;
    }
    uint8_t* p = out + i * kV2InsnSize;
    p[0] = hyda_vm2_slot[op];
    p[1] = ins[i].dst;
    p[2] = ins[i].src;
    p[3] = 0;
    std::memcpy(p + 4, &ins[i].imm, sizeof(ins[i].imm));
  }
  return static_cast<uint32_t>(n * kV2InsnSize);
}

uint32_t vm2_make_program(unsigned id, unsigned form, uint8_t* out, size_t cap) {
  if (id >= kV2ProgCount) return 0;
  Builder b;
  build_program(id, form & 1u, b);
  return vm2_encode(b.ins, b.n, out, cap);
}

namespace {

uint32_t vm2_exec(Vm2Context& c, const uint8_t* prog, uint32_t len) {
  if (prog == nullptr || len == 0 || (len % kV2InsnSize) != 0) return V2_BAD_LEN;

  const uint32_t total = len / static_cast<uint32_t>(kV2InsnSize);
  uint32_t pc = 0;
  c.steps = 0;
  for (;;) {
    if (pc + kV2InsnSize > len) return V2_NO_HALT;
    const uint8_t slot = prog[pc];
    const uint8_t d = prog[pc + 1];
    const uint8_t s = prog[pc + 2];
    uint64_t imm = 0;
    std::memcpy(&imm, prog + pc + 4, sizeof(imm));
    pc += kV2InsnSize;

    if (++c.steps > total) return V2_NO_HALT;
    if (d >= kV2Regs || s >= kV2Regs) return V2_BAD_REG;

    const uint8_t op = hyda_vm2_map[slot];
    if (op == kV2Bad || op >= kV2Count) return V2_BAD_SLOT;

    switch (static_cast<V2>(op)) {
      case V2::NOP:
        break;
      case V2::HALT:
        return V2_OK;
      case V2::MOV_RR:
        c.r[d] = c.r[s];
        break;
      case V2::MOV_RI:
        c.r[d] = imm;
        break;
      case V2::ADD:
        c.r[d] += c.r[s];
        break;
      case V2::SUB:
        c.r[d] -= c.r[s];
        break;
      case V2::XOR:
        c.r[d] ^= c.r[s];
        break;
      case V2::AND:
        c.r[d] &= c.r[s];
        break;
      case V2::OR:
        c.r[d] |= c.r[s];
        break;
      case V2::MUL:
        c.r[d] *= c.r[s];
        break;
      case V2::SHL:
        c.r[d] <<= (c.r[s] & 63u);
        break;
      case V2::SHR:
        c.r[d] >>= (c.r[s] & 63u);
        break;
      case V2::NOT:
        c.r[d] = ~c.r[d];
        break;
      default:
        return V2_BAD_SLOT;
    }
  }
}

}

uint32_t vm2_run(Vm2Context& c, const uint8_t* prog, uint32_t len) {
  if (!hyda_vm2_ready) vm2_build();
  const uint32_t st = vm2_exec(c, prog, len);
  c.status = st;
  return st;
}

uint32_t vm2_eval(unsigned id, uint64_t a, uint64_t b, uint64_t* out) {
  if (id >= kV2ProgCount || out == nullptr) return V2_BAD_LEN;
  if (!hyda_vm2_ready) vm2_build();
  Vm2Context c;
  for (unsigned i = 0; i < kV2Regs; ++i) c.r[i] = 0;
  c.r[0] = a;
  c.r[1] = b;
  c.status = V2_OK;
  c.steps = 0;
  const uint32_t st = vm2_run(c, hyda_vm2_prog[id], hyda_vm2_len[id]);
  if (st == V2_OK) {
    *out = c.r[0];
    ++hyda_vm2_runs;
  }
  return st;
}

void vm2_build() {

  uint64_t st = hyda::vm_seed() ^ 0x9C3D7E1B5A284F60ull;

  uint8_t pool[256];
  for (int i = 0; i < 256; ++i) pool[i] = static_cast<uint8_t>(i);
  for (int i = 255; i > 0; --i) {
    const size_t j = static_cast<size_t>(splitmix64(st) % static_cast<uint64_t>(i + 1));
    const uint8_t t = pool[i];
    pool[i] = pool[j];
    pool[j] = t;
  }
  for (int i = 0; i < 256; ++i) hyda_vm2_map[i] = kV2Bad;
  for (size_t op = 0; op < kV2Count; ++op) {
    hyda_vm2_slot[op] = pool[op];
    hyda_vm2_map[pool[op]] = static_cast<uint8_t>(op);
  }

  hyda_vm2_ready = 1;

  for (unsigned id = 0; id < kV2ProgCount; ++id) {
    const unsigned form = static_cast<unsigned>(splitmix64(st) & 1u);
    hyda_vm2_len[id] =
        vm2_make_program(id, form, hyda_vm2_prog[id], sizeof(hyda_vm2_prog[id]));
  }
}

}
