#pragma once

#include <cstddef>
#include <cstdint>

#include "hyda/core/context.hpp"

namespace hyda {

enum class V2 : uint8_t {
  NOP = 0,
  HALT,
  MOV_RR,
  MOV_RI,
  ADD,
  SUB,
  XOR,
  AND,
  OR,
  MUL,
  SHL,
  SHR,
  NOT,
  COUNT_
};

constexpr size_t kV2Count = static_cast<size_t>(V2::COUNT_);
constexpr unsigned kV2Regs = 8;

constexpr size_t kV2InsnSize = 12;

struct V2Insn {
  V2 op = V2::NOP;
  uint8_t dst = 0;
  uint8_t src = 0;
  uint64_t imm = 0;
};

struct Vm2Context {
  uint64_t r[kV2Regs];
  uint32_t status;
  uint32_t steps;
};

enum : uint32_t {
  V2_OK = 0,
  V2_BAD_LEN = 1,
  V2_BAD_SLOT = 2,
  V2_BAD_REG = 3,
  V2_NO_HALT = 4,
};

enum : unsigned {
  kV2ProgAdd = 0,
  kV2ProgSub = 1,
  kV2ProgXor = 2,
  kV2ProgCount = 3,
};

uint32_t vm2_encode(const V2Insn* ins, size_t n, uint8_t* out, size_t cap);

uint32_t vm2_make_program(unsigned id, unsigned form, uint8_t* out, size_t cap);

uint32_t vm2_run(Vm2Context& c, const uint8_t* prog, uint32_t len);

uint32_t vm2_eval(unsigned id, uint64_t a, uint64_t b, uint64_t* out);

void vm2_build();

}

extern "C" {
extern uint8_t hyda_vm2_map[256];
extern uint8_t hyda_vm2_slot[hyda::kV2Count];
extern uint8_t hyda_vm2_prog[hyda::kV2ProgCount][192];
extern uint32_t hyda_vm2_len[hyda::kV2ProgCount];
extern uint32_t hyda_vm2_runs;
extern uint8_t hyda_vm2_ready;
}
