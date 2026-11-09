#pragma once

#include "hyda/core/config.hpp"
#include "hyda/core/opcodes.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hyda {

struct IRMem {
  int base = -1;
  int index = -1;
  uint8_t scale = 1;
  int32_t disp = 0;
};

enum class IRKind : uint8_t {
  None, Reg, Mem, Imm, Label,

  Xmm,
};

struct IROperand {
  IRKind kind = IRKind::None;
  int reg = 0;
  IRMem mem;
  int64_t imm = 0;
  int label = -1;
  uint8_t size = 8;

  static IROperand R(int r, uint8_t size = 8) { IROperand o; o.kind = IRKind::Reg; o.reg = r; o.size = size; return o; }
  static IROperand M(const IRMem& m, uint8_t size = 8) { IROperand o; o.kind = IRKind::Mem; o.mem = m; o.size = size; return o; }
  static IROperand I(int64_t v, uint8_t size = 8) { IROperand o; o.kind = IRKind::Imm; o.imm = v; o.size = size; return o; }
  static IROperand L(int l) { IROperand o; o.kind = IRKind::Label; o.label = l; return o; }
  static IROperand X(int r, uint8_t size = 16) { IROperand o; o.kind = IRKind::Xmm; o.reg = r; o.size = size; return o; }
};

enum class AluOp : uint8_t { Add = 0, Adc, Sub, Sbb, And, Or, Xor, Cmp };
enum class ShiftOp : uint8_t { Shl = 0, Shr, Sar, Rol, Ror };
enum class UnaryOp : uint8_t { Inc = 0, Dec, Not, Neg };
enum class ExtOp : uint8_t { Zx8 = 0, Zx16, Sx8, Sx16, Sxd };
enum class MulKind : uint8_t { Unsigned = 0, Signed };
enum class SignExtKind : uint8_t { Cdq = 0, Cqo };
enum class BitTestKind : uint8_t { Bt = 0, Bts, Btr, Btc };
enum class BitCountKind : uint8_t { Tz = 0, Lz, Pop };
enum class ImulKind : uint8_t { One = 0, Two, Three };

enum class IROp : uint16_t {
  Nop,
  Halt,

  Mov,
  Lea,
  Xchg,
  Cmov,
  Push,
  Pop,
  Pushf,
  Popf,

  Alu,
  Shift,
  Unary,
  Test,
  Imul,
  Mul,
  Div,
  SignExtend,
  Extend,
  Bswap,
  BitScan,
  BitCount,
  BitTest,

  Jmp,
  Jcc,
  Call,
  Ret,
  RetImm,
  JmpIndirect,

  CmpJcc,

  AluJcc,

  Junk,
  Noise,
  InvR,

  Native,

  SseLoad,
  SseStore,
  SseMov,
  SseBin,
  SseBinM,
  SseUn,
  SseCmp,
  SseCmpM,
  SseCvt,
  SseShuf,

  SseBin3,
  SseShift,
};

enum IRFlag : uint32_t {

  IRF_NO_FLAGS   = 1u << 0,
  IRF_NO_CRYPT   = 1u << 1,
  IRF_INVERSE    = 1u << 2,
  IRF_NATIVE     = 1u << 3,
  IRF_BACKWARD   = 1u << 4,
  IRF_NO_MERGE   = 1u << 5,

  IRF_IMAGE_RVA  = 1u << 6,
};

struct IRCommand {
  IROp op = IROp::Nop;
  uint8_t sub = 0;
  uint8_t size = 8;
  IROperand dst, src, aux;
  int label = -1;
  uint32_t flags = 0;
  uint64_t addr = 0;

  static IRCommand mov(IROperand d, IROperand s);
  static IRCommand lea(IROperand d, const IRMem& m);
  static IRCommand alu(AluOp k, IROperand d, IROperand s);
  static IRCommand shift(ShiftOp k, int reg, uint8_t count);
  static IRCommand unary(UnaryOp k, int reg);
  static IRCommand br(IROp op, int label);
  static IRCommand none(IROp op);
};

struct IRFlagEffect {
  uint32_t wr_max = 0xFFFFFFFFu;
  uint32_t wr_min = 0;
  bool reads = true;
};

constexpr uint32_t kIrAllFlags =
    (1u << F_CF) | (1u << F_PF) | (1u << F_AF) | (1u << F_ZF) |
    (1u << F_SF) | (1u << F_OF);

inline IRFlagEffect ir_flag_effect(const IRCommand& c) {
  const uint32_t CF = 1u << F_CF, PF = 1u << F_PF, AF = 1u << F_AF;
  const uint32_t ZF = 1u << F_ZF, SF = 1u << F_SF, OF = 1u << F_OF;

  const uint32_t CF_OF_SZP = CF | OF | PF | ZF | SF;
  switch (c.op) {
    case IROp::Alu:
      switch (static_cast<AluOp>(c.sub)) {

        case AluOp::Add: case AluOp::Sub: case AluOp::Cmp:
          return {kIrAllFlags, kIrAllFlags, false};

        case AluOp::Adc: case AluOp::Sbb:
          return {kIrAllFlags, kIrAllFlags, true};

        case AluOp::And: case AluOp::Or: case AluOp::Xor:
          return {kIrAllFlags & ~AF, kIrAllFlags & ~AF, false};
      }
      return {};
    case IROp::Test:
      return {kIrAllFlags & ~AF, kIrAllFlags & ~AF, false};
    case IROp::Unary:
      switch (static_cast<UnaryOp>(c.sub)) {

        case UnaryOp::Inc: case UnaryOp::Dec:
          return {kIrAllFlags & ~CF, kIrAllFlags & ~CF, false};
        case UnaryOp::Neg:
          return {kIrAllFlags, kIrAllFlags, false};
        case UnaryOp::Not:
          return {0, 0, false};
      }
      return {};
    case IROp::Shift:
      switch (static_cast<ShiftOp>(c.sub)) {

        case ShiftOp::Rol: case ShiftOp::Ror:
          return {CF | OF, 0, false};
        default:
          return {CF_OF_SZP, 0, false};
      }
    case IROp::Mul: case IROp::Imul:
      return {CF | OF, CF | OF, false};
    case IROp::BitTest:
      return {CF, CF, false};
    case IROp::BitScan:
      return {ZF, ZF, false};
    case IROp::BitCount:
      return {kIrAllFlags, kIrAllFlags, false};
    case IROp::Div:
      return {0, 0, false};
    case IROp::Popf:
      return {kIrAllFlags, kIrAllFlags, false};
    case IROp::Pushf:
    case IROp::Cmov:
    case IROp::Jcc:
      return {0, 0, true};

    case IROp::CmpJcc:
      return (c.aux.imm != 0) ? IRFlagEffect{kIrAllFlags & ~AF, kIrAllFlags & ~AF, false}
                              : IRFlagEffect{kIrAllFlags, kIrAllFlags, false};

    case IROp::AluJcc:
      switch (static_cast<AluOp>(c.sub)) {
        case AluOp::Add: case AluOp::Sub:
          return {kIrAllFlags, kIrAllFlags, false};
        case AluOp::And: case AluOp::Or: case AluOp::Xor:
          return {kIrAllFlags & ~AF, kIrAllFlags & ~AF, false};
        default:
          return {};
      }

    case IROp::Nop: case IROp::Halt: case IROp::Mov: case IROp::Lea:
    case IROp::Xchg: case IROp::Push: case IROp::Pop: case IROp::SignExtend:
    case IROp::Extend: case IROp::Bswap: case IROp::Junk: case IROp::Noise:
    case IROp::InvR:

    case IROp::SseLoad: case IROp::SseStore: case IROp::SseMov:
    case IROp::SseBin: case IROp::SseBinM: case IROp::SseUn:
    case IROp::SseCvt: case IROp::SseShuf:
    case IROp::SseBin3: case IROp::SseShift:
      return {0, 0, false};

    case IROp::SseCmp: case IROp::SseCmpM:
      return {kIrAllFlags, kIrAllFlags, false};

    default:
      return {};
  }
}

inline bool ir_cuts_flag_flow(const IRCommand& c) {
  switch (c.op) {
    case IROp::Jmp: case IROp::Jcc: case IROp::Call: case IROp::Ret:
    case IROp::RetImm: case IROp::JmpIndirect: case IROp::Halt:
    case IROp::Native:
      return true;
    case IROp::CmpJcc:
      return true;
    case IROp::AluJcc:
      return true;
    default:
      return false;
  }
}

constexpr size_t kIrDeadFlagScanLimit = 64;

inline bool ir_flag_only(const IRCommand& c) {
  switch (c.op) {
    case IROp::Alu:  return c.sub == static_cast<uint8_t>(AluOp::Cmp);
    case IROp::Test: return true;
    case IROp::BitTest: return c.sub == static_cast<uint8_t>(BitTestKind::Bt);
    default: return false;
  }
}

inline void ir_mark_dead_flags(std::vector<IRCommand>& cmds) {
  for (size_t i = 0; i < cmds.size(); ++i) {
    IRCommand& x = cmds[i];
    x.flags &= ~static_cast<uint32_t>(IRF_NO_FLAGS);
    if (ir_cuts_flag_flow(x)) continue;
    const IRFlagEffect ex = ir_flag_effect(x);
    if (ex.wr_max == 0) continue;

    size_t seen = 0;
    for (size_t j = i + 1; j < cmds.size() && seen < kIrDeadFlagScanLimit;
         ++j, ++seen) {
      const IRCommand& y = cmds[j];
      if (ir_cuts_flag_flow(y)) break;
      const IRFlagEffect ey = ir_flag_effect(y);
      if (ey.reads) break;
      if (ey.wr_max == 0) continue;

      if ((ex.wr_max & ~ey.wr_min) == 0) {
        x.flags |= static_cast<uint32_t>(IRF_NO_FLAGS);
      }
      break;
    }
  }
}

struct NativeIsland {
  uint64_t orig_addr = 0;
  std::vector<uint8_t> bytes;
  int32_t disp_off = -1;
  uint64_t disp_target = 0;
  std::string text;
  bool tail_call = false;
  int32_t meta_delta = 0;

  bool disp_read = false;
  uint8_t disp_size = 0;
  uint32_t import_index = 0;

  uint8_t flip_kind = 0;
  uint8_t flip_off = 0;
};

struct IRProgram {
  static constexpr size_t kUnbound = static_cast<size_t>(-1);

  std::vector<IRCommand> cmds;
  std::vector<size_t> label_mark;

  std::vector<uint64_t> label_addr;

  std::vector<NativeIsland> natives;

  size_t entry_cmd = 0;
  std::string source_name;

  int new_label() {
    label_mark.push_back(kUnbound);
    label_addr.push_back(0);
    return static_cast<int>(label_mark.size() - 1);
  }

  void bind(int label) { label_mark[static_cast<size_t>(label)] = cmds.size(); }

  void bind_at(int label, size_t cmd_index) { label_mark[static_cast<size_t>(label)] = cmd_index; }

  void add(const IRCommand& c) { cmds.push_back(c); }
  size_t here() const { return cmds.size(); }
};

inline IRCommand IRCommand::mov(IROperand d, IROperand s) {
  IRCommand c; c.op = IROp::Mov; c.dst = d; c.src = s; c.size = d.size; return c;
}
inline IRCommand IRCommand::lea(IROperand d, const IRMem& m) {
  IRCommand c; c.op = IROp::Lea; c.dst = d; c.src = IROperand::M(m, 8); return c;
}
inline IRCommand IRCommand::alu(AluOp k, IROperand d, IROperand s) {
  IRCommand c; c.op = IROp::Alu; c.sub = static_cast<uint8_t>(k); c.dst = d; c.src = s; c.size = d.size; return c;
}
inline IRCommand IRCommand::shift(ShiftOp k, int reg, uint8_t cnt) {
  IRCommand c; c.op = IROp::Shift; c.sub = static_cast<uint8_t>(k);
  c.dst = IROperand::R(reg); c.src = IROperand::I(cnt, 1); c.size = 8; return c;
}
inline IRCommand IRCommand::unary(UnaryOp k, int reg) {
  IRCommand c; c.op = IROp::Unary; c.sub = static_cast<uint8_t>(k); c.dst = IROperand::R(reg); return c;
}
inline IRCommand IRCommand::br(IROp op, int label) {
  IRCommand c; c.op = op; c.label = label; return c;
}
inline IRCommand IRCommand::none(IROp op) {
  IRCommand c; c.op = op; return c;
}

inline void ir_wrap_callable(IRProgram& p) {
  const int entry_label = p.new_label();

  for (size_t& m : p.label_mark) {
    if (m != IRProgram::kUnbound) m += 2;
  }
  p.label_mark[static_cast<size_t>(entry_label)] = p.entry_cmd + 2;
  p.entry_cmd = 0;

  IRCommand call; call.op = IROp::Call; call.label = entry_label;
  IRCommand halt; halt.op = IROp::Halt;

  p.cmds.insert(p.cmds.begin(), halt);
  p.cmds.insert(p.cmds.begin(), call);
}

}
