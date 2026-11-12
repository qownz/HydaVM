#pragma once

#include "hyda/core/config.hpp"
#include "hyda/ir/ir.hpp"

#include <cstdint>

namespace hyda {

constexpr uint32_t ir_reg_bit(int r) { return 1u << static_cast<unsigned>(r); }
constexpr uint32_t ir_all_regs = (1u << NVREG) - 1u;

struct IrRW {
  uint32_t rd = 0;
  uint32_t wr = 0;
};

inline void ir_rw_read_operand(const IROperand& o, uint32_t* rd) {
  if (o.kind == IRKind::Reg) {
    *rd |= ir_reg_bit(o.reg);
  } else if (o.kind == IRKind::Mem) {
    if (o.mem.base >= 0) *rd |= ir_reg_bit(o.mem.base);
    if (o.mem.index >= 0) *rd |= ir_reg_bit(o.mem.index);
  }
}

inline void ir_rw_write_operand(const IROperand& o, uint8_t size, uint32_t* rd,
                                uint32_t* wr) {
  if (o.kind == IRKind::Reg) {
    *wr |= ir_reg_bit(o.reg);
    if (size < 4) *rd |= ir_reg_bit(o.reg);
  } else if (o.kind == IRKind::Mem) {
    ir_rw_read_operand(o, rd);
  }
}

inline IrRW ir_rw_of(const IRCommand& c, bool for_inversion = false) {
  IrRW s;
  switch (c.op) {
    case IROp::Nop:
    case IROp::Junk:
      break;

    case IROp::Noise:
      ir_rw_read_operand(c.dst, &s.rd);
      s.wr |= ir_reg_bit(c.dst.reg);
      break;

    case IROp::InvR:
      ir_rw_read_operand(c.dst, &s.rd);
      s.wr |= ir_reg_bit(c.dst.reg);
      break;

    case IROp::Mov:
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;

    case IROp::Lea:
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, 8, &s.rd, &s.wr);
      break;

    case IROp::Xchg:
      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      s.wr |= ir_reg_bit(c.dst.reg) | ir_reg_bit(c.src.reg);
      break;

    case IROp::Cmov:
      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;

    case IROp::Push:
      ir_rw_read_operand(c.src, &s.rd);
      break;

    case IROp::Pop:
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;

    case IROp::Pushf:
    case IROp::Popf:
      break;

    case IROp::Alu: {
      const bool is_cmp = c.sub == static_cast<uint8_t>(AluOp::Cmp);

      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      if (!is_cmp) ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;
    }

    case IROp::Shift:
      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;

    case IROp::Unary:
      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;

    case IROp::Test:
      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      break;

    case IROp::Imul:
      switch (static_cast<ImulKind>(c.sub)) {
        case ImulKind::One:
          ir_rw_read_operand(c.src, &s.rd);
          s.rd |= ir_reg_bit(REG_RAX) | ir_reg_bit(REG_RDX);
          s.wr |= ir_reg_bit(REG_RAX) | ir_reg_bit(REG_RDX);
          break;
        case ImulKind::Two:
          ir_rw_read_operand(c.dst, &s.rd);
          ir_rw_read_operand(c.src, &s.rd);
          ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
          break;
        case ImulKind::Three:
          ir_rw_read_operand(c.src, &s.rd);
          ir_rw_read_operand(c.aux, &s.rd);
          ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
          break;
      }
      break;

    case IROp::Mul:
    case IROp::Div:
      ir_rw_read_operand(c.src, &s.rd);
      s.rd |= ir_reg_bit(REG_RAX) | ir_reg_bit(REG_RDX);
      s.wr |= ir_reg_bit(REG_RAX) | ir_reg_bit(REG_RDX);
      break;

    case IROp::SignExtend:
      s.rd |= ir_reg_bit(REG_RAX);
      s.wr |= ir_reg_bit(REG_RDX);
      break;

    case IROp::Extend:
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, 8, &s.rd, &s.wr);
      break;

    case IROp::Bswap:
      ir_rw_read_operand(c.dst, &s.rd);
      s.wr |= ir_reg_bit(c.dst.reg);
      break;

    case IROp::BitScan:
    case IROp::BitCount:
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;

    case IROp::BitTest:
      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      s.wr |= ir_reg_bit(c.dst.reg);
      break;

    case IROp::Jmp:
    case IROp::Jcc:
    case IROp::Halt:
      if (for_inversion) s.rd |= ir_all_regs;
      break;

    case IROp::CmpJcc:

      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      if (for_inversion) s.rd |= ir_all_regs;
      break;

    case IROp::AluJcc:

      ir_rw_read_operand(c.dst, &s.rd);
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      if (for_inversion) s.rd |= ir_all_regs;
      break;

    case IROp::Call:
      if (for_inversion) {
        s.rd |= ir_all_regs;
        s.wr |= ir_all_regs;
      }
      break;

    case IROp::Ret:
    case IROp::RetImm:
    case IROp::JmpIndirect:
    case IROp::Native:
      if (for_inversion) {
        s.rd |= ir_all_regs;
        s.wr |= ir_all_regs;
      }
      break;

    case IROp::SseLoad:
    case IROp::SseBinM:
    case IROp::SseCmpM:
    case IROp::SseLoadLane:
    case IROp::SseBin3M:
      ir_rw_read_operand(c.src, &s.rd);
      break;
    case IROp::SseStore:
    case IROp::SseStoreLane:
      ir_rw_read_operand(c.dst, &s.rd);
      break;
    case IROp::SseBin:
    case IROp::SseCmp:
    case IROp::SseUn:
    case IROp::SseMov:
    case IROp::SseShuf:
    case IROp::SseBin3:
    case IROp::SseShift:
    case IROp::SseEx128:
    case IROp::SseIns128:
    case IROp::SseBcast:
      break;
    case IROp::SseCvt:
      ir_rw_read_operand(c.src, &s.rd);
      ir_rw_write_operand(c.dst, c.size, &s.rd, &s.wr);
      break;
  }
  return s;
}

inline bool ir_block_end(IROp op) {
  switch (op) {
    case IROp::Jmp:
    case IROp::Jcc:
    case IROp::CmpJcc:
    case IROp::AluJcc:
    case IROp::Call:
    case IROp::Ret:
    case IROp::RetImm:
    case IROp::JmpIndirect:
    case IROp::Halt:
    case IROp::Native:
      return true;
    default:
      return false;
  }
}

}
