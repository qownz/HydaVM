#include "hyda/ir/ir_codegen.hpp"

#include <algorithm>
#include <cstdio>
#include <utility>
#include <vector>

namespace hyda {

namespace {

constexpr int SCRATCH_A = REG_T4;
constexpr int SCRATCH_B = REG_T5;

const char* ir_op_name(IROp op) {
  switch (op) {
    case IROp::Nop:        return "Nop";
    case IROp::Halt:       return "Halt";
    case IROp::Mov:        return "Mov";
    case IROp::Lea:        return "Lea";
    case IROp::Xchg:       return "Xchg";
    case IROp::Cmov:       return "Cmov";
    case IROp::Push:       return "Push";
    case IROp::Pop:        return "Pop";
    case IROp::Pushf:      return "Pushf";
    case IROp::Popf:       return "Popf";
    case IROp::Alu:        return "Alu";
    case IROp::Shift:      return "Shift";
    case IROp::Unary:      return "Unary";
    case IROp::Test:       return "Test";
    case IROp::Imul:       return "Imul";
    case IROp::Mul:        return "Mul";
    case IROp::Div:        return "Div";
    case IROp::SignExtend: return "SignExtend";
    case IROp::Extend:     return "Extend";
    case IROp::Bswap:      return "Bswap";
    case IROp::BitScan:    return "BitScan";
    case IROp::BitCount:   return "BitCount";
    case IROp::BitTest:    return "BitTest";
    case IROp::Jmp:        return "Jmp";
    case IROp::Jcc:        return "Jcc";
    case IROp::CmpJcc:     return "CmpJcc";
    case IROp::AluJcc:     return "AluJcc";
    case IROp::Call:       return "Call";
    case IROp::Ret:        return "Ret";
    case IROp::RetImm:     return "RetImm";
    case IROp::JmpIndirect:return "JmpIndirect";
    case IROp::Junk:       return "Junk";
    case IROp::Noise:      return "Noise";
    case IROp::InvR:       return "InvR";
    case IROp::Native:     return "Native";
    case IROp::SseLoad:    return "SseLoad";
    case IROp::SseStore:   return "SseStore";
    case IROp::SseMov:     return "SseMov";
    case IROp::SseBin:     return "SseBin";
    case IROp::SseBinM:    return "SseBinM";
    case IROp::SseUn:      return "SseUn";
    case IROp::SseCmp:     return "SseCmp";
    case IROp::SseCmpM:    return "SseCmpM";
    case IROp::SseCvt:     return "SseCvt";
    case IROp::SseShuf:    return "SseShuf";
    case IROp::SseBin3:    return "SseBin3";
    case IROp::SseShift:   return "SseShift";
    case IROp::SseEx128:   return "SseEx128";
    case IROp::SseIns128:  return "SseIns128";
    case IROp::SseStoreLane: return "SseStoreLane";
    case IROp::SseLoadLane:  return "SseLoadLane";
    case IROp::SseBcast:   return "SseBcast";
    case IROp::SseBin3M:   return "SseBin3M";
  }
  return "?";
}

bool pick_size(Op o1, Op o2, Op o4, Op o8, uint8_t size, Op* out) {
  switch (size) {
    case 1: *out = o1; return true;
    case 2: *out = o2; return true;
    case 4: *out = o4; return true;
    case 8: *out = o8; return true;
    default: return false;
  }
}

const Op kAlu8[]  = {Op::ADD8,  Op::ADC8,  Op::SUB8,  Op::SBB8,  Op::AND8,  Op::OR8,  Op::XOR8,  Op::CMP8};
const Op kAlu16[] = {Op::ADD16, Op::ADC16, Op::SUB16, Op::SBB16, Op::AND16, Op::OR16, Op::XOR16, Op::CMP16};
const Op kAlu32[] = {Op::ADD32, Op::ADC32, Op::SUB32, Op::SBB32, Op::AND32, Op::OR32, Op::XOR32, Op::CMP32};
const Op kAlu64[] = {Op::ADD64, Op::ADC64, Op::SUB64, Op::SBB64, Op::AND64, Op::OR64, Op::XOR64, Op::CMP64};

bool pick_alu(uint8_t sub, uint8_t size, Op* out) {
  if (sub > 7) return false;
  switch (size) {
    case 1: *out = kAlu8[sub]; return true;
    case 2: *out = kAlu16[sub]; return true;
    case 4: *out = kAlu32[sub]; return true;
    case 8: *out = kAlu64[sub]; return true;
    default: return false;
  }
}

const Op kShl[] = {Op::SHL8, Op::SHL16, Op::SHL32, Op::SHL};
const Op kShr[] = {Op::SHR8, Op::SHR16, Op::SHR32, Op::SHR};
const Op kSar[] = {Op::SAR8, Op::SAR16, Op::SAR32, Op::SAR};
const Op kRol[] = {Op::ROL8, Op::ROL16, Op::ROL32, Op::ROL};
const Op kRor[] = {Op::ROR8, Op::ROR16, Op::ROR32, Op::ROR};

const Op kShlR[] = {Op::SHL_R8, Op::SHL_R16, Op::SHL_R32, Op::SHL_R};
const Op kShrR[] = {Op::SHR_R8, Op::SHR_R16, Op::SHR_R32, Op::SHR_R};
const Op kSarR[] = {Op::SAR_R8, Op::SAR_R16, Op::SAR_R32, Op::SAR_R};
const Op kRolR[] = {Op::ROL_R8, Op::ROL_R16, Op::ROL_R32, Op::ROL_R};
const Op kRorR[] = {Op::ROR_R8, Op::ROR_R16, Op::ROR_R32, Op::ROR_R};

bool pick_shift(uint8_t sub, uint8_t size, Op* out) {
  int si;
  switch (size) {
    case 1: si = 0; break;
    case 2: si = 1; break;
    case 4: si = 2; break;
    case 8: si = 3; break;
    default: return false;
  }
  switch (sub) {
    case 0: *out = kShl[si]; return true;
    case 1: *out = kShr[si]; return true;
    case 2: *out = kSar[si]; return true;
    case 3: *out = kRol[si]; return true;
    case 4: *out = kRor[si]; return true;
    default: return false;
  }
}

bool pick_shift_v(bool reg_cnt, uint8_t sub, uint8_t size, Op* out) {
  if (!reg_cnt) return pick_shift(sub, size, out);
  int si;
  switch (size) {
    case 1: si = 0; break;
    case 2: si = 1; break;
    case 4: si = 2; break;
    case 8: si = 3; break;
    default: return false;
  }
  switch (sub) {
    case 0: *out = kShlR[si]; return true;
    case 1: *out = kShrR[si]; return true;
    case 2: *out = kSarR[si]; return true;
    case 3: *out = kRolR[si]; return true;
    case 4: *out = kRorR[si]; return true;
    default: return false;
  }
}

bool pick_imul2(uint8_t size, Op* out) {
  switch (size) {
    case 2: *out = Op::IMUL2_16; return true;
    case 4: *out = Op::IMUL2_32; return true;
    case 8: *out = Op::IMUL2;    return true;
    default: return false;
  }
}

bool pick_unary(uint8_t sub, uint8_t size, Op* out) {
  switch (sub) {
    case 0: return pick_size(Op::INC8, Op::INC16, Op::INC32, Op::INC, size, out);
    case 1: return pick_size(Op::DEC8, Op::DEC16, Op::DEC32, Op::DEC, size, out);
    case 2: return pick_size(Op::NOT8, Op::NOT16, Op::NOT32, Op::NOT, size, out);
    case 3: return pick_size(Op::NEG8, Op::NEG16, Op::NEG32, Op::NEG, size, out);
    default: return false;
  }
}

const Op kJcc[16] = {
  Op::JCC_O,  Op::JCC_NO, Op::JCC_B,  Op::JCC_AE,
  Op::JCC_Z,  Op::JCC_NZ, Op::JCC_BE, Op::JCC_A,
  Op::JCC_S,  Op::JCC_NS, Op::JCC_P,  Op::JCC_NP,
  Op::JCC_L,  Op::JCC_GE, Op::JCC_LE, Op::JCC_G,
};

class Lower {
 public:
  Lower(Asm& a, std::string* err, bool* ok) : a_(a), err_(err), ok_(ok) {}

  void run(const IRProgram& p) {
    prog_ = &p;

    asm_label_.resize(p.label_mark.size());
    for (size_t i = 0; i < asm_label_.size(); ++i) asm_label_[i] = a_.label();

    std::vector<std::pair<size_t, size_t>> marks;
    for (size_t l = 0; l < p.label_mark.size(); ++l) {
      if (p.label_mark[l] != IRProgram::kUnbound) marks.emplace_back(p.label_mark[l], l);
    }
    std::stable_sort(marks.begin(), marks.end(),
                     [](const auto& x, const auto& y) { return x.first < y.first; });

    size_t next_mark = 0;
    for (size_t i = 0; i < p.cmds.size(); ++i) {
      while (next_mark < marks.size() && marks[next_mark].first <= i) {
        a_.bind(asm_label_[marks[next_mark].second]);
        ++next_mark;
      }
      if (i == p.entry_cmd) entry_offset_ = a_.here();
      if (!*ok_) return;
      site_ = i;

      if ((p.cmds[i].flags & IRF_NO_FLAGS) && ir_flag_only(p.cmds[i]) &&
          p.cmds[i].dst.kind != IRKind::Mem &&
          p.cmds[i].src.kind != IRKind::Mem) {
        ++dead_dropped_;
        continue;
      }
      emit(p.cmds[i]);
    }

    while (next_mark < marks.size()) {
      a_.bind(asm_label_[marks[next_mark].second]);
      ++next_mark;
    }
    if (p.cmds.empty()) entry_offset_ = a_.here();
  }

  size_t entry_offset() const { return entry_offset_; }
  const std::vector<NativeRef>& native_refs() const { return native_refs_; }

  size_t dead_variant() const { return dead_variant_; }
  size_t body_variant_count() const { return body_variant_; }
  size_t nested_count() const { return nested_; }
  size_t dead_dropped() const { return dead_dropped_; }

 private:
  void fail(const IRCommand& c, const char* what) {
    if (!*ok_) return;
    *ok_ = false;
    char buf[192];
    std::snprintf(buf, sizeof(buf),
                  "IR->bytecode: cannot lower %s (%s)", ir_op_name(c.op), what);
    if (err_) *err_ = buf;
  }

  void i_r(Op o, int a) { a_.i_r(o, a); }
  void i_rr(Op o, int a, int b) { a_.i_rr(o, a, b); }
  void i_rq(Op o, int a, int64_t v) { a_.i_rq(o, a, v); }
  void i_rb(Op o, int a, int v) { a_.i_rb(o, a, v); }
  void i_rrb(Op o, int a, int b, int c) { a_.i_rrb(o, a, b, c); }
  void i_rrrb(Op o, int a, int b, int c, int d) {
    a_.raw(o);
    a_.u8(static_cast<uint8_t>(a));
    a_.u8(static_cast<uint8_t>(b));
    a_.u8(static_cast<uint8_t>(c));
    a_.u8(static_cast<uint8_t>(d));
  }
  void i_mem(Op o, int reg, const IRMem& m) {
    a_.i_mem(o, reg, m.base < 0 ? static_cast<int>(NO_MEM) : m.base,
             m.index < 0 ? static_cast<int>(NO_MEM) : m.index,
             static_cast<int>(m.scale), m.disp);
  }

  bool load_into(int dst_reg, const IRMem& m, uint8_t size, const IRCommand& c) {
    Op o;
    if (!pick_size(Op::LOAD8, Op::LOAD16, Op::LOAD32, Op::MOV_RM, size, &o)) {
      fail(c, "invalid memory access size");
      return false;
    }
    i_mem(o, dst_reg, m);
    return true;
  }

  bool store_from(int src_reg, const IRMem& m, uint8_t size, const IRCommand& c) {
    Op o;
    if (!pick_size(Op::STORE8, Op::STORE16, Op::STORE32, Op::MOV_MR, size, &o)) {
      fail(c, "invalid memory write size");
      return false;
    }
    i_mem(o, src_reg, m);
    return true;
  }

  uint64_t next_rand() { return splitmix64(blind_s_); }

  void load_blinded(int reg, int64_t value, uint8_t size) {
    Op mov_op;
    if (!pick_size(Op::MOV_RI8, Op::MOV_RI16, Op::MOV_RI32, Op::MOV_RI, size,
                   &mov_op)) {
      return;
    }
    if (size < 4) { i_rq(mov_op, reg, value); return; }

    const unsigned parts = 2u + static_cast<unsigned>(next_rand() % 3u);
    int32_t delta[4] = {0, 0, 0, 0};
    uint64_t total = 0;
    for (unsigned i = 0; i < parts && i < 4; ++i) {
      delta[i] = static_cast<int32_t>(static_cast<uint32_t>(next_rand()));
      total += static_cast<uint64_t>(static_cast<int64_t>(delta[i]));
    }

    IRMem m;
    m.base = reg;
    if (size == 8) {
      const uint64_t head = static_cast<uint64_t>(value) - total;
      i_rq(Op::MOV_RI, reg, static_cast<int64_t>(head));
      for (unsigned i = 0; i < parts; ++i) {
        m.disp = delta[i];
        i_mem(Op::LEA, reg, m);
      }
      return;
    }

    const uint32_t head32 = static_cast<uint32_t>(value) -
                            static_cast<uint32_t>(total);
    i_rq(Op::MOV_RI32, reg, static_cast<int64_t>(head32));
    for (unsigned i = 0; i < parts; ++i) {
      m.disp = delta[i];
      i_mem(Op::LEA, reg, m);
    }
    i_rr(Op::MOV_RR32, reg, reg);
  }

  bool materialize(const IROperand& src, uint8_t size, int* out_reg, const IRCommand& c) {
    switch (src.kind) {
      case IRKind::Reg:
        *out_reg = src.reg;
        return true;
      case IRKind::Imm: {
        Op o;
        if (!pick_size(Op::MOV_RI8, Op::MOV_RI16, Op::MOV_RI32, Op::MOV_RI, size, &o)) {
          fail(c, "invalid immediate size");
          return false;
        }
        load_blinded(SCRATCH_B, src.imm, size);
        *out_reg = SCRATCH_B;
        return true;
      }
      case IRKind::Mem:
        if (!load_into(SCRATCH_B, src.mem, size, c)) return false;
        *out_reg = SCRATCH_B;
        return true;
      default:
        fail(c, "operand type not supported");
        return false;
    }
  }

  void emit(const IRCommand& c) {
    switch (c.op) {
      case IROp::Nop:   a_.i0(Op::NOP); break;
      case IROp::Halt:  a_.i0(Op::HALT); break;
      case IROp::Pushf: a_.i0(Op::PUSHF); break;
      case IROp::Popf:  a_.i0(Op::POPF); break;
      case IROp::Junk:  a_.i_q(Op::VM_JUNK, c.src.imm); break;
      case IROp::Noise: a_.i_rq(Op::VM_NOISE, c.dst.reg, c.src.imm); break;
      case IROp::InvR:  i_r(Op::INV_R, c.dst.reg); break;

      case IROp::Mov:   emit_mov(c); break;
      case IROp::Lea:   emit_lea(c); break;
      case IROp::Xchg:  emit_xchg(c); break;
      case IROp::Cmov:  emit_cmov(c); break;
      case IROp::Push:  emit_push(c); break;
      case IROp::Pop:   emit_pop(c); break;
      case IROp::Alu:   emit_alu(c); break;
      case IROp::Shift: emit_shift(c); break;
      case IROp::Unary: emit_unary(c); break;
      case IROp::Test:  emit_test(c); break;
      case IROp::Imul:  emit_imul(c); break;
      case IROp::Mul:   emit_muldiv(c, false); break;
      case IROp::Div:   emit_muldiv(c, true); break;
      case IROp::SignExtend:
        a_.i0(c.sub == 0 ? Op::CDQ : Op::CQO);
        break;
      case IROp::Extend: emit_extend(c); break;
      case IROp::Bswap: i_r(Op::BSWAP, c.dst.reg); break;
      case IROp::BitScan: emit_bitscan(c); break;
      case IROp::BitCount: emit_bitcount(c); break;
      case IROp::BitTest: emit_bittest(c); break;

      case IROp::SseLoad:  emit_sse_load(c); break;
      case IROp::SseStore: emit_sse_store(c); break;
      case IROp::SseMov:   emit_sse_mov(c); break;
      case IROp::SseBin:   emit_sse_bin(c); break;
      case IROp::SseBinM:  emit_sse_binm(c); break;
      case IROp::SseUn:    emit_sse_un(c); break;
      case IROp::SseCmp:   emit_sse_cmp(c); break;
      case IROp::SseCmpM:  emit_sse_cmpm(c); break;
      case IROp::SseCvt:   emit_sse_cvt(c); break;
      case IROp::SseShuf:  emit_sse_shuf(c); break;
      case IROp::SseBin3:  emit_sse_bin3(c); break;
      case IROp::SseShift: emit_sse_shift(c); break;
      case IROp::SseEx128:     emit_sse_ex128(c); break;
      case IROp::SseIns128:    emit_sse_ins128(c); break;
      case IROp::SseStoreLane: emit_sse_store_lane(c); break;
      case IROp::SseLoadLane:  emit_sse_load_lane(c); break;
      case IROp::SseBcast:     emit_sse_bcast(c); break;
      case IROp::SseBin3M:     emit_sse_bin3m(c); break;

      case IROp::Jmp:        i_j(Op::JMP, c.label); break;
      case IROp::Jcc:
        if (c.sub > 15) { fail(c, "invalid condition code"); break; }
        i_j(kJcc[c.sub], c.label);
        break;
      case IROp::CmpJcc:     emit_cmp_jcc(c); break;
      case IROp::AluJcc:     emit_alu_jcc(c); break;
      case IROp::Call:       i_j(Op::CALL, c.label); break;
      case IROp::Ret:        a_.i0(Op::RET); break;
      case IROp::RetImm:     a_.raw(Op::RET_IMM); a_.s32(static_cast<int32_t>(c.src.imm)); break;
      case IROp::JmpIndirect:emit_jmp_indirect(c); break;

      case IROp::Native: {
        a_.raw(Op::NATIVE_GATE);
        a_.u8(c.sub);
        NativeRef ref;
        ref.rva_offset = static_cast<uint32_t>(a_.here());
        ref.island = c.sub;
        native_refs_.push_back(ref);
        a_.s32(0);
        break;
      }
    }
  }

  int masked_reg(int reg, uint8_t size, int scratch) {
    switch (size) {
      case 8: return reg;
      case 4: i_rr(Op::MOV_RR32, scratch, reg); return scratch;
      case 2: i_rr(Op::MOVZX16, scratch, reg); return scratch;
      case 1: i_rr(Op::MOVZX8, scratch, reg); return scratch;
      default: return reg;
    }
  }

  void emit_bitscan(const IRCommand& c) {
    if (!need_rr(c)) return;
    const int src = masked_reg(c.src.reg, c.size, SCRATCH_B);
    i_rr(c.sub == 0 ? Op::BSF : Op::BSR, c.dst.reg, src);
    if (c.size < 8) {
      Op o;
      if (pick_size(Op::MOV_RR8, Op::MOV_RR16, Op::MOV_RR32, Op::MOV_RR, c.size, &o)) {
        i_rr(o, c.dst.reg, c.dst.reg);
      }
    }
  }

  void emit_bitcount(const IRCommand& c) {
    if (!need_rr(c)) return;
    Op o;
    switch (static_cast<BitCountKind>(c.sub)) {
      case BitCountKind::Tz:  o = Op::TZCNT;  break;
      case BitCountKind::Lz:  o = Op::LZCNT;  break;
      case BitCountKind::Pop: o = Op::POPCNT; break;
      default: fail(c, "invalid bitcount sub-op"); return;
    }

    const int src = masked_reg(c.src.reg, c.size, SCRATCH_B);
    i_rrb(o, c.dst.reg, src, static_cast<int>(c.size));
  }

  bool need_rr(const IRCommand& c) {
    if (c.dst.kind != IRKind::Reg || c.src.kind != IRKind::Reg) {
      fail(c, "two register operands expected");
      return false;
    }
    return true;
  }

  void emit_mov(const IRCommand& c) {
    if (c.dst.kind == IRKind::Reg) {
      if (c.src.kind == IRKind::Reg) {
        Op o;
        if (!pick_size(Op::MOV_RR8, Op::MOV_RR16, Op::MOV_RR32, Op::MOV_RR, c.size, &o)) {
          fail(c, "invalid mov size");
          return;
        }
        i_rr(o, c.dst.reg, c.src.reg);
      } else if (c.src.kind == IRKind::Imm) {

        if (c.flags & IRF_IMAGE_RVA) {
          if (c.size != 8) {
            fail(c, "image-relative address must be 64-bit");
            return;
          }
          i_rq(Op::MOV_RI_BASE, c.dst.reg, c.src.imm);
          return;
        }
        Op o;
        if (!pick_size(Op::MOV_RI8, Op::MOV_RI16, Op::MOV_RI32, Op::MOV_RI, c.size, &o)) {
          fail(c, "invalid mov size");
          return;
        }
        load_blinded(c.dst.reg, c.src.imm, c.size);
      } else if (c.src.kind == IRKind::Mem) {
        load_into(c.dst.reg, c.src.mem, c.size, c);
      } else {
        fail(c, "invalid source operand");
      }
      return;
    }

    if (c.dst.kind == IRKind::Mem) {
      if (c.src.kind == IRKind::Reg) {
        store_from(c.src.reg, c.dst.mem, c.size, c);
      } else if (c.src.kind == IRKind::Imm) {
        load_blinded(SCRATCH_A, c.src.imm, 8);
        store_from(SCRATCH_A, c.dst.mem, c.size, c);
      } else {
        fail(c, "no memory-to-memory move");
      }
      return;
    }

    fail(c, "invalid target operand");
  }

  void emit_lea(const IRCommand& c) {
    if (c.dst.kind != IRKind::Reg || c.src.kind != IRKind::Mem) {
      fail(c, "lea reg, [mem] expected");
      return;
    }
    i_mem(Op::LEA, c.dst.reg, c.src.mem);
  }

  void emit_xchg(const IRCommand& c) {
    if (!need_rr(c)) return;
    if (c.size != 8) {
      fail(c, "XCHG only swaps full 64-bit slots");
      return;
    }
    i_rr(Op::XCHG, c.dst.reg, c.src.reg);
  }

  void emit_cmov(const IRCommand& c) {
    if (c.sub > 15) { fail(c, "invalid condition code"); return; }
    if (c.dst.kind != IRKind::Reg) { fail(c, "cmov target must be a register"); return; }
    Op o;
    if (!pick_size(Op::CMOV8, Op::CMOV16, Op::CMOV32, Op::CMOV, c.size, &o)) {
      fail(c, "invalid cmov size");
      return;
    }
    int src = 0;
    if (!materialize(c.src, c.size, &src, c)) return;
    i_rrb(o, c.dst.reg, src, static_cast<int>(c.sub));
  }

  void emit_push(const IRCommand& c) {
    switch (c.src.kind) {
      case IRKind::Reg: i_r(Op::PUSH_R, c.src.reg); break;
      case IRKind::Imm:
        load_blinded(SCRATCH_A, c.src.imm, 8);
        i_r(Op::PUSH_R, SCRATCH_A);
        break;
      case IRKind::Mem:
        if (!load_into(SCRATCH_A, c.src.mem, c.size, c)) return;
        i_r(Op::PUSH_R, SCRATCH_A);
        break;
      default: fail(c, "push operand type not supported");
    }
  }

  void emit_pop(const IRCommand& c) {
    if (c.dst.kind == IRKind::Reg) {
      i_r(Op::POP_R, c.dst.reg);
    } else if (c.dst.kind == IRKind::Mem) {
      i_r(Op::POP_R, SCRATCH_A);
      store_from(SCRATCH_A, c.dst.mem, c.size, c);
    } else {
      fail(c, "pop operand type not supported");
    }
  }

  void emit_alu(const IRCommand& c) {
    Op base;
    if (!pick_alu(c.sub, c.size, &base)) {
      fail(c, "invalid alu sub-op or size");
      return;
    }

    if ((c.flags & IRF_NO_FLAGS) != 0) {
      const Op nf = nf_variant(base);
      if (nf != base) { base = nf; ++dead_variant_; }
    } else if (base == nested_op(codegen_seed())) {

      base = nested_variant(base);
      ++nested_;
    } else {

      const Op bv = pick_body(base, codegen_seed(), site_);
      if (bv != base) { base = bv; ++body_variant_; }
    }
    const bool is_cmp = (c.sub == static_cast<uint8_t>(AluOp::Cmp));

    if (c.dst.kind == IRKind::Reg) {
      int src = 0;
      if (!materialize(c.src, c.size, &src, c)) return;
      i_rr(base, c.dst.reg, src);
      return;
    }

    if (c.dst.kind == IRKind::Mem) {

      if (!load_into(SCRATCH_A, c.dst.mem, c.size, c)) return;
      int src = 0;
      if (!materialize(c.src, c.size, &src, c)) return;
      i_rr(base, SCRATCH_A, src);
      if (!is_cmp) store_from(SCRATCH_A, c.dst.mem, c.size, c);
      return;
    }

    fail(c, "invalid alu target");
  }

  void emit_shift(const IRCommand& c) {
    const bool reg_cnt = (c.src.kind == IRKind::Reg);
    if (!reg_cnt && c.src.kind != IRKind::Imm) {
      fail(c, "shift count must be immediate or register");
      return;
    }
    Op o;
    if (!pick_shift_v(reg_cnt, c.sub, c.size, &o)) {
      fail(c, "invalid shift sub-op or size");
      return;
    }

    int d = 0;
    if (c.dst.kind == IRKind::Reg) {
      d = c.dst.reg;
    } else if (c.dst.kind == IRKind::Mem) {
      if (!load_into(SCRATCH_A, c.dst.mem, c.size, c)) return;
      d = SCRATCH_A;
    } else {
      fail(c, "invalid shift target");
      return;
    }

    if (reg_cnt) i_rr(o, d, c.src.reg);
    else         i_rb(o, d, static_cast<int>(c.src.imm) & 0xFF);

    if (c.dst.kind == IRKind::Mem) store_from(d, c.dst.mem, c.size, c);
  }

  void emit_unary(const IRCommand& c) {
    Op o;
    if (!pick_unary(c.sub, c.size, &o)) {
      fail(c, "invalid unary sub-op or size");
      return;
    }

    if ((c.flags & IRF_NO_FLAGS) != 0) {
      const Op nf = nf_variant(o);
      if (nf != o) { o = nf; ++dead_variant_; }
    } else {
      const Op bv = pick_body(o, codegen_seed(), site_);
      if (bv != o) { o = bv; ++body_variant_; }
    }
    if (c.dst.kind == IRKind::Reg) {
      i_r(o, c.dst.reg);
      return;
    }
    if (c.dst.kind == IRKind::Mem) {
      if (!load_into(SCRATCH_A, c.dst.mem, c.size, c)) return;
      i_r(o, SCRATCH_A);
      store_from(SCRATCH_A, c.dst.mem, c.size, c);
      return;
    }
    fail(c, "invalid unary target");
  }

  void emit_test(const IRCommand& c) {
    int base = 0;
    if (c.dst.kind == IRKind::Mem) {
      if (!load_into(SCRATCH_A, c.dst.mem, c.size, c)) return;
      base = SCRATCH_A;
    } else if (c.dst.kind == IRKind::Reg) {
      base = c.dst.reg;
    } else {
      fail(c, "invalid test target");
      return;
    }

    int src = 0;
    if (!materialize(c.src, c.size, &src, c)) return;

    if (c.size < 8) {
      const int a = masked_reg(base, c.size, SCRATCH_A);
      const int b = masked_reg(src, c.size, SCRATCH_B);
      i_rr(Op::TEST, a, b);
      return;
    }
    i_rr(Op::TEST, base, src);
  }

  void emit_imul(const IRCommand& c) {

    switch (static_cast<ImulKind>(c.sub)) {
      case ImulKind::One: {
        Op o;
        if (!pick_size(Op::IMUL8, Op::IMUL16, Op::IMUL32, Op::IMUL, c.size, &o)) {
          fail(c, "invalid imul size");
          return;
        }
        if (c.src.kind == IRKind::Reg) { i_r(o, c.src.reg); return; }
        if (c.src.kind == IRKind::Mem) {
          if (!load_into(SCRATCH_A, c.src.mem, c.size, c)) return;
          i_r(o, SCRATCH_A);
          return;
        }
        fail(c, "imul single-operand form");
        return;
      }

      case ImulKind::Two: {
        if (c.dst.kind != IRKind::Reg) { fail(c, "imul two-operand target"); return; }
        Op o;
        if (!pick_imul2(c.size, &o)) { fail(c, "invalid imul two-operand size"); return; }
        int src = 0;
        if (!materialize(c.src, c.size, &src, c)) return;
        i_rr(o, c.dst.reg, src);
        return;
      }

      case ImulKind::Three: {
        if (c.dst.kind != IRKind::Reg) { fail(c, "imul three-operand target"); return; }
        if (c.aux.kind != IRKind::Imm) { fail(c, "imul three-operand immediate"); return; }
        Op o, mv, mi;
        if (!pick_imul2(c.size, &o)) { fail(c, "invalid imul three-operand size"); return; }
        if (!pick_size(Op::MOV_RR8, Op::MOV_RR16, Op::MOV_RR32, Op::MOV_RR, c.size, &mv) ||
            !pick_size(Op::MOV_RI8, Op::MOV_RI16, Op::MOV_RI32, Op::MOV_RI, c.size, &mi)) {
          fail(c, "invalid imul three-operand size");
          return;
        }
        int src = 0;
        if (!materialize(c.src, c.size, &src, c)) return;
        i_rr(mv, c.dst.reg, src);
        load_blinded(SCRATCH_B, c.aux.imm, c.size);
        i_rr(o, c.dst.reg, SCRATCH_B);
        return;
      }
    }
    fail(c, "invalid imul form");
  }

  void emit_muldiv(const IRCommand& c, bool is_div) {
    const bool sign = (c.sub != static_cast<uint8_t>(MulKind::Unsigned));
    Op o;
    const bool ok =
        is_div ? (sign ? pick_size(Op::IDIV8, Op::IDIV16, Op::IDIV32, Op::IDIV, c.size, &o)
                       : pick_size(Op::DIV8,  Op::DIV16,  Op::DIV32,  Op::DIV,  c.size, &o))
               : (sign ? pick_size(Op::IMUL8, Op::IMUL16, Op::IMUL32, Op::IMUL, c.size, &o)
                       : pick_size(Op::MUL8,  Op::MUL16,  Op::MUL32,  Op::MUL,  c.size, &o));
    if (!ok) { fail(c, "invalid mul/div size"); return; }
    if (c.src.kind == IRKind::Reg) { i_r(o, c.src.reg); return; }
    if (c.src.kind == IRKind::Mem) {
      if (!load_into(SCRATCH_A, c.src.mem, c.size, c)) return;
      i_r(o, SCRATCH_A);
      return;
    }
    fail(c, "mul/div source must be a register or memory");
  }

  void emit_extend(const IRCommand& c) {
    if (c.dst.kind != IRKind::Reg || c.src.kind != IRKind::Reg) {
      fail(c, "movzx/movsx requires two register operands");
      return;
    }
    switch (static_cast<ExtOp>(c.sub)) {
      case ExtOp::Zx8:  i_rr(Op::MOVZX8,  c.dst.reg, c.src.reg); break;
      case ExtOp::Zx16: i_rr(Op::MOVZX16, c.dst.reg, c.src.reg); break;
      case ExtOp::Sx8:  i_rr(Op::MOVSX8,  c.dst.reg, c.src.reg); break;
      case ExtOp::Sx16: i_rr(Op::MOVSX16, c.dst.reg, c.src.reg); break;
      case ExtOp::Sxd:  i_rr(Op::MOVSXD,  c.dst.reg, c.src.reg); break;
    }
  }

  bool sse_x(const IROperand& o, const IRCommand& c) {
    if (o.kind != IRKind::Xmm) { fail(c, "XMM operand expected"); return false; }
    if (o.reg < 0 || o.reg > 15) { fail(c, "XMM index must be 0..15"); return false; }
    return true;
  }

  void i_sse_mem(Op o, int xr, const IRMem& m, int sub, bool with_sub) {
    a_.raw(o);
    a_.u8(static_cast<uint8_t>(xr));
    a_.u8(m.base < 0 ? static_cast<uint8_t>(NO_MEM)
                     : static_cast<uint8_t>(vsl(m.base)));
    a_.u8(m.index < 0 ? static_cast<uint8_t>(NO_MEM)
                      : static_cast<uint8_t>(vsl(m.index)));
    a_.sb(static_cast<int>(m.scale));
    a_.s32(static_cast<int32_t>(m.disp));
    if (with_sub) a_.u8(static_cast<uint8_t>(sub));
  }

  void emit_sse_load(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Mem) {
      fail(c, "sse load: dst XMM, src memory expected");
      return;
    }
    Op o;
    switch (c.size) {
      case 16: o = Op::SSE_LD16; break;
      case 8:  o = Op::SSE_LD8;  break;
      case 4:  o = Op::SSE_LD4;  break;
      case 32: i_sse_mem(Op::AVX_LD256, c.dst.reg, c.src.mem, 0, false); return;
      default: fail(c, "invalid SSE load size"); return;
    }
    i_sse_mem(o, c.dst.reg, c.src.mem, 0, false);
  }

  void emit_sse_store(const IRCommand& c) {
    if (!sse_x(c.src, c) || c.dst.kind != IRKind::Mem) {
      fail(c, "sse store: dst memory, src XMM expected");
      return;
    }
    Op o;
    switch (c.size) {
      case 16: o = Op::SSE_ST16; break;
      case 8:  o = Op::SSE_ST8;  break;
      case 4:  o = Op::SSE_ST4;  break;
      case 32: i_sse_mem(Op::AVX_ST256, c.src.reg, c.dst.mem, 0, false); return;
      default: fail(c, "invalid SSE store size"); return;
    }
    i_sse_mem(o, c.src.reg, c.dst.mem, 0, false);
  }

  void emit_sse_mov(const IRCommand& c) {
    if (!sse_x(c.dst, c) || !sse_x(c.src, c)) {
      fail(c, "sse mov: two XMM operands expected");
      return;
    }
    if (c.size == 32) {
      i_rr(Op::AVX_MOV256, c.dst.reg, c.src.reg);
      return;
    }
    i_rrb(Op::SSE_MOV, c.dst.reg, c.src.reg, c.sub);
  }

  void emit_sse_bin(const IRCommand& c) {
    if (!sse_x(c.dst, c)) return;
    if (c.src.kind == IRKind::Xmm) {
      i_rrb(Op::SSE_BIN, c.dst.reg, c.src.reg, c.sub);
      return;
    }
    if (c.src.kind == IRKind::Mem) {
      i_sse_mem(Op::SSE_BINM, c.dst.reg, c.src.mem, c.sub, true);
      return;
    }
    fail(c, "sse bin: source must be XMM or memory");
  }

  void emit_sse_binm(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Mem) {
      fail(c, "sse binm: dst XMM, src memory expected");
      return;
    }
    i_sse_mem(Op::SSE_BINM, c.dst.reg, c.src.mem, c.sub, true);
  }

  void emit_sse_ex128(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Xmm) {
      fail(c, "sse extract: XMM destination and YMM source expected");
      return;
    }
    i_rrb(Op::AVX_EX128, c.dst.reg, c.src.reg, c.sub);
  }

  void emit_sse_ins128(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Xmm || c.aux.kind != IRKind::Imm) {
      fail(c, "sse insert: YMM operands expected");
      return;
    }
    i_rrrb(Op::AVX_INS128, c.dst.reg, c.src.reg, static_cast<int>(c.aux.imm), c.sub);
  }

  void emit_sse_store_lane(const IRCommand& c) {
    if (!sse_x(c.src, c) || c.dst.kind != IRKind::Mem) {
      fail(c, "sse lane store: memory destination and YMM source expected");
      return;
    }
    i_sse_mem(Op::AVX_STL128, c.src.reg, c.dst.mem, c.sub, true);
  }

  void emit_sse_load_lane(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Mem) {
      fail(c, "sse lane load: YMM destination and memory source expected");
      return;
    }
    i_sse_mem(Op::AVX_LDL128, c.dst.reg, c.src.mem, c.sub, true);
  }

  void emit_sse_bcast(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Xmm) {
      fail(c, "sse broadcast: XMM source and YMM destination expected");
      return;
    }
    i_rrb(Op::AVX_BCAST, c.dst.reg, c.src.reg, c.sub);
  }

  void emit_sse_bin3m(const IRCommand& c) {
    if (!sse_x(c.dst, c) || !sse_x(c.src, c) || c.aux.kind != IRKind::Mem) {
      fail(c, "avx memory source: two YMM operands and memory expected");
      return;
    }
    i_rr(Op::AVX_MOV256, c.dst.reg, c.src.reg);
    i_sse_mem(Op::AVX_BINM256, c.dst.reg, c.aux.mem, c.sub, true);
  }

  void emit_sse_un(const IRCommand& c) {
    if (!sse_x(c.dst, c)) return;
    i_rb(Op::SSE_UN, c.dst.reg, c.sub);
  }

  void emit_sse_cmp(const IRCommand& c) {
    if (!sse_x(c.dst, c)) return;
    if (c.src.kind == IRKind::Xmm) {
      i_rrb(Op::SSE_CMP, c.dst.reg, c.src.reg, c.sub);
      return;
    }
    if (c.src.kind == IRKind::Mem) {
      i_sse_mem(Op::SSE_CMPM, c.dst.reg, c.src.mem, c.sub, true);
      return;
    }
    fail(c, "sse cmp: source must be XMM or memory");
  }

  void emit_sse_cmpm(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.src.kind != IRKind::Mem) {
      fail(c, "sse cmpm: dst XMM, src memory expected");
      return;
    }
    i_sse_mem(Op::SSE_CMPM, c.dst.reg, c.src.mem, c.sub, true);
  }

  void emit_sse_cvt(const IRCommand& c) {

    const bool dx = c.dst.kind == IRKind::Xmm;
    const bool sx = c.src.kind == IRKind::Xmm;
    if (!dx && !sx) { fail(c, "sse cvt: at least one XMM operand required"); return; }
    if (!dx && c.dst.kind != IRKind::Reg) { fail(c, "sse cvt: invalid target"); return; }
    if (!sx && c.src.kind != IRKind::Reg) { fail(c, "sse cvt: invalid source"); return; }
    if (dx && (c.dst.reg < 0 || c.dst.reg > 15)) { fail(c, "XMM index must be 0..15"); return; }
    if (sx && (c.src.reg < 0 || c.src.reg > 15)) { fail(c, "XMM index must be 0..15"); return; }
    a_.i_rrb_cvt(Op::SSE_CVT, c.dst.reg, !dx, c.src.reg, !sx, c.sub);
  }

  void emit_sse_shuf(const IRCommand& c) {
    if (!sse_x(c.dst, c) || !sse_x(c.src, c) || c.aux.kind != IRKind::Imm) {
      fail(c, "sse shuf: dst/src must be XMM, aux must be imm");
      return;
    }
    a_.raw(Op::SSE_SHUF);
    a_.u8(static_cast<uint8_t>(c.dst.reg));
    a_.u8(static_cast<uint8_t>(c.src.reg));
    a_.u8(static_cast<uint8_t>(c.aux.imm & 0xFF));
    a_.u8(c.sub);
  }

  void emit_sse_bin3(const IRCommand& c) {
    if (!sse_x(c.dst, c) || !sse_x(c.src, c) || c.aux.kind != IRKind::Imm) {
      fail(c, "sse bin3: dst/src must be XMM, aux imm (src2)");
      return;
    }
    if (c.size == 32) {
      a_.i_rrrb(Op::AVX_BIN3_256, c.dst.reg, c.src.reg,
                static_cast<int>(c.aux.imm & 0xF), c.sub);
      return;
    }
    a_.i_rrrb(Op::SSE_BIN3, c.dst.reg, c.src.reg,
              static_cast<int>(c.aux.imm & 0xF), c.sub);
  }

  void emit_sse_shift(const IRCommand& c) {
    if (!sse_x(c.dst, c) || c.aux.kind != IRKind::Imm) {
      fail(c, "sse shift: dst XMM, aux imm expected");
      return;
    }
    a_.i_rbb(Op::SSE_SHIFT, c.dst.reg, c.sub,
             static_cast<int>(c.aux.imm & 0xFF));
  }

  void emit_bittest(const IRCommand& c) {
    Op o;
    switch (static_cast<BitTestKind>(c.sub)) {
      case BitTestKind::Bt:  o = Op::BT;  break;
      case BitTestKind::Bts: o = Op::BTS; break;
      case BitTestKind::Btr: o = Op::BTR; break;
      case BitTestKind::Btc: o = Op::BTC; break;
      default: fail(c, "invalid bittest sub-op"); return;
    }
    if (c.dst.kind == IRKind::Reg && c.src.kind == IRKind::Reg) {
      i_rr(o, c.dst.reg, c.src.reg);
      return;
    }
    int base = 0;
    if (c.dst.kind == IRKind::Reg) {
      base = c.dst.reg;
    } else if (c.dst.kind == IRKind::Mem) {
      if (!load_into(SCRATCH_A, c.dst.mem, 8, c)) return;
      base = SCRATCH_A;
    } else {
      fail(c, "invalid bittest target");
      return;
    }
    int bit = 0;
    if (!materialize(c.src, 8, &bit, c)) return;
    i_rr(o, base, bit);
    if (c.dst.kind == IRKind::Mem && o != Op::BT) store_from(base, c.dst.mem, 8, c);
  }

  void i_j(Op o, int ir_label) {
    if (ir_label < 0 || static_cast<size_t>(ir_label) >= asm_label_.size()) {
      *ok_ = false;
      if (err_) *err_ = "IR->bytecode: invalid label";
      return;
    }
    a_.raw(o);
    a_.rel(asm_label_[static_cast<size_t>(ir_label)]);
  }

  void emit_jmp_indirect(const IRCommand& c) {
    if (prog_ != nullptr) {
      const size_t n = prog_->label_mark.size();
      for (size_t l = 0; l < n; ++l) {
        if (prog_->label_mark[l] == IRProgram::kUnbound) continue;
        if (l >= prog_->label_addr.size() || prog_->label_addr[l] == 0) continue;
        i_rq(Op::MOV_RI_BASE, SCRATCH_B,
             static_cast<int64_t>(prog_->label_addr[l]));
        i_rr(Op::CMP64, c.dst.reg, SCRATCH_B);
        i_j(Op::JCC_Z, static_cast<int>(l));
      }
    }
    i_r(Op::JMP_R, c.dst.reg);
  }

  void emit_cmp_jcc(const IRCommand& c) {
    if (c.dst.kind != IRKind::Reg) {
      fail(c, "CmpJcc expects a register target");
      return;
    }
    if (c.label < 0 || static_cast<size_t>(c.label) >= asm_label_.size()) {
      *ok_ = false;
      if (err_) *err_ = "IR->bytecode: CmpJcc invalid label";
      return;
    }
    uint8_t szc;
    switch (c.size) {
      case 1: szc = 0; break;
      case 2: szc = 1; break;
      case 4: szc = 2; break;
      case 8: szc = 3; break;
      default:
        fail(c, "CmpJcc invalid size");
        return;
    }

    int src = 0;
    if (!materialize(c.src, c.size, &src, c)) return;
    a_.i_rrbbb_j(Op::CMP_JCC, c.dst.reg, src,
                 static_cast<int>(c.aux.imm) != 0 ? 1 : 0,
                 static_cast<int>(c.sub), szc,
                 asm_label_[static_cast<size_t>(c.label)]);
  }

  void emit_alu_jcc(const IRCommand& c) {
    if (c.dst.kind != IRKind::Reg) {
      fail(c, "AluJcc expects a register target");
      return;
    }
    if (c.label < 0 || static_cast<size_t>(c.label) >= asm_label_.size()) {
      *ok_ = false;
      if (err_) *err_ = "IR->bytecode: AluJcc invalid label";
      return;
    }
    uint8_t szc;
    switch (c.size) {
      case 1: szc = 0; break;
      case 2: szc = 1; break;
      case 4: szc = 2; break;
      case 8: szc = 3; break;
      default:
        fail(c, "AluJcc invalid size");
        return;
    }
    int src = 0;
    if (!materialize(c.src, c.size, &src, c)) return;
    a_.i_rrbbb_j(Op::ALU_JCC, c.dst.reg, src, static_cast<int>(c.sub),
                 static_cast<int>(c.aux.imm), szc,
                 asm_label_[static_cast<size_t>(c.label)]);
  }

  Asm& a_;
  std::string* err_;
  bool* ok_;
  std::vector<size_t> asm_label_;
  const IRProgram* prog_ = nullptr;
  size_t entry_offset_ = 0;
  std::vector<NativeRef> native_refs_;

  size_t dead_variant_ = 0;
  size_t body_variant_ = 0;
  size_t nested_ = 0;
  size_t dead_dropped_ = 0;
  uint64_t site_ = 0;
  uint64_t blind_s_ = codegen_seed() ^ 0x243F6A8885A308D3ull;
};

}

CodegenResult ir_codegen(const IRProgram& prog, Asm& out) {
  CodegenResult r;
  bool ok = true;

  IRProgram p = prog;
  ir_mark_dead_flags(p.cmds);
  Lower lo(out, &r.error, &ok);
  lo.run(p);
  if (!ok) {
    r.ok = false;
    return r;
  }
  try {
    out.finalize();
  } catch (const std::exception& e) {
    r.ok = false;
    r.error = e.what();
    return r;
  }
  r.ok = true;
  r.entry_offset = lo.entry_offset();
  r.code_size = out.code.size();
  r.native_refs = lo.native_refs();
  for (size_t op = 0; op < OP_COUNT; ++op) r.op_used[op] = out.used_ops[op];
  for (const IRCommand& c : p.cmds) {
    if (c.flags & IRF_NO_FLAGS) ++r.dead_flags;
  }
  r.dead_emitted = lo.dead_variant();
  r.body_variant_count = lo.body_variant_count();
  r.nested_count = lo.nested_count();
  r.dead_dropped = lo.dead_dropped();
  return r;
}

}
