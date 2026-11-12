#include "lift.hpp"

#include "hyda/vm/sse.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace hyda {
namespace {

int vreg_for(x86_reg r) {
  switch (r) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL:
      return REG_RAX;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL:
      return REG_RCX;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL:
      return REG_RDX;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL:
      return REG_RBX;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
      return REG_RSP;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
      return REG_RBP;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
      return REG_RSI;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
      return REG_RDI;
    case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return REG_R8;
    case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return REG_R9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return REG_R10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return REG_R11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return REG_R12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return REG_R13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return REG_R14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return REG_R15;
    default:
      return -1;
  }
}

bool high_byte_parent(x86_reg r, int* parent) {
  switch (r) {
    case X86_REG_AH: *parent = REG_RAX; return true;
    case X86_REG_BH: *parent = REG_RBX; return true;
    case X86_REG_CH: *parent = REG_RCX; return true;
    case X86_REG_DH: *parent = REG_RDX; return true;
    default: return false;
  }
}

const char* reg_reason(x86_reg r) {
  switch (r) {
    case X86_REG_AH: case X86_REG_BH: case X86_REG_CH: case X86_REG_DH:
      return "high-byte register (AH/BH/CH/DH) cannot be expressed";
    case X86_REG_RIP: case X86_REG_EIP:
      return "RIP cannot be a direct operand";
    default:
      if (r >= X86_REG_XMM0 && r <= X86_REG_XMM31) return "SSE register (call gate required)";
      if (r >= X86_REG_YMM0 && r <= X86_REG_YMM31) return "AVX register (call gate required)";
      if (r >= X86_REG_ST0 && r <= X86_REG_ST7) return "x87 register (call gate required)";
      if (r >= X86_REG_MM0 && r <= X86_REG_MM7) return "MMX register (call gate required)";
      return "register not supported";
  }
}

bool jcc_cc(cs_insn* insn, uint8_t* cc) {
  switch (insn->id) {
    case X86_INS_JO:  *cc = 0x0; return true;
    case X86_INS_JNO: *cc = 0x1; return true;
    case X86_INS_JB:  *cc = 0x2; return true;
    case X86_INS_JAE: *cc = 0x3; return true;
    case X86_INS_JE:  *cc = 0x4; return true;
    case X86_INS_JNE: *cc = 0x5; return true;
    case X86_INS_JBE: *cc = 0x6; return true;
    case X86_INS_JA:  *cc = 0x7; return true;
    case X86_INS_JS:  *cc = 0x8; return true;
    case X86_INS_JNS: *cc = 0x9; return true;
    case X86_INS_JP:  *cc = 0xA; return true;
    case X86_INS_JNP: *cc = 0xB; return true;
    case X86_INS_JL:  *cc = 0xC; return true;
    case X86_INS_JGE: *cc = 0xD; return true;
    case X86_INS_JLE: *cc = 0xE; return true;
    case X86_INS_JG:  *cc = 0xF; return true;
    default: return false;
  }
}

bool cmov_cc(cs_insn* insn, uint8_t* cc) {
  switch (insn->id) {
    case X86_INS_CMOVO:  *cc = 0x0; return true;
    case X86_INS_CMOVNO: *cc = 0x1; return true;
    case X86_INS_CMOVB:  *cc = 0x2; return true;
    case X86_INS_CMOVAE: *cc = 0x3; return true;
    case X86_INS_CMOVE:  *cc = 0x4; return true;
    case X86_INS_CMOVNE: *cc = 0x5; return true;
    case X86_INS_CMOVBE: *cc = 0x6; return true;
    case X86_INS_CMOVA:  *cc = 0x7; return true;
    case X86_INS_CMOVS:  *cc = 0x8; return true;
    case X86_INS_CMOVNS: *cc = 0x9; return true;
    case X86_INS_CMOVP:  *cc = 0xA; return true;
    case X86_INS_CMOVNP: *cc = 0xB; return true;
    case X86_INS_CMOVL:  *cc = 0xC; return true;
    case X86_INS_CMOVGE: *cc = 0xD; return true;
    case X86_INS_CMOVLE: *cc = 0xE; return true;
    case X86_INS_CMOVG:  *cc = 0xF; return true;
    default: return false;
  }
}

bool setcc_cc(cs_insn* insn, uint8_t* cc) {
  switch (insn->id) {
    case X86_INS_SETO:  *cc = 0x0; return true;
    case X86_INS_SETNO: *cc = 0x1; return true;
    case X86_INS_SETB:  *cc = 0x2; return true;
    case X86_INS_SETAE: *cc = 0x3; return true;
    case X86_INS_SETE:  *cc = 0x4; return true;
    case X86_INS_SETNE: *cc = 0x5; return true;
    case X86_INS_SETBE: *cc = 0x6; return true;
    case X86_INS_SETA:  *cc = 0x7; return true;
    case X86_INS_SETS:  *cc = 0x8; return true;
    case X86_INS_SETNS: *cc = 0x9; return true;
    case X86_INS_SETP:  *cc = 0xA; return true;
    case X86_INS_SETNP: *cc = 0xB; return true;
    case X86_INS_SETL:  *cc = 0xC; return true;
    case X86_INS_SETGE: *cc = 0xD; return true;
    case X86_INS_SETLE: *cc = 0xE; return true;
    case X86_INS_SETG:  *cc = 0xF; return true;
    default: return false;
  }
}

struct InsnRec {
  cs_insn* insn = nullptr;
  bool reachable = false;
};

class Lifter {
 public:
  Lifter(const uint8_t* code, size_t size, const LiftOptions& opt)
      : code_(code), size_(size), opt_(opt) {}

  ~Lifter() {
    if (insns_) cs_free(insns_, count_);
    if (handle_) cs_close(&handle_);
  }

  LiftResult run() {
    LiftResult r;
    r.prog.source_name = opt_.name;

    if (!open()) {
      r.error = "cannot initialize capstone";
      return r;
    }
    if (!decode()) {
      r.error = "cannot decode bytes";
      return r;
    }
    if (count_ == 0) {
      r.error = "empty range";
      return r;
    }
    r.decoded = count_;

    index_.reserve(count_ * 2);
    for (size_t i = 0; i < count_; ++i) index_[insns_[i].address] = i;

    mark_reachable();
    register_labels();

    if (!emit_all(r)) {

      r.ok = false;
      return r;
    }

    for (size_t i = 0; i < count_; ++i) {
      if (!reach_[i]) ++r.pruned;
    }

    r.ok = r.unsupported.empty();
    if (!r.ok) {
      char buf[160];
      std::snprintf(buf, sizeof(buf), "%zu instructions not supported (first: %s @ %#llx)",
                    r.unsupported.size(), r.unsupported.front().mnemonic.c_str(),
                    static_cast<unsigned long long>(r.unsupported.front().address));
      r.error = buf;
    }

    if (opt_.fuse) {
      r.fuse = ir_fuse(prog_);
    }

    if (opt_.mutate) {
      MutateOptions mo;
      mo.seed = opt_.mutate_seed;
      r.mutate = ir_mutate(prog_, mo);
    }

    if (opt_.obfuscate) {
      r.obf = ir_bogus_cfg(prog_, opt_.mutate_seed);
    }

    r.prog = prog_;
    r.address_fixups = fixups_;
    r.image_relocs = image_relocs_;
    r.written_regs = written_;
    r.native_islands = prog_.natives.size();
    return r;
  }

 private:

  bool open() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) return false;
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    return true;
  }

  bool decode() {
    count_ = cs_disasm(handle_, code_, size_, opt_.base_address, 0, &insns_);
    return count_ > 0;
  }

  bool is_branch_target(const cs_insn& in, uint64_t* target) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count == 0) return false;
    if (x.operands[0].type != X86_OP_IMM) return false;
    *target = static_cast<uint64_t>(x.operands[0].imm);
    return true;
  }

  void mark(uint64_t addr) {
    auto it = index_.find(addr);
    if (it == index_.end()) return;
    if (reach_[it->second]) return;
    work_.push_back(addr);
  }

  static bool is_trap(const cs_insn& in) {
    return in.id == X86_INS_UD2 || in.id == X86_INS_INT3 ||
           in.id == X86_INS_INT1 || in.id == X86_INS_HLT;
  }

  bool has_known_target_at_or_after(uint64_t addr) const {
    return label_.lower_bound(addr) != label_.end();
  }

  void mark_reachable() {
    reach_.assign(count_, 0);
    work_.clear();
    mark(opt_.base_address);

    bool indirect = false;
    while (!work_.empty()) {
      const uint64_t a = work_.back();
      work_.pop_back();
      auto it = index_.find(a);
      if (it == index_.end()) continue;
      const size_t i = it->second;
      if (reach_[i]) continue;
      reach_[i] = 1;

      cs_insn& in = insns_[i];
      const uint64_t next = in.address + in.size;

      bool is_jump = false, is_call = false, is_ret = false, is_int = false;
      for (int g = 0; g < in.detail->groups_count; ++g) {
        switch (in.detail->groups[g]) {
          case CS_GRP_JUMP: is_jump = true; break;
          case CS_GRP_CALL: is_call = true; break;
          case CS_GRP_RET:  is_ret = true; break;
          case CS_GRP_INT:  is_int = true; break;
          case CS_GRP_IRET: is_ret = true; break;
          default: break;
        }
      }
      if (in.id == X86_INS_INT3 || in.id == X86_INS_UD2 || in.id == X86_INS_HLT) is_int = true;

      if (is_ret || is_int) continue;

      const bool unconditional = (in.id == X86_INS_JMP);
      if (is_jump || is_call) {
        uint64_t t = 0;
        if (is_branch_target(in, &t)) {
          mark(t);
        } else {
          indirect = true;
        }

        if (indirect) all_reachable_ = true;
      }
      if (!unconditional) mark(next);
    }

    if (all_reachable_) std::fill(reach_.begin(), reach_.end(), 1);
  }

  void register_labels() {
    const uint64_t ib = opt_.image_base ? opt_.image_base : opt_.base_address;
    for (size_t i = 0; i < count_; ++i) {
      if (!reach_[i]) continue;
      cs_insn& in = insns_[i];
      bool is_branch = false;
      for (int g = 0; g < in.detail->groups_count; ++g) {
        if (in.detail->groups[g] == CS_GRP_JUMP || in.detail->groups[g] == CS_GRP_CALL) {
          is_branch = true;
        }
      }
      if (!is_branch) continue;

      uint64_t t = 0;
      if (!is_branch_target(in, &t)) continue;
      if (label_.count(t)) continue;
      if (!index_.count(t)) continue;
      const int id = prog_.new_label();
      label_[t] = id;

      prog_.label_addr[static_cast<size_t>(id)] = t - ib;
    }

    if (all_reachable_) {
      for (size_t i = 0; i < count_; ++i) {
        if (!reach_[i]) continue;
        if (is_trap(insns_[i])) break;
        const uint64_t a = insns_[i].address;
        if (label_.count(a)) continue;
        const int id = prog_.new_label();
        label_[a] = id;
        prog_.label_addr[static_cast<size_t>(id)] = a - ib;
      }
    }
  }

  void note_written(const cs_insn& in) {
    if (in.detail == nullptr) return;
    mark_string_regs(in);
    for (uint8_t i = 0; i < in.detail->regs_write_count; ++i) {
      mark_written(static_cast<x86_reg>(in.detail->regs_write[i]));
    }
    const cs_x86& x = in.detail->x86;
    for (int i = 0; i < x.op_count; ++i) {
      if (x.operands[i].type != X86_OP_REG) continue;
      if ((x.operands[i].access & CS_AC_WRITE) == 0) continue;
      mark_written(x.operands[i].reg);
    }
  }

  void mark_string_regs(const cs_insn& in) {
    switch (in.id) {
      case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD:
      case X86_INS_MOVSQ:
        written_ |= 1u << REG_RSI;
        written_ |= 1u << REG_RDI;
        written_ |= 1u << REG_RCX;
        break;
      case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD:
      case X86_INS_STOSQ:
        written_ |= 1u << REG_RDI;
        written_ |= 1u << REG_RCX;
        break;
      default:
        break;
    }
  }

  void mark_written(x86_reg r) {
    int parent = -1;
    if (high_byte_parent(r, &parent)) {
      written_ |= 1u << parent;
      return;
    }
    const int v = vreg_for(r);
    if (v >= 0) written_ |= 1u << v;
  }

  bool emit_all(LiftResult& r) {
    if (!reach_[0]) {
      r.error = "entry point not reachable";
      return false;
    }

    for (size_t i = 0; i < count_; ++i) {
      if (!reach_[i]) continue;
      cs_insn& in = insns_[i];

      auto lit = label_.find(in.address);
      if (lit != label_.end()) prog_.bind_at(lit->second, prog_.here());

      const size_t mark = prog_.here();
      const size_t fix_mark = fixups_;
      const size_t rel_mark = image_relocs_;

      if (!emit_one(in)) {

        prog_.cmds.resize(mark);
        fixups_ = fix_mark;
        image_relocs_ = rel_mark;

        hb_parent_ = -1;
        hb_write_ = false;
        hb_loaded_ = false;

        if (!make_island(in)) {

          if (is_trap(in) && !has_known_target_at_or_after(in.address)) break;

          r.unsupported.push_back(
              UnsupportedInsn{in.address, in.mnemonic, last_reason_});
          continue;
        }
      }
      flush_high_byte();
      ++r.emitted;
      note_written(in);
    }

    if (prog_.cmds.empty()) {
      r.error = "no instructions emitted";
      return false;
    }

    const IROp last = prog_.cmds.back().op;
    if (last != IROp::Ret && last != IROp::RetImm && last != IROp::Jmp && last != IROp::Halt) {
      prog_.add(IRCommand::none(IROp::Halt));
    }
    return true;
  }

  bool fail(const char* why) {
    last_reason_ = why;
    return false;
  }

  bool op_reg(const cs_insn& in, int i, int* vreg, uint8_t* sz) {
    const cs_x86_op& o = in.detail->x86.operands[i];
    if (o.type != X86_OP_REG) return fail("register operand expected");
    const int v = vreg_for(o.reg);
    if (v < 0) return fail(reg_reason(o.reg));
    *vreg = v;
    *sz = static_cast<uint8_t>(o.size);
    return true;
  }

  bool op_imm(const cs_insn& in, int i, int64_t* v, uint8_t* sz) {
    const cs_x86_op& o = in.detail->x86.operands[i];
    if (o.type != X86_OP_IMM) return fail("immediate operand expected");
    *v = o.imm;
    *sz = static_cast<uint8_t>(o.size);
    return true;
  }

  bool op_mem(const cs_insn& in, int i, IRMem* out, uint8_t* sz) {
    const cs_x86_op& o = in.detail->x86.operands[i];
    if (o.type != X86_OP_MEM) return fail("memory operand expected");
    if (o.mem.segment != X86_REG_INVALID) {
      return fail("segment override (FS/GS) henuz desteklenmiyor");
    }

    IRMem m;
    m.scale = static_cast<uint8_t>(o.mem.scale);
    m.disp = static_cast<int32_t>(o.mem.disp);
    *sz = static_cast<uint8_t>(o.size);

    const bool has_base = (o.mem.base != X86_REG_INVALID);
    const bool has_index = (o.mem.index != X86_REG_INVALID);

    if (has_base && o.mem.base == X86_REG_RIP) {

      const uint64_t target =
          in.address + in.size + static_cast<int64_t>(o.mem.disp);
      prog_.add(IRCommand::mov(IROperand::R(REG_T0),
                               IROperand::I(static_cast<int64_t>(target - img_base()), 8)));
      prog_.cmds.back().flags |= IRF_NO_CRYPT | IRF_IMAGE_RVA;
      m.base = REG_T0;
      m.disp = 0;
      ++image_relocs_;
    } else if (has_base) {
      m.base = vreg_for(o.mem.base);
      if (m.base < 0) return fail(reg_reason(o.mem.base));
    }

    if (has_index) {
      m.index = vreg_for(o.mem.index);
      if (m.index < 0) return fail(reg_reason(o.mem.index));
    }

    if (!has_base && !has_index) {

      prog_.add(IRCommand::mov(IROperand::R(REG_T1), IROperand::I(static_cast<int64_t>(m.disp), 8)));
      prog_.cmds.back().flags |= IRF_NO_CRYPT;
      m.base = REG_T1;
      m.disp = 0;
      ++fixups_;
    }

    *out = m;
    return true;
  }

  static int64_t sext_imm(int64_t v, uint8_t imm_size, uint8_t op_size) {
    if (imm_size >= op_size || imm_size == 0) return v;
    const unsigned bits = imm_size * 8u;
    const int64_t mask = (int64_t{1} << (bits - 1));
    return ((v & ((int64_t{1} << bits) - 1)) ^ mask) - mask;
  }

  uint8_t op_size(const cs_insn& in, int i = 0) {
    return static_cast<uint8_t>(in.detail->x86.operands[i].size);
  }

  bool check_size(uint8_t s) {
    if (s == 1 || s == 2 || s == 4 || s == 8) return true;
    return fail("invalid operand size");
  }

  static bool same_operands(const cs_insn& a, const cs_insn& b) {
    if (a.detail == nullptr || b.detail == nullptr) return false;
    if (a.detail->x86.op_count != b.detail->x86.op_count) return false;
    for (int i = 0; i < a.detail->x86.op_count; ++i) {
      const cs_x86_op& x = a.detail->x86.operands[i];
      const cs_x86_op& y = b.detail->x86.operands[i];
      if (x.type != y.type || x.size != y.size) return false;
      switch (x.type) {
        case X86_OP_REG:
          if (x.reg != y.reg) return false;
          break;
        case X86_OP_IMM:
          if (x.imm != y.imm) return false;
          break;
        case X86_OP_MEM:
          if (x.mem.base != y.mem.base || x.mem.index != y.mem.index ||
              x.mem.scale != y.mem.scale || x.mem.disp != y.mem.disp) {
            return false;
          }
          break;
        default:
          break;
      }
    }
    return true;
  }

  bool meta_ok(const std::vector<uint8_t>& bytes, const cs_insn& orig,
               bool same_id, unsigned expect_id) {
    if (bytes.empty() || bytes.size() > 16) return false;
    cs_insn* out = nullptr;
    const size_t n = cs_disasm(handle_, bytes.data(), bytes.size(), orig.address,
                               0, &out);
    if (n != 1 || out == nullptr) {
      if (out != nullptr) cs_free(out, n);
      return false;
    }
    const bool ok = same_operands(orig, out[0]) &&
                    (same_id ? (out[0].id == orig.id)
                             : (out[0].id == static_cast<unsigned>(expect_id)));
    cs_free(out, n);
    return ok;
  }

  bool meta_ok_head(const std::vector<uint8_t>& bytes, const cs_insn& orig,
                    unsigned expect_id) {
    if (bytes.empty() || bytes.size() > 16) return false;
    cs_insn* out = nullptr;
    const size_t n =
        cs_disasm(handle_, bytes.data(), bytes.size(), orig.address, 0, &out);
    if (n < 1 || out == nullptr) {
      if (out != nullptr) cs_free(out, n);
      return false;
    }
    const bool ok = same_operands(orig, out[0]) &&
                    out[0].id == static_cast<unsigned>(expect_id);
    cs_free(out, n);
    return ok;
  }

  static bool same_operands_swapped(const cs_insn& a, const cs_insn& b) {
    if (a.detail == nullptr || b.detail == nullptr) return false;
    const int n = a.detail->x86.op_count;
    if (n != 2 || b.detail->x86.op_count != 2) return false;

    const cs_x86_op& x0 = a.detail->x86.operands[0];
    const cs_x86_op& x1 = a.detail->x86.operands[1];
    const cs_x86_op& y0 = b.detail->x86.operands[0];
    const cs_x86_op& y1 = b.detail->x86.operands[1];
    if (x0.type != y1.type || x1.type != y0.type) return false;
    if (x0.size != y1.size || x1.size != y0.size) return false;
    if (x0.type == X86_OP_REG && (x0.reg != y1.reg || x1.reg != y0.reg)) {
      return false;
    }
    return true;
  }

  bool meta_ok_swapped(const std::vector<uint8_t>& bytes, const cs_insn& orig) {
    if (bytes.empty() || bytes.size() > 16) return false;
    cs_insn* out = nullptr;
    const size_t n = cs_disasm(handle_, bytes.data(), bytes.size(), orig.address,
                               0, &out);
    if (n != 1 || out == nullptr) {
      if (out != nullptr) cs_free(out, n);
      return false;
    }
    const bool ok = (out[0].id == orig.id) && same_operands_swapped(orig, out[0]);
    cs_free(out, n);
    return ok;
  }

  std::vector<uint8_t> metamorph(const cs_insn& in, uint64_t seed,
                                 int* delta) {
    *delta = 0;
    const std::vector<uint8_t> orig(in.bytes, in.bytes + in.size);

    {
      static const uint8_t kSeg[4] = {0x2E, 0x3E, 0x26, 0x36};
      const uint8_t pick = kSeg[splitmix64(seed) & 3u];
      std::vector<uint8_t> alt;
      alt.reserve(orig.size() + 1);
      alt.push_back(pick);
      alt.insert(alt.end(), orig.begin(), orig.end());
      if (meta_ok(alt, in, true, 0)) {
        *delta = 1;
        return alt;
      }
    }

    if (orig.size() == 5 && orig[0] == 0x66 && orig[1] == 0x0F &&
        (orig[2] == 0xEF || orig[2] == 0x57)) {
      std::vector<uint8_t> alt = orig;
      if (orig[2] == 0xEF) {
        alt.erase(alt.begin());
        alt[1] = 0x57;
      } else {
        alt.insert(alt.begin(), 0x66);
        alt[2] = 0xEF;
      }
      const unsigned want = (orig[2] == 0xEF) ? X86_INS_XORPS : X86_INS_PXOR;
      if (meta_ok(alt, in, false, want)) {
        *delta = static_cast<int>(alt.size()) - static_cast<int>(orig.size());
        return alt;
      }
    }

    if (orig.size() == 4 && orig[1] == 0x0F && orig[2] == 0x10) {
      std::vector<uint8_t> alt = orig;
      const bool had66 = (orig[0] == 0x66);
      if (had66) {
        alt.erase(alt.begin());
      } else {
        alt.insert(alt.begin(), 0x66);
      }
      const unsigned want = had66 ? X86_INS_MOVUPS : X86_INS_MOVUPD;
      if (meta_ok(alt, in, false, want)) {
        *delta = static_cast<int>(alt.size()) - static_cast<int>(orig.size());
        return alt;
      }
    }

    if (orig.size() == 3 && (orig[0] == 0x48 || orig[0] == 0x4C) &&
        (orig[1] == 0x89 || orig[1] == 0x8B)) {
      const uint8_t modrm = orig[2];
      if ((modrm >> 6) == 3) {
        std::vector<uint8_t> alt = orig;
        alt[1] = (orig[1] == 0x89) ? 0x8B : 0x89;
        if (meta_ok_swapped(alt, in)) {
          *delta = 0;
          return alt;
        }
      }
    }

    return orig;
  }

  bool make_island(cs_insn& in) {
    if (in.detail == nullptr) return fail("no instruction detail");

    const bool is_tail = (in.id == X86_INS_JMP);

    for (int g = 0; g < in.detail->groups_count; ++g) {
      switch (in.detail->groups[g]) {
        case CS_GRP_RET:
        case CS_GRP_IRET:
        case CS_GRP_INT:
          return fail("control-flow instruction cannot be a native island");
        case CS_GRP_JUMP:

          if (!is_tail || in.detail->x86.op_count < 1 ||
              in.detail->x86.operands[0].type != X86_OP_IMM) {
            return fail("control-flow instruction cannot be a native island");
          }
          break;
        default:
          break;
      }
    }
    switch (in.id) {
      case X86_INS_INT3: case X86_INS_INT: case X86_INS_INT1: case X86_INS_UD2:
      case X86_INS_HLT: case X86_INS_SYSCALL: case X86_INS_SYSENTER:
      case X86_INS_IRET: case X86_INS_IRETD: case X86_INS_IRETQ:
        return fail("control-flow instruction cannot be a native island");
      default:
        break;
    }

    NativeIsland isl;
    isl.orig_addr = in.address;
    isl.bytes.assign(in.bytes, in.bytes + in.size);
    isl.text = std::string(in.mnemonic) + " " + in.op_str;
    isl.tail_call = is_tail;

    {
      int delta = 0;
      uint64_t seed = opt_.base_address ^ in.address ^ 0x8C3D5A17u;
      std::vector<uint8_t> alt = metamorph(in, seed, &delta);
      if (!alt.empty() && alt.size() != isl.bytes.size()) {
        isl.bytes = alt;
        isl.meta_delta = delta;
      } else if (!alt.empty()) {
        isl.bytes = alt;
      }
    }

    {
      size_t npre = 0;
      while (npre < isl.bytes.size() &&
             (isl.bytes[npre] == 0x2E || isl.bytes[npre] == 0x3E ||
              isl.bytes[npre] == 0x26 || isl.bytes[npre] == 0x36)) {
        ++npre;
      }
      if (isl.bytes.size() == npre + 4 && isl.bytes[npre] == 0x66 &&
          isl.bytes[npre + 1] == 0x0F) {
        static const uint8_t kOps[8] = {0xEF, 0xDB, 0xEB, 0xDF,
                                        0x10, 0x6F, 0x11, 0x7F};
        static const uint8_t kAlts[8] = {0x57, 0x54, 0x56, 0x55,
                                         0x10, 0x28, 0x11, 0x29};
        static const unsigned kWant[8] = {X86_INS_XORPS, X86_INS_ANDPS,
                                          X86_INS_ORPS, X86_INS_ANDNPS,
                                          X86_INS_MOVUPS, X86_INS_MOVAPS,
                                          X86_INS_MOVUPS, X86_INS_MOVAPS};
        for (int fk = 0; fk < 8; ++fk) {
          if (isl.bytes[npre + 2] != kOps[fk]) continue;
          std::vector<uint8_t> alt;
          alt.push_back(0x0F);
          alt.push_back(kAlts[fk]);
          alt.push_back(isl.bytes[npre + 3]);
          alt.push_back(0x90);
          if (meta_ok_head(alt, in, kWant[fk])) {
            isl.flip_kind = static_cast<uint8_t>(fk + 1);
            isl.flip_off = static_cast<uint8_t>(npre);
          }
          break;
        }
      }
    }

    int imm_len = 0;
    for (int i = 0; i < in.detail->x86.op_count; ++i) {
      const cs_x86_op& o = in.detail->x86.operands[i];
      if (o.type == X86_OP_IMM) {
        imm_len = (o.size == 1) ? 1 : (o.size == 2) ? 2 : (o.size == 8) ? 8 : 4;
      }
    }
    if (!island_relative_field(in, imm_len, &isl)) return false;

    if (isl.meta_delta != 0 && isl.disp_off >= 0) {
      isl.disp_off += isl.meta_delta;
      if (isl.disp_off < 0) {
        return fail("relative field invalid after metamorphic encoding");
      }
    }

    if (isl.tail_call && isl.disp_off < 0) {
      return fail("tail-call rel32 target not found");
    }

    IRCommand c;
    c.op = IROp::Native;
    c.sub = static_cast<uint8_t>(prog_.natives.size());
    c.addr = in.address;
    c.flags |= IRF_NATIVE;
    prog_.natives.push_back(std::move(isl));
    prog_.add(c);

    if (is_tail) {

      written_ |= 1u << REG_RAX;
      IRCommand h = IRCommand::none(IROp::Halt);
      h.addr = in.address;
      prog_.add(h);
    }
    return true;
  }

  bool island_relative_field(cs_insn& in, int32_t imm_len, NativeIsland* isl) {
    const cs_x86& x = in.detail->x86;
    for (int i = 0; i < x.op_count; ++i) {
      const cs_x86_op& o = x.operands[i];
      if (o.type == X86_OP_MEM) {
        const bool rip_rel = (o.mem.base == X86_REG_RIP || o.mem.base == X86_REG_EIP);
        const bool absolute = (o.mem.base == X86_REG_INVALID &&
                               o.mem.index == X86_REG_INVALID);
        if (absolute) {
          return fail("native island contains an absolute memory address (cannot relocate)");
        }
        if (rip_rel) {
          const int32_t off = static_cast<int32_t>(in.size) - imm_len - 4;
          if (off < 0 || static_cast<size_t>(off) + 4 > in.size) {
            return fail("RIP-relative disp32 field not found");
          }
          int32_t got = 0;
          std::memcpy(&got, in.bytes + off, 4);
          if (got != static_cast<int32_t>(o.mem.disp)) {
            return fail("cannot verify RIP-relative disp32 field");
          }
          isl->disp_off = off;
          isl->disp_target = in.address + in.size +
                             static_cast<uint64_t>(static_cast<int64_t>(o.mem.disp));

          isl->disp_read = (o.access & CS_AC_READ) != 0;
          isl->disp_size = static_cast<uint8_t>(o.size);
        }
      } else if (o.type == X86_OP_IMM &&
                 (in.id == X86_INS_CALL || in.id == X86_INS_JMP)) {

        if (in.id == X86_INS_JMP && in.bytes[0] != 0xE9) {
          return fail("expected tail-call rel32 (E9) encoding");
        }
        const int32_t off = static_cast<int32_t>(in.size) - 4;
        if (off < 0) return fail("call rel32 field not found");
        const uint64_t target = static_cast<uint64_t>(o.imm);
        int32_t got = 0;
        std::memcpy(&got, in.bytes + off, 4);
        const int64_t want = static_cast<int64_t>(target) -
                             static_cast<int64_t>(in.address + in.size);
        if (static_cast<int64_t>(got) != want) {
          return fail("cannot verify call rel32 field");
        }
        isl->disp_off = off;
        isl->disp_target = target;
      }
    }
    return true;
  }

  bool emit_one(cs_insn& in) {
    last_reason_.clear();
    switch (in.id) {
      case X86_INS_NOP:
      case X86_INS_ENDBR32:
      case X86_INS_ENDBR64:
        return true;

      case X86_INS_MOV:
      case X86_INS_MOVABS:  return ins_mov(in);
      case X86_INS_LEA:     return ins_lea(in);
      case X86_INS_XCHG:    return ins_xchg(in);
      case X86_INS_MOVZX:   return ins_extend(in, false);
      case X86_INS_MOVSB:   return ins_string(in, false, 1);
      case X86_INS_MOVSW:   return ins_string(in, false, 2);
      case X86_INS_MOVSQ:   return ins_string(in, false, 8);
      case X86_INS_STOSB:   return ins_string(in, true, 1);
      case X86_INS_STOSW:   return ins_string(in, true, 2);
      case X86_INS_STOSD:   return ins_string(in, true, 4);
      case X86_INS_STOSQ:   return ins_string(in, true, 8);
      case X86_INS_CLD:     return ins_dirflag(true);
      case X86_INS_STD:     return ins_dirflag(false);

      case X86_INS_MOVSX:
      case X86_INS_MOVSXD:  return ins_extend(in, true);

      case X86_INS_ADD:     return ins_alu(in, AluOp::Add);
      case X86_INS_ADC:     return ins_alu(in, AluOp::Adc);
      case X86_INS_SUB:     return ins_alu(in, AluOp::Sub);
      case X86_INS_SBB:     return ins_alu(in, AluOp::Sbb);
      case X86_INS_AND:     return ins_alu(in, AluOp::And);
      case X86_INS_OR:      return ins_alu(in, AluOp::Or);
      case X86_INS_XOR:     return ins_alu(in, AluOp::Xor);
      case X86_INS_CMP:     return ins_alu(in, AluOp::Cmp);
      case X86_INS_TEST:    return ins_test(in);

      case X86_INS_INC:     return ins_unary(in, UnaryOp::Inc);
      case X86_INS_DEC:     return ins_unary(in, UnaryOp::Dec);
      case X86_INS_NOT:     return ins_unary(in, UnaryOp::Not);
      case X86_INS_NEG:     return ins_unary(in, UnaryOp::Neg);

      case X86_INS_SHL:
      case X86_INS_SAL:     return ins_shift(in, ShiftOp::Shl);
      case X86_INS_SHR:     return ins_shift(in, ShiftOp::Shr);
      case X86_INS_SAR:     return ins_shift(in, ShiftOp::Sar);
      case X86_INS_ROL:     return ins_shift(in, ShiftOp::Rol);
      case X86_INS_ROR:     return ins_shift(in, ShiftOp::Ror);
      case X86_INS_SHLD:    return ins_double_shift(in, true);
      case X86_INS_SHRD:    return ins_double_shift(in, false);

      case X86_INS_IMUL:    return ins_imul(in);
      case X86_INS_MUL:     return ins_muldiv(in, MulKind::Unsigned);
      case X86_INS_DIV:     return ins_muldiv(in, MulKind::Unsigned);
      case X86_INS_IDIV:    return ins_muldiv(in, MulKind::Signed);

      case X86_INS_CDQ:     return ins_signext(in, SignExtKind::Cdq);
      case X86_INS_CQO:     return ins_signext(in, SignExtKind::Cqo);
      case X86_INS_CDQE:    return ins_cdqe(in);
      case X86_INS_CWDE:    return ins_cwde(in);

      case X86_INS_BSWAP:   return ins_bswap(in);
      case X86_INS_BSF:
      case X86_INS_BSR:     return ins_bitscan(in);
      case X86_INS_TZCNT:
      case X86_INS_LZCNT:
      case X86_INS_POPCNT:  return ins_bitcount(in);
      case X86_INS_BT:
      case X86_INS_BTS:
      case X86_INS_BTR:
      case X86_INS_BTC:     return ins_bittest(in);

      case X86_INS_MOVAPS:
      case X86_INS_MOVUPS:
      case X86_INS_MOVAPD:
      case X86_INS_MOVUPD:
      case X86_INS_MOVDQA:
      case X86_INS_MOVDQU:  return ins_sse_mov16(in);
      case X86_INS_MOVSS:   return ins_sse_mov_scalar(in, 4, kSseMovSS);
      case X86_INS_MOVSD:
        if (in.detail->x86.op_count >= 1 &&
            in.detail->x86.operands[0].type == X86_OP_MEM) {
          return ins_string(in, false, 4);
        }
        return ins_sse_mov_scalar(in, 8, kSseMovSD);
      case X86_INS_MOVD:    return ins_sse_mov_gpr(in, 4);
      case X86_INS_MOVQ:    return ins_sse_mov_gpr(in, 8);

      case X86_INS_ADDSS:   return ins_sse_bin(in, SseBin::AddSS);
      case X86_INS_ADDSD:   return ins_sse_bin(in, SseBin::AddSD);
      case X86_INS_ADDPS:   return ins_sse_bin(in, SseBin::AddPS);
      case X86_INS_ADDPD:   return ins_sse_bin(in, SseBin::AddPD);
      case X86_INS_SUBSS:   return ins_sse_bin(in, SseBin::SubSS);
      case X86_INS_SUBSD:   return ins_sse_bin(in, SseBin::SubSD);
      case X86_INS_SUBPS:   return ins_sse_bin(in, SseBin::SubPS);
      case X86_INS_SUBPD:   return ins_sse_bin(in, SseBin::SubPD);
      case X86_INS_MULSS:   return ins_sse_bin(in, SseBin::MulSS);
      case X86_INS_MULSD:   return ins_sse_bin(in, SseBin::MulSD);
      case X86_INS_MULPS:   return ins_sse_bin(in, SseBin::MulPS);
      case X86_INS_MULPD:   return ins_sse_bin(in, SseBin::MulPD);
      case X86_INS_DIVSS:   return ins_sse_bin(in, SseBin::DivSS);
      case X86_INS_DIVSD:   return ins_sse_bin(in, SseBin::DivSD);
      case X86_INS_DIVPS:   return ins_sse_bin(in, SseBin::DivPS);
      case X86_INS_DIVPD:   return ins_sse_bin(in, SseBin::DivPD);
      case X86_INS_MINSS:   return ins_sse_bin(in, SseBin::MinSS);
      case X86_INS_MINSD:   return ins_sse_bin(in, SseBin::MinSD);
      case X86_INS_MINPS:   return ins_sse_bin(in, SseBin::MinPS);
      case X86_INS_MINPD:   return ins_sse_bin(in, SseBin::MinPD);
      case X86_INS_MAXSS:   return ins_sse_bin(in, SseBin::MaxSS);
      case X86_INS_MAXSD:   return ins_sse_bin(in, SseBin::MaxSD);
      case X86_INS_MAXPS:   return ins_sse_bin(in, SseBin::MaxPS);
      case X86_INS_MAXPD:   return ins_sse_bin(in, SseBin::MaxPD);
      case X86_INS_ANDPS:   return ins_sse_bin(in, SseBin::AndPS);
      case X86_INS_ANDPD:   return ins_sse_bin(in, SseBin::AndPD);
      case X86_INS_ANDNPS:  return ins_sse_bin(in, SseBin::AndNPS);
      case X86_INS_ANDNPD:  return ins_sse_bin(in, SseBin::AndNPD);
      case X86_INS_ORPS:    return ins_sse_bin(in, SseBin::OrPS);
      case X86_INS_ORPD:    return ins_sse_bin(in, SseBin::OrPD);
      case X86_INS_XORPS:   return ins_sse_bin(in, SseBin::XorPS);
      case X86_INS_XORPD:   return ins_sse_bin(in, SseBin::XorPD);
      case X86_INS_PAND:    return ins_sse_bin(in, SseBin::PAnd);
      case X86_INS_PANDN:   return ins_sse_bin(in, SseBin::PAndN);
      case X86_INS_POR:     return ins_sse_bin(in, SseBin::POr);
      case X86_INS_PXOR:    return ins_sse_bin(in, SseBin::PXor);
      case X86_INS_PADDB:   return ins_sse_bin(in, SseBin::PAddB);
      case X86_INS_PADDW:   return ins_sse_bin(in, SseBin::PAddW);
      case X86_INS_PADDD:   return ins_sse_bin(in, SseBin::PAddD);
      case X86_INS_PADDQ:   return ins_sse_bin(in, SseBin::PAddQ);
      case X86_INS_PSUBB:   return ins_sse_bin(in, SseBin::PSubB);
      case X86_INS_PSUBW:   return ins_sse_bin(in, SseBin::PSubW);
      case X86_INS_PSUBD:   return ins_sse_bin(in, SseBin::PSubD);
      case X86_INS_PSUBQ:   return ins_sse_bin(in, SseBin::PSubQ);

      case X86_INS_SQRTSS:  return ins_sse_un(in, SseUn::SqrtSS, kSseMovSS);
      case X86_INS_SQRTSD:  return ins_sse_un(in, SseUn::SqrtSD, kSseMovSD);
      case X86_INS_SQRTPS:  return ins_sse_un(in, SseUn::SqrtPS, kSseMovFull);
      case X86_INS_SQRTPD:  return ins_sse_un(in, SseUn::SqrtPD, kSseMovFull);

      case X86_INS_COMISS:  return ins_sse_cmp(in, SseCmp::ComiSS);
      case X86_INS_UCOMISS: return ins_sse_cmp(in, SseCmp::UcomiSS);
      case X86_INS_COMISD:  return ins_sse_cmp(in, SseCmp::ComiSD);
      case X86_INS_UCOMISD: return ins_sse_cmp(in, SseCmp::UcomiSD);

      case X86_INS_CVTSI2SS:  return ins_sse_cvt(in, 0);
      case X86_INS_CVTSI2SD:  return ins_sse_cvt(in, 1);
      case X86_INS_CVTTSS2SI: return ins_sse_cvt(in, 2);
      case X86_INS_CVTTSD2SI: return ins_sse_cvt(in, 3);
      case X86_INS_CVTSS2SD:  return ins_sse_cvt(in, 4);
      case X86_INS_CVTSD2SS:  return ins_sse_cvt(in, 5);

      case X86_INS_PSHUFD:  return ins_sse_shuf(in, SseShuf::Pshufd);
      case X86_INS_SHUFPS:  return ins_sse_shuf(in, SseShuf::ShufPS);
      case X86_INS_SHUFPD:  return ins_sse_shuf(in, SseShuf::ShufPD);
      case X86_INS_UNPCKLPS:return ins_sse_shuf(in, SseShuf::UnpckLPS);
      case X86_INS_UNPCKLPD:return ins_sse_shuf(in, SseShuf::UnpckLPD);
      case X86_INS_PUNPCKLQDQ: return ins_sse_shuf(in, SseShuf::UnpckLQDQ);
      case X86_INS_PUNPCKHQDQ: return ins_sse_shuf(in, SseShuf::UnpckHQDQ);

      case X86_INS_PADDSB:   return ins_sse_bin(in, SseBin::PAddSB);
      case X86_INS_PADDSW:   return ins_sse_bin(in, SseBin::PAddSW);
      case X86_INS_PADDUSB:  return ins_sse_bin(in, SseBin::PAddUSB);
      case X86_INS_PADDUSW:  return ins_sse_bin(in, SseBin::PAddUSW);
      case X86_INS_PSUBSB:   return ins_sse_bin(in, SseBin::PSubSB);
      case X86_INS_PSUBSW:   return ins_sse_bin(in, SseBin::PSubSW);
      case X86_INS_PSUBUSB:  return ins_sse_bin(in, SseBin::PSubUSB);
      case X86_INS_PSUBUSW:  return ins_sse_bin(in, SseBin::PSubUSW);
      case X86_INS_PMULLW:   return ins_sse_bin(in, SseBin::PMullW);
      case X86_INS_PMULHW:   return ins_sse_bin(in, SseBin::PMulHW);
      case X86_INS_PMULHUW:  return ins_sse_bin(in, SseBin::PMulHUW);
      case X86_INS_PMULLD:   return ins_sse_bin(in, SseBin::PMulLD);
      case X86_INS_PMULUDQ:  return ins_sse_bin(in, SseBin::PMulUDQ);
      case X86_INS_PMADDWD:  return ins_sse_bin(in, SseBin::PMaddWD);
      case X86_INS_PMINUB:   return ins_sse_bin(in, SseBin::PMinUB);
      case X86_INS_PMINSW:   return ins_sse_bin(in, SseBin::PMinSW);
      case X86_INS_PMINUD:   return ins_sse_bin(in, SseBin::PMinUD);
      case X86_INS_PMAXUB:   return ins_sse_bin(in, SseBin::PMaxUB);
      case X86_INS_PMAXSW:   return ins_sse_bin(in, SseBin::PMaxSW);
      case X86_INS_PMAXUD:   return ins_sse_bin(in, SseBin::PMaxUD);
      case X86_INS_PCMPEQB:  return ins_sse_bin(in, SseBin::PCmpeqB);
      case X86_INS_PCMPEQW:  return ins_sse_bin(in, SseBin::PCmpeqW);
      case X86_INS_PCMPEQD:  return ins_sse_bin(in, SseBin::PCmpeqD);
      case X86_INS_PCMPGTB:  return ins_sse_bin(in, SseBin::PCmpgtB);
      case X86_INS_PCMPGTW:  return ins_sse_bin(in, SseBin::PCmpgtW);
      case X86_INS_PCMPGTD:  return ins_sse_bin(in, SseBin::PCmpgtD);
      case X86_INS_PUNPCKLBW:return ins_sse_bin(in, SseBin::PunpckLBW);
      case X86_INS_PUNPCKLWD:return ins_sse_bin(in, SseBin::PunpckLWD);
      case X86_INS_PUNPCKLDQ:return ins_sse_bin(in, SseBin::PunpckLDQ);
      case X86_INS_PUNPCKHBW:return ins_sse_bin(in, SseBin::PunpckHBW);
      case X86_INS_PUNPCKHWD:return ins_sse_bin(in, SseBin::PunpckHWD);
      case X86_INS_PUNPCKHDQ:return ins_sse_bin(in, SseBin::PunpckHDQ);
      case X86_INS_PACKSSWB: return ins_sse_bin(in, SseBin::PackssWB);
      case X86_INS_PACKSSDW: return ins_sse_bin(in, SseBin::PackssDW);
      case X86_INS_PACKUSWB: return ins_sse_bin(in, SseBin::PackusWB);
      case X86_INS_PABSB:    return ins_sse_bin(in, SseBin::PabsB);
      case X86_INS_PABSW:    return ins_sse_bin(in, SseBin::PabsW);
      case X86_INS_PABSD:    return ins_sse_bin(in, SseBin::PabsD);
      case X86_INS_PAVGB:    return ins_sse_bin(in, SseBin::PavgB);
      case X86_INS_PAVGW:    return ins_sse_bin(in, SseBin::PavgW);
      case X86_INS_PSIGNB:   return ins_sse_bin(in, SseBin::PsignB);
      case X86_INS_PSIGNW:   return ins_sse_bin(in, SseBin::PsignW);
      case X86_INS_PSIGND:   return ins_sse_bin(in, SseBin::PsignD);

      case X86_INS_PSLLW:    return ins_sse_shift(in, SseShift::PslW);
      case X86_INS_PSLLD:    return ins_sse_shift(in, SseShift::PslD);
      case X86_INS_PSLLQ:    return ins_sse_shift(in, SseShift::PslQ);
      case X86_INS_PSRLW:    return ins_sse_shift(in, SseShift::PsrW);
      case X86_INS_PSRLD:    return ins_sse_shift(in, SseShift::PsrD);
      case X86_INS_PSRLQ:    return ins_sse_shift(in, SseShift::PsrQ);
      case X86_INS_PSRAW:    return ins_sse_shift(in, SseShift::PsaW);
      case X86_INS_PSRAD:    return ins_sse_shift(in, SseShift::PsaD);
      case X86_INS_PSLLDQ:   return ins_sse_shift(in, SseShift::PslDQ);
      case X86_INS_PSRLDQ:   return ins_sse_shift(in, SseShift::PsrDQ);

      case X86_INS_VADDPS:   return ins_sse_bin3(in, SseBin::AddPS);
      case X86_INS_VADDPD:   return ins_sse_bin3(in, SseBin::AddPD);
      case X86_INS_VADDSS:   return ins_sse_bin3(in, SseBin::AddSS);
      case X86_INS_VADDSD:   return ins_sse_bin3(in, SseBin::AddSD);
      case X86_INS_VSUBPS:   return ins_sse_bin3(in, SseBin::SubPS);
      case X86_INS_VSUBPD:   return ins_sse_bin3(in, SseBin::SubPD);
      case X86_INS_VSUBSS:   return ins_sse_bin3(in, SseBin::SubSS);
      case X86_INS_VSUBSD:   return ins_sse_bin3(in, SseBin::SubSD);
      case X86_INS_VMULPS:   return ins_sse_bin3(in, SseBin::MulPS);
      case X86_INS_VMULPD:   return ins_sse_bin3(in, SseBin::MulPD);
      case X86_INS_VMULSS:   return ins_sse_bin3(in, SseBin::MulSS);
      case X86_INS_VMULSD:   return ins_sse_bin3(in, SseBin::MulSD);
      case X86_INS_VDIVPS:   return ins_sse_bin3(in, SseBin::DivPS);
      case X86_INS_VDIVPD:   return ins_sse_bin3(in, SseBin::DivPD);
      case X86_INS_VDIVSS:   return ins_sse_bin3(in, SseBin::DivSS);
      case X86_INS_VDIVSD:   return ins_sse_bin3(in, SseBin::DivSD);
      case X86_INS_VMINPS:   return ins_sse_bin3(in, SseBin::MinPS);
      case X86_INS_VMINPD:   return ins_sse_bin3(in, SseBin::MinPD);
      case X86_INS_VMAXPS:   return ins_sse_bin3(in, SseBin::MaxPS);
      case X86_INS_VMAXPD:   return ins_sse_bin3(in, SseBin::MaxPD);
      case X86_INS_VANDPS:   return ins_sse_bin3(in, SseBin::AndPS);
      case X86_INS_VANDPD:   return ins_sse_bin3(in, SseBin::AndPD);
      case X86_INS_VANDNPS:  return ins_sse_bin3(in, SseBin::AndNPS);
      case X86_INS_VANDNPD:  return ins_sse_bin3(in, SseBin::AndNPD);
      case X86_INS_VORPS:    return ins_sse_bin3(in, SseBin::OrPS);
      case X86_INS_VORPD:    return ins_sse_bin3(in, SseBin::OrPD);
      case X86_INS_VXORPS:   return ins_sse_bin3(in, SseBin::XorPS);
      case X86_INS_VXORPD:   return ins_sse_bin3(in, SseBin::XorPD);
      case X86_INS_VPAND:    return ins_sse_bin3(in, SseBin::PAnd);
      case X86_INS_VPANDN:   return ins_sse_bin3(in, SseBin::PAndN);
      case X86_INS_VPOR:     return ins_sse_bin3(in, SseBin::POr);
      case X86_INS_VPXOR:    return ins_sse_bin3(in, SseBin::PXor);
      case X86_INS_VPADDB:   return ins_sse_bin3(in, SseBin::PAddB);
      case X86_INS_VPADDW:   return ins_sse_bin3(in, SseBin::PAddW);
      case X86_INS_VPADDD:   return ins_sse_bin3(in, SseBin::PAddD);
      case X86_INS_VPADDQ:   return ins_sse_bin3(in, SseBin::PAddQ);
      case X86_INS_VPSUBB:   return ins_sse_bin3(in, SseBin::PSubB);
      case X86_INS_VPSUBW:   return ins_sse_bin3(in, SseBin::PSubW);
      case X86_INS_VPSUBD:   return ins_sse_bin3(in, SseBin::PSubD);
      case X86_INS_VPSUBQ:   return ins_sse_bin3(in, SseBin::PSubQ);
      case X86_INS_VPMULLW:  return ins_sse_bin3(in, SseBin::PMullW);
      case X86_INS_VPMULLD:  return ins_sse_bin3(in, SseBin::PMulLD);
      case X86_INS_VPMULUDQ: return ins_sse_bin3(in, SseBin::PMulUDQ);
      case X86_INS_VPMADDWD: return ins_sse_bin3(in, SseBin::PMaddWD);
      case X86_INS_VPCMPEQB: return ins_sse_bin3(in, SseBin::PCmpeqB);
      case X86_INS_VPCMPEQW: return ins_sse_bin3(in, SseBin::PCmpeqW);
      case X86_INS_VPCMPEQD: return ins_sse_bin3(in, SseBin::PCmpeqD);
      case X86_INS_VPCMPGTB: return ins_sse_bin3(in, SseBin::PCmpgtB);
      case X86_INS_VPCMPGTW: return ins_sse_bin3(in, SseBin::PCmpgtW);
      case X86_INS_VPCMPGTD: return ins_sse_bin3(in, SseBin::PCmpgtD);
      case X86_INS_VPABSB:   return ins_sse_bin3(in, SseBin::PabsB);
      case X86_INS_VPABSW:   return ins_sse_bin3(in, SseBin::PabsW);
      case X86_INS_VPABSD:   return ins_sse_bin3(in, SseBin::PabsD);
      case X86_INS_VPAVGB:   return ins_sse_bin3(in, SseBin::PavgB);
      case X86_INS_VPAVGW:   return ins_sse_bin3(in, SseBin::PavgW);

      case X86_INS_VMOVAPS:
      case X86_INS_VMOVUPS:
      case X86_INS_VMOVAPD:
      case X86_INS_VMOVUPD:
      case X86_INS_VMOVDQA:
      case X86_INS_VMOVDQU:  return ins_sse_mov16(in);
      case X86_INS_VPSLLW:   return ins_sse_shift(in, SseShift::PslW);
      case X86_INS_VPSLLD:   return ins_sse_shift(in, SseShift::PslD);
      case X86_INS_VPSLLQ:   return ins_sse_shift(in, SseShift::PslQ);
      case X86_INS_VPSRLW:   return ins_sse_shift(in, SseShift::PsrW);
      case X86_INS_VPSRLD:   return ins_sse_shift(in, SseShift::PsrD);
      case X86_INS_VPSRLQ:   return ins_sse_shift(in, SseShift::PsrQ);
      case X86_INS_VPSRAW:   return ins_sse_shift(in, SseShift::PsaW);
      case X86_INS_VPSRAD:   return ins_sse_shift(in, SseShift::PsaD);
      case X86_INS_VPSLLDQ:  return ins_sse_shift(in, SseShift::PslDQ);
      case X86_INS_VPSRLDQ:  return ins_sse_shift(in, SseShift::PsrDQ);
      case X86_INS_VZEROUPPER:
      case X86_INS_VZEROALL: prog_.add(IRCommand::none(IROp::Nop)); return true;

      case X86_INS_PUSH:    return ins_push(in);
      case X86_INS_POP:     return ins_pop(in);
      case X86_INS_PUSHFQ:
      case X86_INS_PUSHF:   prog_.add(IRCommand::none(IROp::Pushf)); return true;
      case X86_INS_POPFQ:
      case X86_INS_POPF:    prog_.add(IRCommand::none(IROp::Popf)); return true;
      case X86_INS_LEAVE:   return ins_leave(in);

      case X86_INS_JMP:     return ins_jmp(in);
      case X86_INS_CALL:    return ins_call(in);
      case X86_INS_RET:
        prog_.add(IRCommand::none(IROp::Ret));
        return true;
      case X86_INS_RETF:
      case X86_INS_RETFQ:
        return fail("RETF not supported");

      default:
        break;
    }

    if (in.detail->groups_count > 0) {
      for (int g = 0; g < in.detail->groups_count; ++g) {
        if (in.detail->groups[g] == CS_GRP_JUMP) return ins_jcc(in);
      }
    }

    uint8_t cc = 0;
    if (cmov_cc(&in, &cc)) return ins_cmov(in, cc);
    if (setcc_cc(&in, &cc)) return ins_setcc(in, cc);

    return fail("instruction not supported");
  }

  bool ins_cmov(cs_insn& in, uint8_t cc) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("cmov: 2 operands expected");
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    if (d.kind != IRKind::Reg) return fail("cmov target must be a register");
    if (!check_size(d.size)) return false;

    IRCommand c = IRCommand::none(IROp::Cmov);
    c.sub = cc;
    c.dst = d;
    c.src = s;
    c.size = d.size;
    prog_.add(c);
    return true;
  }

  bool ins_setcc(cs_insn& in, uint8_t cc) {
    IROperand d;
    if (!to_operand(in, 0, &d)) return false;

    prog_.add(IRCommand::mov(IROperand::R(REG_T3), IROperand::I(1, 8)));
    prog_.add(IRCommand::mov(IROperand::R(REG_T4, 1), IROperand::I(0, 1)));

    IRCommand cm = IRCommand::none(IROp::Cmov);
    cm.sub = cc;
    cm.size = 1;
    cm.dst = IROperand::R(REG_T4, 1);
    cm.src = IROperand::R(REG_T3, 1);
    prog_.add(cm);

    if (d.kind == IRKind::Reg) {
      prog_.add(IRCommand::mov(IROperand::R(d.reg, 1), IROperand::R(REG_T4, 1)));
    } else if (d.kind == IRKind::Mem) {
      prog_.add(IRCommand::mov(IROperand::M(d.mem, 1), IROperand::R(REG_T4, 1)));
    } else {
      return fail("setcc target must be reg/mem");
    }
    return true;
  }

  bool ins_mov(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("mov: 2 operands expected");

    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;

    uint8_t size = d.size > s.size ? d.size : s.size;
    if (s.kind == IRKind::Imm) size = d.size;
    if (!check_size(size)) return false;
    if (s.kind == IRKind::Imm) s.imm = sext_imm(s.imm, s.size, size);

    d.size = size;
    s.size = size;

    if (d.kind == IRKind::Mem && s.kind == IRKind::Mem) return fail("no mem->mem mov");
    prog_.add(IRCommand::mov(d, s));
    return true;
  }

  bool to_operand(const cs_insn& in, int i, IROperand* out) {
    const cs_x86_op& o = in.detail->x86.operands[i];
    switch (o.type) {
      case X86_OP_REG: {
        int parent = -1;
        if (high_byte_parent(o.reg, &parent)) {
          const int v = parent;
          if (hb_parent_ >= 0 && hb_parent_ != v) return fail("two high-byte operands");
          const uint32_t access = o.access & (CS_AC_READ | CS_AC_WRITE);
          const bool rd = access == 0 || (access & CS_AC_READ) != 0;
          const bool wr = access == 0 || (access & CS_AC_WRITE) != 0;
          if (rd && !hb_loaded_) {
            prog_.add(IRCommand::mov(IROperand::R(REG_T1, 8), IROperand::R(v, 8)));
            IRCommand sh = IRCommand::none(IROp::Shift);
            sh.sub = static_cast<uint8_t>(ShiftOp::Shr);
            sh.dst = IROperand::R(REG_T1, 8);
            sh.src = IROperand::I(8, 1);
            sh.size = 8;
            prog_.add(sh);
            hb_loaded_ = true;
          }
          hb_parent_ = v;
          if (wr) hb_write_ = true;
          *out = IROperand::R(REG_T1, 1);
          return true;
        }
        const int v = vreg_for(o.reg);
        if (v < 0) return fail(reg_reason(o.reg));
        *out = IROperand::R(v, static_cast<uint8_t>(o.size));
        return true;
      }
      case X86_OP_IMM:
        *out = IROperand::I(o.imm, static_cast<uint8_t>(o.size));
        return true;
      case X86_OP_MEM: {
        IRMem m;
        uint8_t sz = 0;
        if (!op_mem(in, i, &m, &sz)) return false;
        *out = IROperand::M(m, sz);
        return true;
      }
      default:
        return fail("operand type not supported");
    }
  }

  bool ins_dirflag(bool clear) {
    prog_.add(IRCommand::none(IROp::Pushf));
    IRCommand read = IRCommand::none(IROp::Pop);
    read.dst = IROperand::R(REG_T1, 8);
    prog_.add(read);
    prog_.add(IRCommand::alu(clear ? AluOp::And : AluOp::Or,
                             IROperand::R(REG_T1, 8),
                             IROperand::I(clear ? static_cast<int64_t>(~0x400ull) : 0x400,
                                          8)));
    IRCommand write = IRCommand::none(IROp::Push);
    write.src = IROperand::R(REG_T1, 8);
    prog_.add(write);
    prog_.add(IRCommand::none(IROp::Popf));
    return true;
  }

  bool ins_string(cs_insn& in, bool stos, uint8_t size) {
    const uint8_t p1 = in.detail->x86.prefix[1];
    if (p1 == X86_PREFIX_CS || p1 == X86_PREFIX_SS || p1 == X86_PREFIX_DS ||
        p1 == X86_PREFIX_ES || p1 == X86_PREFIX_FS || p1 == X86_PREFIX_GS) {
      return fail("string op with a segment override stays an island");
    }
    const bool rep = in.detail->x86.prefix[0] == 0xF3;

    prog_.add(IRCommand::none(IROp::Pushf));
    IRCommand read_flags = IRCommand::none(IROp::Pop);
    read_flags.dst = IROperand::R(REG_T1, 8);
    prog_.add(read_flags);

    prog_.add(IRCommand::mov(IROperand::R(REG_T2, 8), IROperand::I(size, 8)));
    prog_.add(IRCommand::mov(IROperand::R(REG_T3, 8),
                             IROperand::I(-static_cast<int64_t>(size), 8)));
    IRCommand df = IRCommand::none(IROp::Test);
    df.dst = IROperand::R(REG_T1, 8);
    df.src = IROperand::I(0x400, 8);
    df.size = 8;
    prog_.add(df);
    IRCommand pick = IRCommand::none(IROp::Cmov);
    pick.sub = 0x5;
    pick.dst = IROperand::R(REG_T2, 8);
    pick.src = IROperand::R(REG_T3, 8);
    pick.size = 8;
    prog_.add(pick);
    IRCommand restore = IRCommand::none(IROp::Push);
    restore.src = IROperand::R(REG_T1, 8);
    prog_.add(restore);
    prog_.add(IRCommand::none(IROp::Popf));

    const int loop = prog_.new_label();
    const int done = prog_.new_label();

    prog_.bind(loop);
    if (rep) {
      IRCommand count = IRCommand::none(IROp::Test);
      count.dst = IROperand::R(REG_RCX, 8);
      count.src = IROperand::R(REG_RCX, 8);
      count.size = 8;
      prog_.add(count);
      IRCommand jz = IRCommand::br(IROp::Jcc, done);
      jz.sub = 0x4;
      prog_.add(jz);
    }

    if (stos) {
      prog_.add(IRCommand::mov(IROperand::R(REG_T3, size),
                               IROperand::R(REG_RAX, size)));
      prog_.add(IRCommand::mov(
          IROperand::M(IRMem{.base = REG_RDI, .index = -1, .scale = 1, .disp = 0},
                       size),
          IROperand::R(REG_T3, size)));
    } else {
      prog_.add(IRCommand::mov(
          IROperand::R(REG_T3, size),
          IROperand::M(IRMem{.base = REG_RSI, .index = -1, .scale = 1, .disp = 0},
                       size)));
      prog_.add(IRCommand::mov(
          IROperand::M(IRMem{.base = REG_RDI, .index = -1, .scale = 1, .disp = 0},
                       size),
          IROperand::R(REG_T3, size)));
      prog_.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RSI, 8),
                               IROperand::R(REG_T2, 8)));
    }
    prog_.add(IRCommand::alu(AluOp::Add, IROperand::R(REG_RDI, 8),
                             IROperand::R(REG_T2, 8)));
    if (rep) {
      prog_.add(IRCommand::alu(AluOp::Sub, IROperand::R(REG_RCX, 8),
                               IROperand::I(1, 8)));
      prog_.add(IRCommand::br(IROp::Jmp, loop));
    }
    prog_.bind(done);
    return true;
  }

  void flush_high_byte() {
    if (hb_parent_ >= 0 && hb_write_) {
      const int parent = hb_parent_;
      prog_.add(IRCommand::none(IROp::Pushf));
      prog_.add(IRCommand::mov(IROperand::R(REG_T2, 8), IROperand::R(REG_T1, 8)));
      prog_.add(IRCommand::alu(AluOp::And, IROperand::R(REG_T2, 8),
                               IROperand::I(0xff, 8)));
      IRCommand sh = IRCommand::none(IROp::Shift);
      sh.sub = static_cast<uint8_t>(ShiftOp::Shl);
      sh.dst = IROperand::R(REG_T2, 8);
      sh.src = IROperand::I(8, 1);
      sh.size = 8;
      prog_.add(sh);
      prog_.add(IRCommand::mov(IROperand::R(REG_T3, 8), IROperand::R(parent, 8)));
      prog_.add(IRCommand::alu(AluOp::And, IROperand::R(REG_T3, 8),
                               IROperand::I(static_cast<int64_t>(~0xff00ull), 8)));
      prog_.add(IRCommand::alu(AluOp::Or, IROperand::R(REG_T3, 8),
                               IROperand::R(REG_T2, 8)));
      prog_.add(IRCommand::mov(IROperand::R(parent, 8), IROperand::R(REG_T3, 8)));
      prog_.add(IRCommand::none(IROp::Popf));
    }
    hb_parent_ = -1;
    hb_write_ = false;
    hb_loaded_ = false;
  }

  bool sse_op(const cs_insn& in, int i, IROperand* out) {
    if (i >= in.detail->x86.op_count) return fail("not enough SSE operands");
    const cs_x86_op& o = in.detail->x86.operands[i];
    if (o.type == X86_OP_REG && o.reg >= X86_REG_XMM0 &&
        o.reg <= X86_REG_XMM31) {
      *out = IROperand::X(static_cast<int>(o.reg - X86_REG_XMM0),
                          static_cast<uint8_t>(o.size));
      return true;
    }

    if (o.type == X86_OP_REG && o.reg >= X86_REG_YMM0 &&
        o.reg <= X86_REG_YMM31) {
      *out = IROperand::X(static_cast<int>(o.reg - X86_REG_YMM0), 32);
      return true;
    }
    return to_operand(in, i, out);
  }

  bool ins_sse_mov16(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("sse mov: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;

    const uint8_t sz = d.kind == IRKind::Xmm ? d.size : s.size;
    if (d.kind == IRKind::Xmm && s.kind == IRKind::Xmm) {
      IRCommand c = IRCommand::none(IROp::SseMov);
      c.dst = d; c.src = s; c.size = sz == 32 ? 32 : 16; c.sub = kSseMovFull;
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Xmm && s.kind == IRKind::Mem) {
      IRCommand c = IRCommand::none(IROp::SseLoad);
      c.dst = d; c.src = s; c.size = sz == 32 ? 32 : 16;
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Mem && s.kind == IRKind::Xmm) {
      IRCommand c = IRCommand::none(IROp::SseStore);
      c.dst = d; c.src = s; c.size = sz == 32 ? 32 : 16;
      prog_.add(c);
      return true;
    }
    return fail("sse mov: invalid operand combination");
  }

  bool ins_sse_mov_scalar(cs_insn& in, uint8_t bytes, uint8_t movsub) {
    const cs_x86& x = in.detail->x86;

    if (x.op_count != 2) return fail("scalar sse mov: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;
    if (d.kind == IRKind::Xmm && s.kind == IRKind::Xmm) {
      IRCommand c = IRCommand::none(IROp::SseMov);
      c.dst = d; c.src = s; c.size = 16; c.sub = movsub;
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Xmm && s.kind == IRKind::Mem) {
      IRCommand c = IRCommand::none(IROp::SseLoad);
      c.dst = d; c.src = s; c.size = bytes;
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Mem && s.kind == IRKind::Xmm) {
      IRCommand c = IRCommand::none(IROp::SseStore);
      c.dst = d; c.src = s; c.size = bytes;
      prog_.add(c);
      return true;
    }
    return fail("scalar sse mov: invalid operand combination");
  }

  bool ins_sse_mov_gpr(cs_insn& in, uint8_t bytes) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("movd/movq: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;
    const bool movq = (bytes == 8);

    if (d.kind == IRKind::Xmm && s.kind == IRKind::Xmm) {
      if (!movq) return fail("movd: cannot have two XMM operands");

      IRCommand c = IRCommand::none(IROp::SseMov);
      c.dst = d; c.src = s; c.size = 16; c.sub = kSseMovQ;
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Xmm && s.kind == IRKind::Reg) {
      IRCommand c = IRCommand::none(IROp::SseCvt);
      c.dst = d; c.src = s;
      c.sub = movq ? static_cast<uint8_t>(SseCvt::MovqToX)
                   : static_cast<uint8_t>(SseCvt::MovdToX);
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Reg && s.kind == IRKind::Xmm) {
      IRCommand c = IRCommand::none(IROp::SseCvt);
      c.dst = d; c.src = s;
      c.sub = movq ? static_cast<uint8_t>(SseCvt::MovqFromX)
                   : static_cast<uint8_t>(SseCvt::MovdFromX);
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Xmm && s.kind == IRKind::Mem) {
      IRCommand c = IRCommand::none(IROp::SseLoad);
      c.dst = d; c.src = s; c.size = bytes;
      prog_.add(c);
      return true;
    }
    if (d.kind == IRKind::Mem && s.kind == IRKind::Xmm) {
      IRCommand c = IRCommand::none(IROp::SseStore);
      c.dst = d; c.src = s; c.size = bytes;
      prog_.add(c);
      return true;
    }
    return fail("movd/movq: invalid operand combination");
  }

  bool ins_sse_bin(cs_insn& in, SseBin sub) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("sse binary op: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;
    if (d.kind != IRKind::Xmm) return fail("sse binary op target must be XMM");
    if (s.kind != IRKind::Xmm && s.kind != IRKind::Mem)
      return fail("sse binary op source must be XMM/memory");
    IRCommand c = IRCommand::none(IROp::SseBin);
    c.dst = d; c.src = s; c.size = 16; c.sub = static_cast<uint8_t>(sub);
    prog_.add(c);
    return true;
  }

  bool ins_sse_bin3(cs_insn& in, SseBin sub) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 3) return fail("avx 3-operand: 3 operands expected");
    IROperand d, s1, s2;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s1)) return false;
    if (!sse_op(in, 2, &s2)) return false;
    if (d.kind != IRKind::Xmm) return fail("avx target must be XMM");
    if (s1.kind != IRKind::Xmm) return fail("avx src1 must be XMM");
    if (s2.kind != IRKind::Xmm)
      return fail("avx src2 must be a register (memory island)");
    IRCommand c = IRCommand::none(IROp::SseBin3);
    c.dst = d; c.src = s1; c.size = (d.size == 32) ? 32 : 16;
    c.sub = static_cast<uint8_t>(sub);
    c.aux = IROperand::I(s2.reg);
    prog_.add(c);
    return true;
  }

  bool ins_sse_un(cs_insn& in, SseUn sub, uint8_t movsub) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("sse unary op: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;
    if (d.kind != IRKind::Xmm) return fail("sse unary op target must be XMM");
    if (s.kind == IRKind::Xmm) {
      IRCommand m = IRCommand::none(IROp::SseMov);
      m.dst = d; m.src = s; m.size = 16; m.sub = movsub;
      prog_.add(m);
    } else if (s.kind == IRKind::Mem) {
      IRCommand l = IRCommand::none(IROp::SseLoad);
      l.dst = d; l.src = s; l.size = 16;
      prog_.add(l);
    } else {
      return fail("sse unary op source must be XMM/memory");
    }
    IRCommand c = IRCommand::none(IROp::SseUn);
    c.dst = d; c.size = 16; c.sub = static_cast<uint8_t>(sub);
    prog_.add(c);
    return true;
  }

  bool ins_sse_cmp(cs_insn& in, SseCmp sub) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("comiss: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;
    if (d.kind != IRKind::Xmm) return fail("comiss target must be XMM");
    if (s.kind != IRKind::Xmm && s.kind != IRKind::Mem)
      return fail("comiss source must be XMM/memory");
    IRCommand c = IRCommand::none(IROp::SseCmp);
    c.dst = d; c.src = s; c.size = 16; c.sub = static_cast<uint8_t>(sub);
    prog_.add(c);
    return true;
  }

  bool ins_sse_cvt(cs_insn& in, int kind) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("sse conversion: 2 operands expected");
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (!sse_op(in, 1, &s)) return false;

    if (s.kind == IRKind::Mem && kind <= 1) {
      prog_.add(IRCommand::mov(IROperand::R(REG_T1, s.size), s));
      s = IROperand::R(REG_T1, s.size);
    }
    if (s.kind == IRKind::Mem) return fail("sse conversion memory source is an island");
    if (d.kind == IRKind::Mem) return fail("sse conversion memory target is an island");

    SseCvt sub;
    switch (kind) {
      case 0: sub = (s.size == 8) ? SseCvt::Si2SS64 : SseCvt::Si2SS32; break;
      case 1: sub = (s.size == 8) ? SseCvt::Si2SD64 : SseCvt::Si2SD32; break;
      case 2: sub = (d.size == 8) ? SseCvt::TtSS2Si64 : SseCvt::TtSS2Si32; break;
      case 3: sub = (d.size == 8) ? SseCvt::TtSD2Si64 : SseCvt::TtSD2Si32; break;
      case 4: sub = SseCvt::Ss2Sd; break;
      default: sub = SseCvt::Sd2Ss; break;
    }
    if (kind <= 1 && s.kind != IRKind::Reg) return fail("cvtsi2* source must be GPR");
    if (kind >= 2 && kind <= 3 && s.kind != IRKind::Xmm)
      return fail("cvtt* source must be XMM");
    if (kind >= 2 && d.kind != IRKind::Reg) return fail("cvtt* target must be GPR");
    if (kind >= 4 && (d.kind != IRKind::Xmm || s.kind != IRKind::Xmm))
      return fail("cvtss2sd/cvtsd2ss operands must be XMM");

    IRCommand c = IRCommand::none(IROp::SseCvt);
    c.dst = d; c.src = s; c.size = 16; c.sub = static_cast<uint8_t>(sub);
    prog_.add(c);
    return true;
  }

  bool ins_sse_shuf(cs_insn& in, SseShuf sub) {
    const cs_x86& x = in.detail->x86;
    int n = x.op_count;
    IROperand d, s;
    if (n == 3) {
      if (!sse_op(in, 0, &d)) return false;
      if (!sse_op(in, 1, &s)) return false;
      IROperand imm;
      if (!sse_op(in, 2, &imm)) return false;
      if (imm.kind != IRKind::Imm) return fail("shuffle imm8 expected");
      if (d.kind != IRKind::Xmm || s.kind != IRKind::Xmm)
        return fail("shuffle operands must be XMM");
      IRCommand c = IRCommand::none(IROp::SseShuf);
      c.dst = d; c.src = s; c.aux = imm; c.size = 16;
      c.sub = static_cast<uint8_t>(sub);
      prog_.add(c);
      return true;
    }
    if (n == 2) {
      if (!sse_op(in, 0, &d)) return false;
      if (!sse_op(in, 1, &s)) return false;
      if (d.kind != IRKind::Xmm || s.kind != IRKind::Xmm)
        return fail("unpack operands must be XMM");
      IRCommand c = IRCommand::none(IROp::SseShuf);
      c.dst = d; c.src = s; c.aux = IROperand::I(0, 1); c.size = 16;
      c.sub = static_cast<uint8_t>(sub);
      prog_.add(c);
      return true;
    }
    return fail("shuffle: 2/3 operands expected");
  }

  bool ins_sse_shift(cs_insn& in, SseShift sub) {
    const cs_x86& x = in.detail->x86;
    IROperand d, s;
    if (!sse_op(in, 0, &d)) return false;
    if (d.kind != IRKind::Xmm) return fail("psll target must be XMM");
    if (x.op_count == 2) {
      const int64_t imm = x.operands[1].imm;
      IRCommand c = IRCommand::none(IROp::SseShift);
      c.dst = d; c.size = 16; c.sub = static_cast<uint8_t>(sub);
      c.aux = IROperand::I(imm);
      prog_.add(c);
      return true;
    }
    if (x.op_count == 3) {
      if (!sse_op(in, 1, &s)) return false;
      if (s.kind != IRKind::Xmm) return fail("psll src must be XMM");
      const int64_t imm = x.operands[2].imm;
      IRCommand m = IRCommand::none(IROp::SseMov);
      m.dst = d; m.src = s; m.size = 16; m.sub = kSseMovFull;
      prog_.add(m);
      IRCommand c = IRCommand::none(IROp::SseShift);
      c.dst = d; c.size = 16; c.sub = static_cast<uint8_t>(sub);
      c.aux = IROperand::I(imm);
      prog_.add(c);
      return true;
    }
    return fail("psll: 2/3 operands expected");
  }

  bool ins_lea(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("lea: 2 operands expected");
    int dst = 0;
    uint8_t dsz = 0;
    if (!op_reg(in, 0, &dst, &dsz)) return false;
    IRMem m;
    uint8_t msz = 0;
    if (!op_mem(in, 1, &m, &msz)) return false;
    if (dsz != 8 && dsz != 4) return fail("lea target must be 64/32-bit");
    prog_.add(IRCommand::lea(IROperand::R(dst, 8), m));

    if (dsz == 4) {
      prog_.add(IRCommand::mov(IROperand::R(dst, 4), IROperand::R(dst, 4)));
    }
    return true;
  }

  bool ins_xchg(cs_insn& in) {
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    if (d.kind == IRKind::Mem || s.kind == IRKind::Mem)
      return fail("xchg: memory operand stays an island");
    if (d.size != s.size) return fail("xchg: operand sizes differ");
    if (d.reg == s.reg) return true;
    const uint8_t size = d.size;
    prog_.add(IRCommand::mov(IROperand::R(REG_T2, size), d));
    prog_.add(IRCommand::mov(d, s));
    prog_.add(IRCommand::mov(s, IROperand::R(REG_T2, size)));
    return true;
  }

  bool ins_extend(cs_insn& in, bool sign) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("movzx/movsx: 2 operands expected");

    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    if (d.kind != IRKind::Reg) return fail("movzx/movsx target must be a register");

    const uint8_t ssz = s.size;

    if (s.kind == IRKind::Mem) {
      IRCommand ld = IRCommand::mov(IROperand::R(REG_T2, ssz), s);
      prog_.add(ld);
      s = IROperand::R(REG_T2, ssz);
    }
    if (s.kind != IRKind::Reg) return fail("movzx/movsx kaynagi desteklenmiyor");

    if (!sign && ssz == 4) {

      IRCommand c = IRCommand::mov(IROperand::R(d.reg, 4), IROperand::R(s.reg, 4));
      prog_.add(c);
      return true;
    }

    ExtOp k;
    if (sign) {
      k = ssz == 1 ? ExtOp::Sx8 : ssz == 2 ? ExtOp::Sx16 : ExtOp::Sxd;
      if (ssz != 1 && ssz != 2 && ssz != 4) return fail("movsx invalid source size");
    } else {
      k = ssz == 1 ? ExtOp::Zx8 : ssz == 2 ? ExtOp::Zx16 : ExtOp::Zx8;
      if (ssz != 1 && ssz != 2) return fail("movzx invalid source size");
    }

    IRCommand c = IRCommand::none(IROp::Extend);
    c.sub = static_cast<uint8_t>(k);
    c.dst = IROperand::R(d.reg, 8);
    c.src = IROperand::R(s.reg, ssz);
    prog_.add(c);
    return true;
  }

  bool ins_alu(cs_insn& in, AluOp k) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("alu: 2 operands expected");

    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;

    uint8_t size = d.size;
    if (d.kind != IRKind::Reg && d.kind != IRKind::Mem) return fail("alu target must be reg/mem");
    if (s.kind == IRKind::Imm) {
      if (size == 0) return fail("alu: unknown operand size");
      s.imm = sext_imm(s.imm, s.size, size);
      s.size = size;
    } else if (s.size != 0 && size != 0 && s.size != size) {

      if (s.kind != IRKind::Mem || s.size != size) return fail("alu: operand sizes do not match");
    }
    if (!check_size(size)) return false;

    d.size = size;
    IRCommand c = IRCommand::alu(k, d, s);
    c.size = size;
    prog_.add(c);
    return true;
  }

  bool ins_test(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("test: 2 operands expected");
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    const uint8_t size = d.size;
    if (s.kind == IRKind::Imm) s.imm = sext_imm(s.imm, s.size, size);
    if (!check_size(size)) return false;
    IRCommand c = IRCommand::none(IROp::Test);
    c.dst = d;
    c.src = s;
    c.size = size;
    prog_.add(c);
    return true;
  }

  bool ins_unary(cs_insn& in, UnaryOp k) {
    IROperand d;
    if (!to_operand(in, 0, &d)) return false;
    if (!check_size(d.size)) return false;
    IRCommand c = IRCommand::unary(k, 0);
    c.dst = d;
    c.size = d.size;
    prog_.add(c);
    return true;
  }

  bool ins_shift(cs_insn& in, ShiftOp k) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("shift: 2 operands expected");
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;

    if (s.kind == IRKind::Reg) {
      if (s.reg != REG_RCX || s.size != 1) return fail("shift count must be CL");
    } else if (s.kind != IRKind::Imm) {
      return fail("shift count must be immediate or CL");
    }
    if (!check_size(d.size)) return false;
    IRCommand c = IRCommand::none(IROp::Shift);
    c.sub = static_cast<uint8_t>(k);
    c.dst = d;
    c.src = s;
    c.size = d.size;
    prog_.add(c);
    return true;
  }

  static IRCommand shift_cmd(ShiftOp k, int reg, uint8_t size, IROperand cnt) {
    IRCommand c = IRCommand::none(IROp::Shift);
    c.sub = static_cast<uint8_t>(k);
    c.dst = IROperand::R(reg, size);
    c.src = cnt;
    c.size = size;
    return c;
  }

  void emit_bt(int reg, IROperand idx) {
    IRCommand bt = IRCommand::none(IROp::BitTest);
    bt.sub = static_cast<uint8_t>(BitTestKind::Bt);
    bt.dst = IROperand::R(reg, 8);
    bt.src = idx;
    bt.size = 8;
    prog_.add(bt);
  }

  void double_shift_imm(bool left, uint8_t size, int r_dst, int r_src,
                        int64_t cnt) {
    const int64_t bits = (size == 8) ? 64 : 32;
    const int64_t key = bits - cnt;

    prog_.add(IRCommand::mov(IROperand::R(REG_T3, size), IROperand::R(r_dst, size)));
    prog_.add(IRCommand::mov(IROperand::R(REG_T1, size), IROperand::R(REG_T3, size)));
    prog_.add(shift_cmd(left ? ShiftOp::Shl : ShiftOp::Shr, REG_T1, size,
                        IROperand::I(cnt, 1)));
    prog_.add(IRCommand::mov(IROperand::R(REG_T2, size), IROperand::R(r_src, size)));
    prog_.add(shift_cmd(left ? ShiftOp::Shr : ShiftOp::Shl, REG_T2, size,
                        IROperand::I(key, 1)));
    prog_.add(IRCommand::alu(AluOp::Or, IROperand::R(REG_T1, size),
                             IROperand::R(REG_T2, size)));
    prog_.add(IRCommand::mov(IROperand::R(r_dst, size), IROperand::R(REG_T1, size)));
    emit_bt(REG_T3, IROperand::I(left ? key : cnt - 1, 1));
  }

  void double_shift_reg(bool left, uint8_t size, int r_dst, int r_src) {
    const int64_t bits = (size == 8) ? 64 : 32;
    const uint8_t bs = size;

    if (left) {
      prog_.add(IRCommand::mov(IROperand::R(REG_T2, 1), IROperand::I(bits, 1)));
      prog_.add(IRCommand::alu(AluOp::Sub, IROperand::R(REG_T2, 1),
                               IROperand::R(REG_T3, 1)));
    } else {
      prog_.add(IRCommand::mov(IROperand::R(REG_T2, 1), IROperand::R(REG_T3, 1)));
      prog_.add(IRCommand::alu(AluOp::Sub, IROperand::R(REG_T2, 1),
                               IROperand::I(1, 1)));
    }
    prog_.add(IRCommand::mov(IROperand::R(REG_T1, bs), IROperand::R(r_dst, bs)));
    prog_.add(shift_cmd(ShiftOp::Shr, REG_T1, bs, IROperand::R(REG_T2, 1)));

    IRCommand save = IRCommand::none(IROp::Push);
    save.src = IROperand::R(REG_T1, 8);
    prog_.add(save);

    prog_.add(IRCommand::mov(IROperand::R(REG_T2, 1), IROperand::I(bits, 1)));
    prog_.add(IRCommand::alu(AluOp::Sub, IROperand::R(REG_T2, 1),
                             IROperand::R(REG_T3, 1)));
    prog_.add(IRCommand::mov(IROperand::R(REG_T1, bs), IROperand::R(r_dst, bs)));
    prog_.add(shift_cmd(left ? ShiftOp::Shl : ShiftOp::Shr, REG_T1, bs,
                        IROperand::R(REG_T3, 1)));
    prog_.add(IRCommand::mov(IROperand::R(REG_T3, bs), IROperand::R(r_src, bs)));
    prog_.add(shift_cmd(left ? ShiftOp::Shr : ShiftOp::Shl, REG_T3, bs,
                        IROperand::R(REG_T2, 1)));
    prog_.add(IRCommand::alu(AluOp::Or, IROperand::R(REG_T1, size),
                             IROperand::R(REG_T3, size)));
    prog_.add(IRCommand::mov(IROperand::R(r_dst, bs), IROperand::R(REG_T1, bs)));

    IRCommand restore = IRCommand::none(IROp::Pop);
    restore.dst = IROperand::R(REG_T2, 8);
    prog_.add(restore);
    emit_bt(REG_T2, IROperand::I(0, 1));

    IRCommand drop = IRCommand::none(IROp::Pop);
    drop.dst = IROperand::R(REG_T1, 8);
    prog_.add(drop);
  }

  bool ins_double_shift(cs_insn& in, bool left) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 3) return fail("shld/shrd: 3 operands expected");

    IROperand d, s, n;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    if (!to_operand(in, 2, &n)) return false;

    if (d.kind != IRKind::Reg || s.kind != IRKind::Reg)
      return fail("shld/shrd operands must be registers");
    if (d.size != s.size) return fail("shld/shrd operand sizes differ");
    if (d.size != 4 && d.size != 8)
      return fail("shld/shrd supports 32/64-bit operands");

    const uint8_t size = d.size;
    const int64_t bits = (size == 8) ? 64 : 32;
    const int r_dst = d.reg;
    const int r_src = s.reg;

    if (n.kind == IRKind::Imm) {
      const int64_t cnt = n.imm & (bits - 1);
      if (cnt == 0) {
        if (size == 4) {
          prog_.add(IRCommand::mov(IROperand::R(r_dst, 4), IROperand::R(r_dst, 4)));
        }
        return true;
      }
      double_shift_imm(left, size, r_dst, r_src, cnt);
      return true;
    }

    if (n.kind != IRKind::Reg || n.size != 1 || n.reg != REG_RCX)
      return fail("shld/shrd count must be CL or imm8");

    const int l_zero = prog_.new_label();
    const int l_done = prog_.new_label();

    prog_.add(IRCommand::none(IROp::Pushf));
    prog_.add(IRCommand::mov(IROperand::R(REG_T3, 1), IROperand::R(REG_RCX, 1)));
    prog_.add(IRCommand::alu(AluOp::And, IROperand::R(REG_T3, 1),
                             IROperand::I(bits - 1, 1)));

    IRCommand t = IRCommand::none(IROp::Test);
    t.dst = IROperand::R(REG_T3, 1);
    t.src = IROperand::R(REG_T3, 1);
    t.size = 1;
    prog_.add(t);

    IRCommand jz = IRCommand::br(IROp::Jcc, l_zero);
    jz.sub = 0x4;
    prog_.add(jz);

    double_shift_reg(left, size, r_dst, r_src);

    prog_.add(IRCommand::br(IROp::Jmp, l_done));
    prog_.bind(l_zero);
    prog_.add(IRCommand::none(IROp::Popf));
    if (size == 4) {
      prog_.add(IRCommand::mov(IROperand::R(r_dst, 4), IROperand::R(r_dst, 4)));
    }
    prog_.bind(l_done);
    return true;
  }

  bool ins_imul(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    IRCommand c = IRCommand::none(IROp::Imul);
    c.size = op_size(in);

    if (c.size == 1 && x.op_count != 1) return fail("imul: 8-bit only supports one operand");
    if (x.op_count == 1) {
      c.sub = static_cast<uint8_t>(ImulKind::One);
      if (!to_operand(in, 0, &c.src)) return false;
    } else if (x.op_count == 2) {
      c.sub = static_cast<uint8_t>(ImulKind::Two);
      if (!to_operand(in, 0, &c.dst)) return false;
      if (!to_operand(in, 1, &c.src)) return false;
    } else if (x.op_count == 3) {
      c.sub = static_cast<uint8_t>(ImulKind::Three);
      if (!to_operand(in, 0, &c.dst)) return false;
      if (!to_operand(in, 1, &c.src)) return false;
      if (!to_operand(in, 2, &c.aux)) return false;
    } else {
      return fail("imul: invalid operand count");
    }
    prog_.add(c);
    return true;
  }

  bool ins_muldiv(cs_insn& in, MulKind k) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 1) return fail("mul/div: 1 operand expected");
    const bool is_div = (in.id == X86_INS_DIV || in.id == X86_INS_IDIV);
    IRCommand c = IRCommand::none(is_div ? IROp::Div : IROp::Mul);
    c.sub = static_cast<uint8_t>(k);
    c.size = op_size(in);
    if (!check_size(c.size)) return false;
    if (!to_operand(in, 0, &c.src)) return false;
    prog_.add(c);
    return true;
  }

  bool ins_bitcount(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("tzcnt/lzcnt/popcnt: 2 operands expected");
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    if (d.kind != IRKind::Reg) return fail("tzcnt/lzcnt/popcnt target must be a register");
    if (d.size == 1) return fail("tzcnt/lzcnt/popcnt: no 8-bit form");
    if (s.kind == IRKind::Mem) {
      prog_.add(IRCommand::mov(IROperand::R(REG_T2, s.size), s));
      s = IROperand::R(REG_T2, s.size);
    }
    IRCommand c = IRCommand::none(IROp::BitCount);
    c.sub = (in.id == X86_INS_TZCNT) ? static_cast<uint8_t>(BitCountKind::Tz)
          : (in.id == X86_INS_LZCNT) ? static_cast<uint8_t>(BitCountKind::Lz)
                                     : static_cast<uint8_t>(BitCountKind::Pop);
    c.dst = d;
    c.src = s;
    c.size = d.size;
    prog_.add(c);
    return true;
  }

  bool ins_signext(cs_insn& in, SignExtKind k) {
    IRCommand c = IRCommand::none(IROp::SignExtend);
    c.sub = static_cast<uint8_t>(k);
    (void)in;
    prog_.add(c);
    return true;
  }

  bool ins_cdqe(cs_insn& in) {
    (void)in;
    IRCommand c = IRCommand::none(IROp::Extend);
    c.sub = static_cast<uint8_t>(ExtOp::Sxd);
    c.dst = IROperand::R(REG_RAX, 8);
    c.src = IROperand::R(REG_RAX, 4);
    prog_.add(c);
    return true;
  }

  bool ins_cwde(cs_insn& in) {
    (void)in;
    IRCommand c = IRCommand::none(IROp::Extend);
    c.sub = static_cast<uint8_t>(ExtOp::Sx16);
    c.dst = IROperand::R(REG_RAX, 8);
    c.src = IROperand::R(REG_RAX, 2);
    prog_.add(c);
    prog_.add(IRCommand::mov(IROperand::R(REG_RAX, 4), IROperand::R(REG_RAX, 4)));
    return true;
  }

  bool ins_bswap(cs_insn& in) {
    IROperand d;
    if (!to_operand(in, 0, &d)) return false;
    if (d.kind != IRKind::Reg || d.size != 8) return fail("bswap only supports 64-bit registers");
    prog_.add(IRCommand::none(IROp::Bswap));
    prog_.cmds.back().dst = d;
    return true;
  }

  bool ins_bitscan(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("bsf/bsr: 2 operands expected");
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;
    if (d.kind != IRKind::Reg) return fail("bsf/bsr target must be a register");
    if (s.kind == IRKind::Mem) {
      prog_.add(IRCommand::mov(IROperand::R(REG_T2, s.size), s));
      s = IROperand::R(REG_T2, s.size);
    }
    IRCommand c = IRCommand::none(IROp::BitScan);
    c.sub = (in.id == X86_INS_BSF) ? 0 : 1;
    c.dst = d;
    c.src = s;
    c.size = d.size;
    prog_.add(c);
    return true;
  }

  bool ins_bittest(cs_insn& in) {
    const cs_x86& x = in.detail->x86;
    if (x.op_count != 2) return fail("bt/bts/btr/btc: 2 operands expected");
    IROperand d, s;
    if (!to_operand(in, 0, &d)) return false;
    if (!to_operand(in, 1, &s)) return false;

    BitTestKind k = BitTestKind::Bt;
    if (in.id == X86_INS_BTS) k = BitTestKind::Bts;
    else if (in.id == X86_INS_BTR) k = BitTestKind::Btr;
    else if (in.id == X86_INS_BTC) k = BitTestKind::Btc;

    if (d.size != 8 && d.kind == IRKind::Reg) return fail("bt*: only 64-bit target");
    IRCommand c = IRCommand::none(IROp::BitTest);
    c.sub = static_cast<uint8_t>(k);
    c.dst = d;
    c.src = s;
    c.size = d.size;
    prog_.add(c);
    return true;
  }

  bool ins_push(cs_insn& in) {
    IROperand s;
    if (!to_operand(in, 0, &s)) return false;
    s.size = 8;
    IRCommand c = IRCommand::none(IROp::Push);
    c.src = s;
    prog_.add(c);
    return true;
  }

  bool ins_pop(cs_insn& in) {
    IROperand d;
    if (!to_operand(in, 0, &d)) return false;
    d.size = 8;
    IRCommand c = IRCommand::none(IROp::Pop);
    c.dst = d;
    prog_.add(c);
    return true;
  }

  bool ins_leave(cs_insn& in) {
    (void)in;
    prog_.add(IRCommand::mov(IROperand::R(REG_RSP), IROperand::R(REG_RBP)));
    IRCommand c = IRCommand::none(IROp::Pop);
    c.dst = IROperand::R(REG_RBP);
    prog_.add(c);
    return true;
  }

  bool branch_label(const cs_insn& in, int* label) {
    uint64_t t = 0;
    if (!is_branch_target(in, &t)) return fail("cannot read branch target");
    auto it = label_.find(t);
    if (it == label_.end()) return fail("branch target outside function range");
    *label = it->second;
    return true;
  }

  bool ins_jmp(cs_insn& in) {
    const cs_x86_op& o = in.detail->x86.operands[0];
    if (o.type == X86_OP_IMM) {
      int l = -1;
      if (!branch_label(in, &l)) return false;
      IRCommand c = IRCommand::br(IROp::Jmp, l);
      c.addr = in.address;
      prog_.add(c);
      return true;
    }

    IROperand s;
    if (!to_operand(in, 0, &s)) return false;
    if (s.kind == IRKind::Mem) {
      prog_.add(IRCommand::mov(IROperand::R(REG_T2, 8), s));
      s = IROperand::R(REG_T2, 8);
    }
    if (s.kind != IRKind::Reg) return fail("indirect jmp operand not supported");
    IRCommand c = IRCommand::none(IROp::JmpIndirect);
    c.dst = s;
    prog_.add(c);
    return true;
  }

  bool ins_call(cs_insn& in) {
    const cs_x86_op& o = in.detail->x86.operands[0];
    if (o.type != X86_OP_IMM) {
      return fail("indirect call: native call gate required (stage 3)");
    }
    int l = -1;
    if (!branch_label(in, &l)) return false;
    IRCommand c = IRCommand::br(IROp::Call, l);
    c.addr = in.address;
    prog_.add(c);
    return true;
  }

  bool ins_jcc(cs_insn& in) {
    uint8_t cc = 0;
    if (!jcc_cc(&in, &cc)) return fail("desteklenmeyen kosullu dal");
    int l = -1;
    if (!branch_label(in, &l)) return false;
    IRCommand c = IRCommand::br(IROp::Jcc, l);
    c.sub = cc;
    prog_.add(c);
    return true;
  }

  const uint8_t* code_;
  size_t size_;
  LiftOptions opt_;
  csh handle_ = 0;
  cs_insn* insns_ = nullptr;
  size_t count_ = 0;

  std::unordered_map<uint64_t, size_t> index_;
  std::vector<char> reach_;
  std::vector<uint64_t> work_;
  std::map<uint64_t, int> label_;
  bool all_reachable_ = false;

  IRProgram prog_;
  std::string last_reason_;
  size_t fixups_ = 0;
  size_t image_relocs_ = 0;
  uint16_t written_ = 0;
  int hb_parent_ = -1;
  bool hb_write_ = false;
  bool hb_loaded_ = false;

  uint64_t img_base() const {
    return opt_.image_base ? opt_.image_base : opt_.base_address;
  }
};

}

LiftResult lift_x86_64(const uint8_t* code, size_t size, const LiftOptions& opt) {
  Lifter l(code, size, opt);
  return l.run();
}

}
