#include "hyda/mutate/fuse.hpp"

#include "hyda/ir/ir_rw.hpp"

#include <vector>

namespace hyda {
namespace {

void use_def(const IRCommand& c, uint32_t* use, uint32_t* def) {
  const IrRW rw = ir_rw_of(c, false);
  *use = rw.rd;
  *def = rw.wr;
  switch (c.op) {
    case IROp::Call:
    case IROp::Native:
      *use |= ir_all_regs;
      *def |= ir_all_regs;
      break;
    case IROp::Ret:
    case IROp::RetImm:
      *use |= ir_reg_bit(REG_RAX) | ir_reg_bit(REG_RDX);
      break;
    case IROp::JmpIndirect:

      break;
    case IROp::Halt:
      break;
    default:
      break;
  }
}

struct Rewrite {
  IRProgram* p = nullptr;
  const std::vector<char>* boundary = nullptr;
  const std::vector<uint32_t>* live_out = nullptr;
  std::vector<char> consumed;
  std::vector<char> is_fused;
  std::vector<IRCommand> fused;
  size_t count = 0;
  size_t mem_source = 0;

  bool fuse_mov_consumer(size_t i);
  bool fuse_compare_branch(size_t i);
  bool fuse_alu_branch(size_t i);

  void apply();
};

bool Rewrite::fuse_mov_consumer(size_t i) {
  const IRCommand& c1 = p->cmds[i];
  const IRCommand& c2 = p->cmds[i + 1];
  if (c1.op != IROp::Mov || c1.dst.kind != IRKind::Reg) return false;
  if (c1.size < 4 || c1.size != c2.size) return false;
  if ((c1.flags & IRF_NO_MERGE) || (c2.flags & IRF_NO_MERGE)) return false;
  const int t = c1.dst.reg;
  if (c1.src.kind == IRKind::Reg && c1.src.reg == t) return false;
  if ((*live_out)[i + 1] & ir_reg_bit(t)) return false;

  IRCommand f = c2;
  bool ok = false;
  switch (c2.op) {
    case IROp::Mov:
      if (c2.dst.kind == IRKind::Reg && c2.dst.reg != t &&
          c2.src.kind == IRKind::Reg && c2.src.reg == t) {
        f.src = c1.src;
        ok = true;
      }
      break;
    case IROp::Alu:
    case IROp::Test:
      if (c2.dst.kind == IRKind::Reg && c2.dst.reg != t &&
          c2.src.kind == IRKind::Reg && c2.src.reg == t) {
        f.src = c1.src;
        ok = true;
      }
      break;
    case IROp::Imul:
      if (static_cast<ImulKind>(c2.sub) == ImulKind::Two &&
          c2.dst.kind == IRKind::Reg && c2.dst.reg != t &&
          c2.src.kind == IRKind::Reg && c2.src.reg == t) {
        f.src = c1.src;
        ok = true;
      }
      break;
    default:
      break;
  }
  if (!ok) return false;

  if (c1.src.kind == IRKind::Mem) ++mem_source;
  f.flags |= c1.flags & (IRF_NO_CRYPT | IRF_IMAGE_RVA);
  f.addr = c1.addr;
  fused[i] = f;
  is_fused[i] = 1;
  consumed[i + 1] = 1;
  ++count;
  return true;
}

bool Rewrite::fuse_compare_branch(size_t i) {
  const IRCommand& c1 = p->cmds[i];
  const IRCommand& c2 = p->cmds[i + 1];
  if (c2.op != IROp::Jcc || c2.sub > 15) return false;
  if ((c1.flags & IRF_NO_MERGE) || (c2.flags & IRF_NO_MERGE)) return false;

  if (c1.dst.kind != IRKind::Reg) return false;

  int kind;
  if (c1.op == IROp::Alu && c1.sub == static_cast<uint8_t>(AluOp::Cmp)) {
    kind = 0;
  } else if (c1.op == IROp::Test) {
    kind = 1;
  } else {
    return false;
  }
  if (c1.size != c2.size && c2.size != 8) return false;

  IRCommand f;
  f.op = IROp::CmpJcc;
  f.dst = c1.dst;
  f.src = c1.src;
  f.size = c1.size;
  f.sub = c2.sub;
  f.aux = IROperand::I(kind, 1);
  f.label = c2.label;
  f.flags = c2.flags | (c1.flags & IRF_NO_CRYPT);
  f.addr = c1.addr;
  fused[i] = f;
  is_fused[i] = 1;
  consumed[i + 1] = 1;
  ++count;
  return true;
}

bool Rewrite::fuse_alu_branch(size_t i) {
  const IRCommand& c1 = p->cmds[i];
  const IRCommand& c2 = p->cmds[i + 1];
  if (c2.op != IROp::Jcc || c2.sub > 15) return false;
  if (c1.op != IROp::Alu) return false;
  const uint8_t aop = c1.sub;
  if (!(aop == 0 || aop == 2 || aop == 4 || aop == 5 || aop == 6)) return false;
  if (c1.dst.kind != IRKind::Reg) return false;
  if ((c1.flags & IRF_NO_MERGE) || (c2.flags & IRF_NO_MERGE)) return false;

  IRCommand f;
  f.op = IROp::AluJcc;
  f.dst = c1.dst;
  f.src = c1.src;
  f.size = c1.size;
  f.sub = c1.sub;
  f.aux = IROperand::I(c2.sub, 1);
  f.label = c2.label;
  f.flags = c2.flags | (c1.flags & (IRF_NO_CRYPT | IRF_IMAGE_RVA));
  f.addr = c1.addr;
  fused[i] = f;
  is_fused[i] = 1;
  consumed[i + 1] = 1;
  ++count;
  return true;
}

void Rewrite::apply() {
  const size_t n = p->cmds.size();
  std::vector<size_t> old_to_new(n, 0);
  std::vector<IRCommand> out;
  out.reserve(n - count);
  for (size_t i = 0; i < n; ++i) {
    if (consumed[i]) {
      old_to_new[i] = out.size();
      continue;
    }
    old_to_new[i] = out.size();
    out.push_back(is_fused[i] ? fused[i] : p->cmds[i]);
  }
  for (size_t l = 0; l < p->label_mark.size(); ++l) {
    if (p->label_mark[l] == IRProgram::kUnbound) continue;
    p->label_mark[l] = old_to_new[p->label_mark[l]];
  }
  p->entry_cmd = old_to_new[p->entry_cmd];
  p->cmds.swap(out);
}

bool fuse_once(IRProgram& p, FuseStats* st) {
  const size_t n = p.cmds.size();
  if (n < 2) return false;

  std::vector<char> boundary(n, 0);
  for (size_t l = 0; l < p.label_mark.size(); ++l) {
    const size_t m = p.label_mark[l];
    if (m != IRProgram::kUnbound && m < n) boundary[m] = 1;
  }
  if (p.entry_cmd < n) boundary[p.entry_cmd] = 1;

  std::vector<uint32_t> use(n, 0), def(n, 0), live_in(n, 0), live_out(n, 0);
  for (size_t i = 0; i < n; ++i) use_def(p.cmds[i], &use[i], &def[i]);

  auto target_of = [&](const IRCommand& c) -> size_t {
    if (c.label < 0) return IRProgram::kUnbound;
    return p.label_mark[static_cast<size_t>(c.label)];
  };
  bool changed = true;
  for (size_t pass = 0; changed && pass <= n + 1; ++pass) {
    changed = false;
    for (size_t idx = n; idx-- > 0;) {
      const IRCommand& c = p.cmds[idx];
      uint32_t lo = 0;
      switch (c.op) {
        case IROp::Jmp:
        case IROp::Jcc:
        case IROp::Call: {
          if (c.op != IROp::Jmp) lo |= (idx + 1 < n) ? live_in[idx + 1] : 0u;
          const size_t t = target_of(c);
          if (t == IRProgram::kUnbound) lo = ir_all_regs;
          else lo |= live_in[t];
          break;
        }
        case IROp::CmpJcc:
          lo |= (idx + 1 < n) ? live_in[idx + 1] : 0u;
          if (c.label < 0) lo = ir_all_regs;
          else if (target_of(c) == IRProgram::kUnbound) lo = ir_all_regs;
          else lo |= live_in[target_of(c)];
          break;
        case IROp::Ret:
        case IROp::RetImm:
        case IROp::JmpIndirect:
        case IROp::Halt:
        case IROp::Native:
          break;
        default:
          lo = (idx + 1 < n) ? live_in[idx + 1] : 0u;
          break;
      }
      const uint32_t in = use[idx] | (lo & ~def[idx]);
      if (lo != live_out[idx] || in != live_in[idx]) {
        live_out[idx] = lo;
        live_in[idx] = in;
        changed = true;
      }
    }
  }

  Rewrite rw;
  rw.p = &p;
  rw.boundary = &boundary;
  rw.live_out = &live_out;
  rw.consumed.assign(n, 0);
  rw.is_fused.assign(n, 0);
  rw.fused.assign(n, IRCommand{});

  for (size_t i = 0; i + 1 < n; ++i) {
    if (rw.consumed[i]) continue;
    if ((*rw.boundary)[i + 1]) continue;
    if (rw.fuse_mov_consumer(i)) continue;
    if (rw.fuse_compare_branch(i)) continue;
    rw.fuse_alu_branch(i);
  }
  st->mem_source += rw.mem_source;
  if (rw.count == 0) return false;
  st->fused += rw.count;
  rw.apply();
  return true;
}

}

FuseStats ir_fuse(IRProgram& p) {
  FuseStats st;
  st.cmds_before = p.cmds.size();

  for (int iter = 0; iter < 4; ++iter) {
    if (!fuse_once(p, &st)) break;
  }
  st.cmds_after = p.cmds.size();
  return st;
}

}
