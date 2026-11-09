#include "hyda/mutate/obf.hpp"

#include <vector>

namespace hyda {
namespace {

uint64_t obf_mix(uint64_t& x) {
  x += 0x9E3779B97F4A7C15ull;
  uint64_t z = x;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

void emit_opaque(std::vector<IRCommand>& out, uint64_t& s, int dead_label,
                 size_t site_index) {
  const uint64_t r = obf_mix(s);
  const int src = static_cast<int>(r % 3u);
  const int gr = (src == 0) ? REG_RAX : (src == 1 ? REG_RBX : REG_RDX);
  out.push_back(IRCommand::mov(IROperand::R(REG_T0), IROperand::R(gr)));
  switch (static_cast<unsigned>(site_index + (r >> 8)) % 4u) {
    case 0:

      out.push_back(IRCommand::alu(AluOp::Xor, IROperand::R(REG_T0),
                                   IROperand::R(gr)));
      out.push_back(IRCommand::alu(AluOp::Cmp, IROperand::R(REG_T0),
                                   IROperand::I(1)));
      {
        IRCommand j = IRCommand::br(IROp::Jcc, dead_label);
        j.sub = 4;
        out.push_back(j);
      }
      break;
    case 1:

      out.push_back(IRCommand::alu(AluOp::Sub, IROperand::R(REG_T0),
                                   IROperand::R(gr)));
      out.push_back(IRCommand::alu(AluOp::Cmp, IROperand::R(REG_T0),
                                   IROperand::I(0)));
      {
        IRCommand j = IRCommand::br(IROp::Jcc, dead_label);
        j.sub = 5;
        out.push_back(j);
      }
      break;
    case 2:

      out.push_back(IRCommand::alu(AluOp::And, IROperand::R(REG_T0),
                                   IROperand::I(0)));
      out.push_back(IRCommand::alu(AluOp::Cmp, IROperand::R(REG_T0),
                                   IROperand::I(1)));
      {
        IRCommand j = IRCommand::br(IROp::Jcc, dead_label);
        j.sub = 4;
        out.push_back(j);
      }
      break;
    default:

      out.push_back(IRCommand::alu(AluOp::Xor, IROperand::R(REG_T0),
                                   IROperand::R(gr)));
      out.push_back(IRCommand::alu(AluOp::Cmp, IROperand::R(REG_T0),
                                   IROperand::I(0)));
      {
        IRCommand j = IRCommand::br(IROp::Jcc, dead_label);
        j.sub = 5;
        out.push_back(j);
      }
      break;
  }
}

IRCommand dead_cmd(uint64_t& s) {
  const uint64_t r = obf_mix(s);
  const int t = REG_T0 + static_cast<int>((r >> 3) % 4u);
  const int64_t imm = static_cast<int64_t>(r >> 16);
  switch ((r >> 8) % 5u) {
    case 0:
      return IRCommand::mov(IROperand::R(t), IROperand::I(imm));
    case 1:
      return IRCommand::alu(AluOp::Xor, IROperand::R(t), IROperand::I(imm));
    case 2:
      return IRCommand::alu(AluOp::Add, IROperand::R(t), IROperand::I(imm));
    case 3: {
      IRCommand c = IRCommand::none(IROp::Noise);
      c.dst = IROperand::R(REG_NOISE);
      c.src = IROperand::I(imm);
      return c;
    }
    default: {
      IRCommand c = IRCommand::none(IROp::Junk);
      c.src = IROperand::I(imm);
      return c;
    }
  }
}

IRCommand dead_halt() { return IRCommand::none(IROp::Halt); }

}

ObfStats ir_bogus_cfg(IRProgram& p, uint64_t seed) {
  ObfStats st;
  const size_t n = p.cmds.size();
  st.cmds_before = n;
  if (n < 8) {
    st.cmds_after = n;
    return st;
  }

  std::vector<size_t> sites;
  for (size_t i = 0; i < n; ++i) {
    if (ir_flag_effect(p.cmds[i]).wr_min == kIrAllFlags) sites.push_back(i);
  }
  if (sites.empty()) {
    st.cmds_after = n;
    return st;
  }

  uint64_t s = seed ? seed : 0x9E3779B97F4A7C15ull;

  std::vector<char> ins(n, 0);
  for (size_t i : sites) {
    if ((obf_mix(s) % 100u) < 45u) ins[i] = 1;
  }

  std::vector<int> dead_label(n, -1);
  std::vector<int> chain_len(n, 0);
  for (size_t i = 0; i < n; ++i) {
    if (!ins[i]) continue;
    dead_label[i] = p.new_label();
    chain_len[i] = 3 + static_cast<int>(obf_mix(s) % 9u);
  }

  std::vector<IRCommand> out;
  out.reserve(n + sites.size() * 6 + 64);
  std::vector<size_t> map(n, 0);
  size_t site_idx = 0;
  for (size_t i = 0; i < n; ++i) {
    map[i] = out.size();
    if (ins[i]) {
      emit_opaque(out, s, dead_label[i], site_idx++);
      ++st.opaque;
    }
    out.push_back(p.cmds[i]);
  }

  for (size_t l = 0; l < p.label_mark.size(); ++l) {
    if (p.label_mark[l] == IRProgram::kUnbound) continue;
    p.label_mark[l] = map[p.label_mark[l]];
  }

  for (size_t i = 0; i < n; ++i) {
    if (!ins[i]) continue;
    p.label_mark[static_cast<size_t>(dead_label[i])] = out.size();
    for (int k = 0; k < chain_len[i]; ++k) {
      out.push_back(dead_cmd(s));
      ++st.dead_cmds;
    }
    out.push_back(dead_halt());
    ++st.dead_blocks;
  }

  p.entry_cmd = map[p.entry_cmd];
  p.cmds.swap(out);
  st.cmds_after = p.cmds.size();
  return st;
}

}
