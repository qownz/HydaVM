#include "hyda/mutate/mutate.hpp"
#include "hyda/ir/ir_rw.hpp"

#include <vector>

namespace hyda {
namespace {

constexpr uint32_t kInvertible = ((1u << 16) - 1u) & ~(1u << REG_RSP);

constexpr uint32_t bit(int r) { return 1u << static_cast<unsigned>(r); }

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed) {}
  uint64_t next() { return splitmix64(s); }
  uint32_t below(uint32_t n) { return n ? static_cast<uint32_t>(next() % n) : 0u; }
  bool chance(unsigned pct) { return pct != 0 && below(100u) < pct; }
};

int pick_reg(uint32_t mask, Rng& rng) {
  uint32_t n = 0;
  for (int r = 0; r < NVREG; ++r) {
    if (mask & bit(r)) ++n;
  }
  if (n == 0) return -1;
  uint32_t k = rng.below(n);
  for (int r = 0; r < NVREG; ++r) {
    if (!(mask & bit(r))) continue;
    if (k == 0) return r;
    --k;
  }
  return -1;
}

}

MutateStats ir_mutate(IRProgram& p, const MutateOptions& opt) {
  MutateStats st;
  st.cmds_before = p.cmds.size();

  const uint64_t seed = opt.seed ? opt.seed : hyda::vm_seed();
  uint64_t mix = seed;
  Rng rng(splitmix64(mix) ^ 0x4D5554415445ull);

  bool inverse = opt.inverse;
  if (inverse) {
    for (const IRCommand& c : p.cmds) {
      if (c.op == IROp::JmpIndirect) {
        inverse = false;
        st.inverse_disabled = true;
        st.inverse_disabled_reason = "indirect branch: target not statically known";
        break;
      }
      if (c.op == IROp::InvR) {
        inverse = false;
        st.inverse_disabled = true;
        st.inverse_disabled_reason = "program already contains INV_R";
        break;
      }
    }
  }
  if (!opt.inverse) {
    st.inverse_disabled = true;
    st.inverse_disabled_reason = "disabled by caller";
  }

  std::vector<char> label_target(p.cmds.size() + 1, 0);
  for (size_t m : p.label_mark) {
    if (m != IRProgram::kUnbound && m <= p.cmds.size()) label_target[m] = 1;
  }

  std::vector<IRCommand> out;
  out.reserve(p.cmds.size() * 2 + 8);
  std::vector<size_t> remap(p.cmds.size() + 1, 0);

  uint32_t inv = 0;

  auto emit_inv = [&](int r) {
    IRCommand c;
    c.op = IROp::InvR;
    c.dst = IROperand::R(r);
    out.push_back(c);
    ++st.inv_r;
  };
  auto normalize = [&](uint32_t mask) {
    for (int r = 0; r < NVREG; ++r) {
      if (inv & mask & bit(r)) {
        emit_inv(r);
        inv &= ~bit(r);
        ++st.normalized;
      }
    }
  };

  for (size_t i = 0; i < p.cmds.size(); ++i) {
    const IRCommand& c = p.cmds[i];
    const IrRW rw = ir_rw_of(c, true);

    if (inverse) normalize(rw.rd);

    if (inverse && label_target[i]) normalize(kInvertible);

    remap[i] = out.size();
    out.push_back(c);

    inv &= ~rw.wr;

    if (inverse && !ir_block_end(c.op) && (rw.wr & kInvertible) &&
        rng.chance(opt.inverse_pct)) {
      const int d = pick_reg(rw.wr & kInvertible, rng);
      if (d >= 0) {
        emit_inv(d);
        inv |= bit(d);
        ++st.inverted_stores;
      }
    }

    if (opt.junk && rng.chance(opt.junk_pct)) {
      IRCommand j;
      j.op = IROp::Junk;
      j.src = IROperand::I(static_cast<int64_t>(rng.next()), 8);
      out.push_back(j);
      ++st.junk;
    }
    if (opt.noise && rng.chance(opt.noise_pct)) {
      IRCommand n;
      n.op = IROp::Noise;
      n.dst = IROperand::R(REG_NOISE);
      n.src = IROperand::I(static_cast<int64_t>(rng.next()), 8);
      out.push_back(n);
      ++st.noise;
    }
  }
  remap[p.cmds.size()] = out.size();

  const size_t n = p.cmds.size();
  for (size_t& m : p.label_mark) {
    if (m == IRProgram::kUnbound) continue;
    m = remap[m <= n ? m : n];
  }
  p.entry_cmd = remap[p.entry_cmd <= n ? p.entry_cmd : n];
  p.cmds.swap(out);
  st.cmds_after = p.cmds.size();
  return st;
}

}
