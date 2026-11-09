#pragma once

#include "hyda/core/opcodes.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace hyda {

class Asm {
 public:
  static constexpr size_t kUnbound = static_cast<size_t>(-1);

  std::vector<uint8_t> code;

  bool used_ops[OP_COUNT] = {};

  size_t here() const { return code.size(); }

  size_t label() {
    labels_.push_back(kUnbound);
    return labels_.size() - 1;
  }

  Asm& bind(size_t l) {
    labels_[l] = code.size();
    return *this;
  }

  Asm& raw(Op o) {
    used_ops[static_cast<size_t>(o)] = true;
    const uint16_t slot = opcode_map().slot_of_op[static_cast<size_t>(o)];
    u8(static_cast<uint8_t>(slot & 0xFFu));
    return u8(static_cast<uint8_t>(slot >> 8));
  }
  Asm& u8(uint8_t v) { code.push_back(v); return *this; }
  Asm& sb(int v) { code.push_back(static_cast<uint8_t>(static_cast<int8_t>(v))); return *this; }

  Asm& s32(int32_t v) {
    uint8_t t[4];
    std::memcpy(t, &v, 4);
    code.insert(code.end(), t, t + 4);
    return *this;
  }

  Asm& s64(int64_t v) {
    uint8_t t[8];
    std::memcpy(t, &v, 8);
    code.insert(code.end(), t, t + 8);
    return *this;
  }

  static uint8_t vr(int logical) {

    if (logical < 0 || logical >= NVREG) return static_cast<uint8_t>(logical);
    return static_cast<uint8_t>(vsl(logical));
  }
  static uint8_t rv(Op o, int idx) {
    return is_xmm_op(o) ? static_cast<uint8_t>(idx) : vr(idx);
  }
  static uint8_t mem_idx(int idx) {
    return idx == static_cast<int>(NO_MEM) ? static_cast<uint8_t>(NO_MEM)
                                           : vr(idx);
  }

  Asm& i0(Op o) { return raw(o); }
  Asm& i_r(Op o, int a) { raw(o); return u8(rv(o, a)); }
  Asm& i_rr(Op o, int a, int b) { raw(o); u8(rv(o, a)); return u8(rv(o, b)); }
  Asm& i_rb(Op o, int a, int c) { raw(o); u8(rv(o, a)); return sb(c); }
  Asm& i_rrb(Op o, int a, int b, int c) { raw(o); u8(rv(o, a)); u8(rv(o, b)); return sb(c); }

  Asm& i_rbb(Op o, int a, int b, int c) { raw(o); u8(rv(o, a)); sb(b); return sb(c); }
  Asm& i_rrrb(Op o, int a, int b, int c, int d) {
    raw(o);
    u8(rv(o, a));
    u8(rv(o, b));
    u8(rv(o, c));
    return sb(d);
  }
  Asm& i_rq(Op o, int a, int64_t v) { raw(o); u8(rv(o, a)); return s64(v); }
  Asm& i_q(Op o, int64_t v) { raw(o); return s64(v); }

  Asm& i_rrb_cvt(Op o, int a, bool a_gpr, int b, bool b_gpr, int c) {
    raw(o);
    u8(a_gpr ? vr(a) : static_cast<uint8_t>(a));
    u8(b_gpr ? vr(b) : static_cast<uint8_t>(b));
    return sb(c);
  }

  Asm& i_mem(Op o, int reg, int base, int index, int scale, int32_t disp) {
    raw(o);
    u8(is_xmm_op(o) ? static_cast<uint8_t>(reg) : vr(reg));
    u8(mem_idx(base));
    u8(mem_idx(index));
    sb(scale);
    return s32(disp);
  }

  Asm& rel(size_t l) {
    fixups_.push_back(Fixup{l, code.size()});
    return s32(0);
  }

  Asm& i_j(Op o, size_t l) { raw(o); return rel(l); }

  Asm& i_rrbbb_j(Op o, int a, int b, int c, int d, int e, size_t l) {
    raw(o);
    u8(vr(a));
    u8(vr(b));
    sb(c);
    sb(d);
    sb(e);
    return rel(l);
  }

  void finalize() {
    for (const Fixup& f : fixups_) {
      if (labels_[f.label] == kUnbound) {
        throw std::runtime_error("HydaVM/Asm: unresolved label");
      }
      const int64_t disp =
          static_cast<int64_t>(labels_[f.label]) - static_cast<int64_t>(f.at + 4);
      const int32_t v = static_cast<int32_t>(disp);
      std::memcpy(&code[f.at], &v, 4);
    }
    fixups_.clear();
  }

 private:
  struct Fixup {
    size_t label;
    size_t at;
  };
  std::vector<Fixup> fixups_;
  std::vector<size_t> labels_;
};

}
