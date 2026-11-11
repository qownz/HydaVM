#include "lift.hpp"

#include "hyda/ir/disasm.hpp"
#include "hyda/ir/ir_codegen.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

void usage(const char* argv0) {
  std::fprintf(stderr,
               "usage: %s <input.bin> <base_hex> [--dump <output>] [--ir]\n"
               "  input  : raw x86-64 machine code\n"
               "  base   : virtual address to load the code at (e.g. 0x140001000)\n"
               "  --dump : write generated VM bytecode to a file\n"
               "  --ir   : also print the IR listing\n",
               argv0);
}

const char* ir_name(hyda::IROp op) {
  using hyda::IROp;
  switch (op) {
    case IROp::Nop: return "nop";
    case IROp::Halt: return "halt";
    case IROp::Mov: return "mov";
    case IROp::Lea: return "lea";
    case IROp::Xchg: return "xchg";
    case IROp::Cmov: return "cmov";
    case IROp::Push: return "push";
    case IROp::Pop: return "pop";
    case IROp::Pushf: return "pushf";
    case IROp::Popf: return "popf";
    case IROp::Alu: return "alu";
    case IROp::Shift: return "shift";
    case IROp::Unary: return "unary";
    case IROp::Test: return "test";
    case IROp::Imul: return "imul";
    case IROp::Mul: return "mul";
    case IROp::Div: return "div";
    case IROp::SignExtend: return "signext";
    case IROp::Extend: return "extend";
    case IROp::Bswap: return "bswap";
    case IROp::BitScan: return "bitscan";
    case IROp::BitTest: return "bittest";
    case IROp::Jmp: return "jmp";
    case IROp::Jcc: return "jcc";
    case IROp::CmpJcc: return "cmpjcc";
    case IROp::AluJcc: return "alujcc";
    case IROp::Call: return "call";
    case IROp::Ret: return "ret";
    case IROp::RetImm: return "ret imm";
    case IROp::JmpIndirect: return "jmp *";
    case IROp::Junk: return "junk";
    case IROp::Noise: return "noise";
    case IROp::InvR: return "inv";
  }
  return "?";
}

void print_operand(const hyda::IROperand& o) {
  using hyda::IRKind;
  switch (o.kind) {
    case IRKind::Reg:
      std::printf("%s", hyda::vreg_name(o.reg));
      break;
    case IRKind::Imm:
      std::printf("%lld", static_cast<long long>(o.imm));
      break;
    case IRKind::Label:
      std::printf("L%d", o.label);
      break;
    case IRKind::Mem: {
      std::printf("[");
      const char* sep = "";
      if (o.mem.base >= 0) { std::printf("%s", hyda::vreg_name(o.mem.base)); sep = "+"; }
      if (o.mem.index >= 0) {
        std::printf("%s%s*%u", sep, hyda::vreg_name(o.mem.index), o.mem.scale);
        sep = "+";
      }
      if (o.mem.disp != 0 || (o.mem.base < 0 && o.mem.index < 0)) {
        std::printf("%s%d", sep, o.mem.disp);
      }
      std::printf("]");
      break;
    }
    case IRKind::Xmm:
      std::printf("xmm%d", o.reg);
      break;
    case IRKind::None:
      break;
  }
}

void dump_ir(const hyda::IRProgram& p, size_t limit) {
  size_t shown = 0;
  for (size_t i = 0; i < p.cmds.size() && shown < limit; ++i, ++shown) {
    const hyda::IRCommand& c = p.cmds[i];
    std::printf("  %4zu  %-9s", i, ir_name(c.op));
    if (c.dst.kind != hyda::IRKind::None) { print_operand(c.dst); }
    if (c.src.kind != hyda::IRKind::None) { std::printf(", "); print_operand(c.src); }
    if (c.op == hyda::IROp::Jcc || c.op == hyda::IROp::Jmp || c.op == hyda::IROp::Call) {
      std::printf("  -> L%d", c.label);
    }
    std::printf("\n");
  }
  if (p.cmds.size() > limit) std::printf("  ... (%zu more)\n", p.cmds.size() - limit);
}

}

int main(int argc, char** argv) {
  if (argc < 3) { usage(argv[0]); return 2; }

  const std::string in_path = argv[1];
  const uint64_t base = std::strtoull(argv[2], nullptr, 0);

  std::string out_path;
  bool want_ir = false;
  for (int i = 3; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--dump" && i + 1 < argc) out_path = argv[++i];
    else if (a == "--ir") want_ir = true;
    else { usage(argv[0]); return 2; }
  }

  std::ifstream f(in_path, std::ios::binary);
  if (!f) { std::fprintf(stderr, "error: cannot open '%s'\n", in_path.c_str()); return 1; }
  std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
  if (buf.empty()) { std::fprintf(stderr, "error: empty file\n"); return 1; }

  hyda::LiftOptions opt;
  opt.base_address = base;
  opt.name = in_path;

  const hyda::LiftResult r = hyda::lift_x86_64(buf.data(), buf.size(), opt);

  std::printf("input      : %s (%zu bytes)\n", in_path.c_str(), buf.size());
  std::printf("base       : %#llx\n", static_cast<unsigned long long>(base));
  std::printf("decoded    : %zu\n", r.decoded);
  std::printf("ir insns   : %zu\n", r.emitted);
  std::printf("pruned     : %zu\n", r.pruned);
  std::printf("islands    : %zu\n", r.prog.natives.size());
  for (const hyda::NativeIsland& isl : r.prog.natives) {
    std::printf("    %#llx  %s\n",
                static_cast<unsigned long long>(isl.orig_addr), isl.text.c_str());
  }

  if (!r.unsupported.empty()) {
    std::printf("unsupported: %zu\n", r.unsupported.size());
    for (const hyda::UnsupportedInsn& u : r.unsupported) {
      std::printf("    %#llx  %-10s  %s\n",
                  static_cast<unsigned long long>(u.address), u.mnemonic.c_str(),
                  u.reason.c_str());
    }
  }

  if (want_ir) {
    std::printf("--- IR ---\n");
    dump_ir(r.prog, 200);
  }

  if (!r.ok) {
    std::printf("result: failed - %s\n", r.error.c_str());
    return 1;
  }

  hyda::Asm asm_out;
  const hyda::CodegenResult cg = hyda::ir_codegen(r.prog, asm_out);
  if (!cg.ok) {
    std::printf("result: codegen failed - %s\n", cg.error.c_str());
    return 1;
  }

  std::printf("bytecode   : %zu bytes, entry @ %zu\n", cg.code_size, cg.entry_offset);
  std::printf("--- VM bytecode ---\n");
  hyda::disasm(asm_out.code.data(), asm_out.code.size());

  if (!out_path.empty()) {
    std::ofstream o(out_path, std::ios::binary);
    if (!o) { std::fprintf(stderr, "error: cannot write '%s'\n", out_path.c_str()); return 1; }
    o.write(reinterpret_cast<const char*>(asm_out.code.data()),
            static_cast<std::streamsize>(asm_out.code.size()));
    std::printf("written    : %s\n", out_path.c_str());
  }

  std::printf("result: ok\n");
  return 0;
}
