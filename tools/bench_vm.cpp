#include "lift.hpp"

#include "hyda/codec/crypt.hpp"
#include "hyda/ir/ir_codegen.hpp"
#include "hyda/native/island.hpp"
#include "hyda/vm/gate.hpp"
#include "hyda/vm/vm.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <sys/mman.h>
#include <vector>

extern "C" char __stop_bench_loop[];
extern "C" char __stop_bench_straight[];

namespace {

using Clock = std::chrono::steady_clock;
using Fn = uint64_t (*)(uint64_t, uint64_t);

struct Fixture {
  const char* name;
  Fn fn;
  const char* stop;
  uint64_t a;
  uint64_t b;
};

__attribute__((naked, noinline, section("bench_loop"), aligned(16)))
uint64_t bench_loop(uint64_t, uint64_t) {
  __asm__(".intel_syntax noprefix\n"
          "xor eax, eax\n"
          "1:\n"
          "add rax, rsi\n"
          "imul rax, rax, 3\n"
          "dec rdi\n"
          "jnz 1b\n"
          "ret\n .att_syntax prefix\n");
}

__attribute__((naked, noinline, section("bench_straight"), aligned(16)))
uint64_t bench_straight(uint64_t, uint64_t) {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          ".rept 32\n"
          "xor rax, rsi\n"
          "add rax, 3\n"
          ".endr\n"
          "ret\n .att_syntax prefix\n");
}

constexpr size_t kStackBytes = 1u << 20;
alignas(64) uint8_t g_stack[kStackBytes];

struct VmCall {
  uint32_t status = 0;
  uint64_t ret = 0;
  uint64_t steps = 0;
};

VmCall vm_run(const hyda::Asm& code, uint64_t entry, uint64_t a, uint64_t b,
              uint64_t key = 0) {
  hyda::VMContext ctx;
  const uint64_t top =
      reinterpret_cast<uint64_t>(g_stack) + sizeof(g_stack) - 64;
  hyda::vm_init(ctx, top);
  ctx.max_steps = 100000000;
  ctx.r[hyda::vsl(hyda::REG_RDI)] = a;
  ctx.r[hyda::vsl(hyda::REG_RSI)] = b;
  hyda::vm_set_entry(ctx, entry);
  VmCall out;
  out.status = hyda::vm_exec(ctx, code.code.data(), code.code.size(), key);
  out.ret = ctx.r[hyda::vsl(hyda::REG_RAX)];
  out.steps = ctx.steps;
  return out;
}

double best_ns(int rounds, int iters, const std::function<void()>& fn) {
  double best = 1e18;
  for (int r = 0; r < rounds; ++r) {
    const Clock::time_point t0 = Clock::now();
    for (int i = 0; i < iters; ++i) fn();
    const Clock::time_point t1 = Clock::now();
    const double ns =
        static_cast<double>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()) /
        iters;
    best = std::min(best, ns);
  }
  return best;
}

}  // namespace

int main() {
  const Fixture fixtures[] = {
      {"alu loop (64 iterations)", bench_loop, __stop_bench_loop, 64, 7},
      {"straight line (64 ops)", bench_straight, __stop_bench_straight, 11, 5},
  };

  std::printf("%-26s %10s %11s %7s %7s %9s\n", "body", "native", "vm", "ratio",
              "vm ops", "ns/op");
  for (const Fixture& f : fixtures) {
    const uintptr_t start = reinterpret_cast<uintptr_t>(f.fn);
    const size_t size =
        static_cast<size_t>(reinterpret_cast<uintptr_t>(f.stop) - start);

    hyda::LiftOptions opt;
    opt.base_address = start;
    opt.name = f.name;
    const hyda::LiftResult lr = hyda::lift_x86_64(
        reinterpret_cast<const uint8_t*>(start), size, opt);
    if (!lr.ok) {
      std::printf("%-26s lift failed: %s\n", f.name, lr.error.c_str());
      continue;
    }
    hyda::IRProgram prog = lr.prog;
    hyda::ir_wrap_callable(prog);
    hyda::Asm asmb;
    const hyda::CodegenResult cg = hyda::ir_codegen(prog, asmb);
    if (!cg.ok) {
      std::printf("%-26s codegen failed: %s\n", f.name, cg.error.c_str());
      continue;
    }

    volatile uint64_t sink = 0;
    const int iters = 20000;
    const VmCall probe = vm_run(asmb, cg.entry_offset, f.a, f.b);
    if (probe.status != hyda::ST_HALT) {
      std::printf("%-26s vm status %u\n", f.name, probe.status);
      continue;
    }
    const double native_ns = best_ns(5, iters, [&]() {
      sink = sink + static_cast<uint64_t>(f.fn(f.a, f.b));
    });
    const double vm_ns = best_ns(5, iters / 4, [&]() {
      sink = sink + vm_run(asmb, cg.entry_offset, f.a, f.b).ret;
    });

    std::printf("%-26s %8.1fns %9.1fns %6.1fx %7llu %8.1f\n", f.name, native_ns,
                vm_ns, vm_ns / native_ns,
                static_cast<unsigned long long>(probe.steps),
                vm_ns / static_cast<double>(probe.steps));

    hyda::Asm enc = asmb;
    const uint64_t key = hyda::crypt_key_for(0x1000);
    hyda::crypt_operands_encrypt(enc.code.data(), enc.code.size(), key);
    const VmCall enc_probe = vm_run(enc, cg.entry_offset, f.a, f.b, key);
    if (enc_probe.status != hyda::ST_HALT || enc_probe.ret != probe.ret) {
      std::printf("%-26s ciphertext run diverged (status %u)\n", f.name,
                  enc_probe.status);
      continue;
    }
    const double enc_ns = best_ns(5, iters / 4, [&]() {
      sink = sink + vm_run(enc, cg.entry_offset, f.a, f.b, key).ret;
    });
    std::printf("%-26s %8.1fns %9.1fns %6.1fx %7llu %8.1f\n",
                "  ^ ciphertext slots", native_ns, enc_ns, enc_ns / native_ns,
                static_cast<unsigned long long>(enc_probe.steps),
                enc_ns / static_cast<double>(enc_probe.steps));
  }
  {
    alignas(4096) static uint8_t area[8192];
    if (mprotect(area, sizeof(area), PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
      const uint32_t rva = 0x1000;
      const uint64_t base = reinterpret_cast<uint64_t>(area) - rva;
      uint8_t* body = area + hyda::HYDA_ISLAND_SIZE;
      const uint8_t insn[] = {0x31, 0xC0, 0x83, 0xC0, 0x07, 0xE9};
      std::memcpy(body, insn, sizeof(insn));
      const int64_t next = reinterpret_cast<int64_t>(body) + sizeof(insn) + 4;
      const int32_t rel = static_cast<int32_t>(
          reinterpret_cast<int64_t>(&hyda_vm_gate_leave) - next);
      std::memcpy(body + sizeof(insn), &rel, 4);
      const uint32_t len = static_cast<uint32_t>(sizeof(insn) + 4);

      hyda::IslandHeader h;
      h.magic = hyda::island_magic();
      h.size = len;
      h.salt = hyda::island_salt_for(0, rva + hyda::HYDA_ISLAND_SIZE);
      h.flags = 0;
      h.refs = 0;
      h.import_index = 0;
      h.reserved2 = 0;
      std::memcpy(area, &h, sizeof(h));
      hyda::island_encrypt(body, len,
                           hyda::island_key_for(h.salt, rva + hyda::HYDA_ISLAND_SIZE));

      hyda::VMContext ctx;
      const uint64_t top =
          reinterpret_cast<uint64_t>(g_stack) + sizeof(g_stack) - 64;
      const double gate_ns = best_ns(5, 20000, [&]() {
        hyda::vm_init(ctx, top);
        ctx.image_base = base;
        hyda_vm_gate_enter(&ctx, body);
      });
      std::printf("%-26s %8.1fns %9s %6s %7s %8s\n", "island gate round trip",
                  gate_ns, "-", "-", "1", "-");
    }
  }
  return 0;
}