#include "harness/test.hpp"
#include "lift.hpp"
#include "native_island.hpp"

#include "hyda/ir/disasm.hpp"
#include "hyda/vm/gate.hpp"
#include "hyda/ir/ir_codegen.hpp"
#include "hyda/native/island.hpp"
#include "hyda/native/island_mut.hpp"
#include "hyda/vm/fpstate.hpp"
#include "hyda/vm/vm.hpp"

#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace hyda;

namespace {

hyda::test::Reporter* g_rep = nullptr;

}  // namespace

#define ck(ok, what) \
  (g_rep->check(static_cast<bool>(ok), (what), __FILE__, __LINE__))

#define HYDA_FN(NAME, SEC)                                        \
  __attribute__((naked, noinline, section(SEC)))                  \
  uint64_t NAME(uint64_t, uint64_t, uint64_t, uint64_t)

HYDA_FN(f_alu, "hyda_f_alu") {
  __asm__(".intel_syntax noprefix\n"
          "lea rax, [rdi + rsi]\n"
          "add rax, rdx\n"
          "sub rax, rcx\n"
          "xor rax, 0x1234\n"
          "not rax\n"
          "neg rax\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_alu[];

HYDA_FN(f_writes, "hyda_f_writes") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "mov rdx, rsi\n"
          "add rax, rdx\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_writes[];

HYDA_FN(f_cmp, "hyda_f_cmp") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "cmp rax, rsi\n"
          "jle 1f\n"
          "sub rax, rsi\n"
          "ret\n"
          "1:\n"
          "add rax, rsi\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_cmp[];

HYDA_FN(f_loop, "hyda_f_loop") {
  __asm__(".intel_syntax noprefix\n"
          "xor eax, eax\n"
          "test rdi, rdi\n"
          "je 2f\n"
          "1:\n"
          "add rax, rdi\n"
          "dec rdi\n"
          "jne 1b\n"
          "2:\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_loop[];

HYDA_FN(f_alu_jcc, "hyda_f_alu_jcc") {
  __asm__(".intel_syntax noprefix\n"
          "xor eax, eax\n"
          "test rdi, rdi\n"
          "je 2f\n"
          "mov rdx, rdi\n"
          "1:\n"
          "add rax, rsi\n"
          "sub rdx, 1\n"
          "jnz 1b\n"
          "2:\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_alu_jcc[];

HYDA_FN(f_mem, "hyda_f_mem") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, [rdi]\n"
          "add rax, [rsi]\n"
          "mov [rdx], rax\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_mem[];

HYDA_FN(f_shift, "hyda_f_shift") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "shl rax, 3\n"
          "shr rax, 1\n"
          "sar rax, 1\n"
          "rol rax, 5\n"
          "ror rax, 2\n"
          "xor rax, rsi\n"
          "or rax, rdx\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_shift[];

HYDA_FN(f_extend, "hyda_f_extend") {
  __asm__(".intel_syntax noprefix\n"
          "movzx eax, dil\n"
          "movsx rcx, si\n"
          "add rax, rcx\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_extend[];

HYDA_FN(f_div, "hyda_f_div") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "cqo\n"
          "idiv rsi\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_div[];

HYDA_FN(f_call, "hyda_f_call") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "call 1f\n"
          "add rax, rsi\n"
          "ret\n"
          "1:\n"
          "add rax, 5\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_call[];

HYDA_FN(f_32bit, "hyda_f_32bit") {
  __asm__(".intel_syntax noprefix\n"
          "mov eax, edi\n"
          "add eax, esi\n"
          "sub eax, edx\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_32bit[];

HYDA_FN(f_test32, "hyda_f_test32") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "mov rcx, rsi\n"
          "test eax, ecx\n"
          "jne 1f\n"
          "mov rax, 0x111\n"
          "ret\n"
          "1:\n"
          "mov rax, 0x222\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_test32[];

HYDA_FN(f_imul_lea, "hyda_f_imul_lea") {
  __asm__(".intel_syntax noprefix\n"
          "imul rax, rdi, 9\n"
          "add rax, rsi\n"
          "lea rax, [rax + rdx*4 + 8]\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_imul_lea[];

HYDA_FN(f_cmov32, "hyda_f_cmov32") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "mov ecx, esi\n"
          "cmp eax, ecx\n"
          "cmovae eax, edx\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_cmov32[];

HYDA_FN(f_cmov64, "hyda_f_cmov64") {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rdi\n"
          "cmp rax, rsi\n"
          "cmovb rax, rdx\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_cmov64[];

HYDA_FN(f_setcc, "hyda_f_setcc") {
  __asm__(".intel_syntax noprefix\n"
          "xor eax, eax\n"
          "mov ecx, edi\n"
          "test ecx, ecx\n"
          "setne al\n"
          "add rax, rsi\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_setcc[];

#define HYDA_SAVE_PTR "mov r10, rdx\n"

#define HYDA_PACK_FLAGS                                                       \
  "setc cl\n seto sil\n setz dil\n sets r8b\n setp r9b\n"                     \
  "movzx ecx, cl\n movzx esi, sil\n movzx edi, dil\n"                         \
  "movzx r8d, r8b\n movzx r9d, r9b\n"                                         \
  "shl esi, 1\n shl edi, 2\n shl r8d, 3\n shl r9d, 4\n"                       \
  "or ecx, esi\n or ecx, edi\n or ecx, r8d\n or ecx, r9d\n"                   \
  "mov r8d, ecx\n"

#define HYDA_OUT                                                              \
  "mov [r10], rax\n mov [r10 + 8], rdx\n mov [r10 + 16], r8\n"

HYDA_FN(f_dead_add, "hyda_f_dead_add") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n"
          "add rax, rsi\n"
          "mov rcx, rdx\n"
          "cmp rax, rsi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_dead_add[];

HYDA_FN(f_dead_cmp, "hyda_f_dead_cmp") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n"
          "cmp rax, rsi\n"
          "sub rax, rsi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_dead_cmp[];

HYDA_FN(f_live_add, "hyda_f_live_add") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n"
          "add rax, rsi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_live_add[];

HYDA_FN(f_mul32, "hyda_f_mul32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n mul ecx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_mul32[];

HYDA_FN(f_imul1_32, "hyda_f_imul1_32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n imul ecx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_imul1_32[];

HYDA_FN(f_mul16, "hyda_f_mul16") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n mul cx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_mul16[];

HYDA_FN(f_imul1_16, "hyda_f_imul1_16") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n imul cx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_imul1_16[];

HYDA_FN(f_mul8, "hyda_f_mul8") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n mul cl\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_mul8[];

HYDA_FN(f_imul1_8, "hyda_f_imul1_8") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n imul cl\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_imul1_8[];

HYDA_FN(f_imul2_32, "hyda_f_imul2_32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n imul eax, esi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_imul2_32[];

HYDA_FN(f_imul2_16, "hyda_f_imul2_16") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n mov ecx, esi\n imul ax, cx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_imul2_16[];

HYDA_FN(f_div32, "hyda_f_div32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n mov rdx, rax\n shr rdx, 32\n mov ecx, esi\n div ecx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_div32[];

HYDA_FN(f_idiv32, "hyda_f_idiv32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n cdq\n mov ecx, esi\n idiv ecx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_idiv32[];

HYDA_FN(f_div16, "hyda_f_div16") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n xor edx, edx\n mov ecx, esi\n div cx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_div16[];

HYDA_FN(f_idiv16, "hyda_f_idiv16") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n xor edx, edx\n mov ecx, esi\n idiv cx\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_idiv16[];

HYDA_FN(f_tzcnt32, "hyda_f_tzcnt32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n tzcnt eax, esi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_tzcnt32[];

HYDA_FN(f_lzcnt32, "hyda_f_lzcnt32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n lzcnt eax, esi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_lzcnt32[];

HYDA_FN(f_popcnt32, "hyda_f_popcnt32") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov eax, edi\n popcnt eax, esi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_popcnt32[];

HYDA_FN(f_tzcnt64, "hyda_f_tzcnt64") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n tzcnt rax, rsi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_tzcnt64[];

HYDA_FN(f_lzcnt64, "hyda_f_lzcnt64") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n lzcnt rax, rsi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_lzcnt64[];

HYDA_FN(f_popcnt64, "hyda_f_popcnt64") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n popcnt rax, rsi\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_popcnt64[];

HYDA_FN(f_tzcnt16, "hyda_f_tzcnt16") {
  __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR
          "mov rax, rdi\n tzcnt ax, si\n"
          HYDA_PACK_FLAGS HYDA_OUT "ret\n .att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_tzcnt16[];

#define HYDA_SHIFT_PROBE(NAME, SEC, INSN, SZ)                                 \
  HYDA_FN(NAME, HYDA_STR(SEC)) {                                              \
    __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR                                        \
            "mov rax, rdi\n mov cl, sil\n cmp edx, edx\n"                     \
            INSN " " SZ ", cl\n" HYDA_PACK_FLAGS HYDA_OUT                     \
            "ret\n .att_syntax prefix\n");                                    \
  }                                                                           \
  extern "C" char __stop_##SEC[];

#define HYDA_STR2(x) #x
#define HYDA_STR(x) HYDA_STR2(x)

HYDA_SHIFT_PROBE(f_shl8,  hyda_f_shl8,  "shl", "al")
HYDA_SHIFT_PROBE(f_shl16, hyda_f_shl16, "shl", "ax")
HYDA_SHIFT_PROBE(f_shl32, hyda_f_shl32, "shl", "eax")
HYDA_SHIFT_PROBE(f_shl64, hyda_f_shl64, "shl", "rax")
HYDA_SHIFT_PROBE(f_shr8,  hyda_f_shr8,  "shr", "al")
HYDA_SHIFT_PROBE(f_shr16, hyda_f_shr16, "shr", "ax")
HYDA_SHIFT_PROBE(f_shr32, hyda_f_shr32, "shr", "eax")
HYDA_SHIFT_PROBE(f_shr64, hyda_f_shr64, "shr", "rax")
HYDA_SHIFT_PROBE(f_sar8,  hyda_f_sar8,  "sar", "al")
HYDA_SHIFT_PROBE(f_sar16, hyda_f_sar16, "sar", "ax")
HYDA_SHIFT_PROBE(f_sar32, hyda_f_sar32, "sar", "eax")
HYDA_SHIFT_PROBE(f_sar64, hyda_f_sar64, "sar", "rax")
HYDA_SHIFT_PROBE(f_rol8,  hyda_f_rol8,  "rol", "al")
HYDA_SHIFT_PROBE(f_rol16, hyda_f_rol16, "rol", "ax")
HYDA_SHIFT_PROBE(f_rol32, hyda_f_rol32, "rol", "eax")
HYDA_SHIFT_PROBE(f_rol64, hyda_f_rol64, "rol", "rax")
HYDA_SHIFT_PROBE(f_ror8,  hyda_f_ror8,  "ror", "al")
HYDA_SHIFT_PROBE(f_ror16, hyda_f_ror16, "ror", "ax")
HYDA_SHIFT_PROBE(f_ror32, hyda_f_ror32, "ror", "eax")
HYDA_SHIFT_PROBE(f_ror64, hyda_f_ror64, "ror", "rax")

#define HYDA_DOUBLE_SHIFT_PROBE(NAME, SEC, INSN)                              \
  HYDA_FN(NAME, HYDA_STR(SEC)) {                                              \
    __asm__(".intel_syntax noprefix\n" HYDA_SAVE_PTR                          \
            "mov rax, rdi\n mov r11, rsi\n mov cl, sil\n cmp edx, edx\n"      \
            INSN "\n" HYDA_PACK_FLAGS HYDA_OUT                                \
            "ret\n .att_syntax prefix\n");                                    \
  }                                                                           \
  extern "C" char __stop_##SEC[];

HYDA_DOUBLE_SHIFT_PROBE(f_shld64, hyda_f_shld64, "shld rax, r11, cl")
HYDA_DOUBLE_SHIFT_PROBE(f_shrd64, hyda_f_shrd64, "shrd rax, r11, cl")
HYDA_DOUBLE_SHIFT_PROBE(f_shld32, hyda_f_shld32, "shld eax, r11d, cl")
HYDA_DOUBLE_SHIFT_PROBE(f_shrd32, hyda_f_shrd32, "shrd eax, r11d, cl")
HYDA_DOUBLE_SHIFT_PROBE(f_shld64_imm, hyda_f_shld64_imm, "shld rax, r11, 9")
HYDA_DOUBLE_SHIFT_PROBE(f_shrd64_imm, hyda_f_shrd64_imm, "shrd rax, r11, 9")
HYDA_DOUBLE_SHIFT_PROBE(f_shld32_imm, hyda_f_shld32_imm, "shld eax, r11d, 9")
HYDA_DOUBLE_SHIFT_PROBE(f_shrd32_imm, hyda_f_shrd32_imm, "shrd eax, r11d, 9")
HYDA_DOUBLE_SHIFT_PROBE(f_shld32_zero, hyda_f_shld32_zero, "shld eax, r11d, 0")
HYDA_DOUBLE_SHIFT_PROBE(f_shrd32_zero, hyda_f_shrd32_zero, "shrd eax, r11d, 0")

HYDA_FN(f_sse_mix, "hyda_f_sse_mix") {
  __asm__(".intel_syntax noprefix\n"
          "movupd xmm0, [rdi]\n"
          "pxor xmm1, xmm1\n"
          "pshufb xmm0, xmm1\n"
          "blendps xmm0, xmm1, 0\n"
          "pblendw xmm0, xmm1, 0\n"
          "phaddd xmm0, xmm1\n"
          "movupd [rdx], xmm0\n"
          "mov eax, 4\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_sse_mix[];

HYDA_FN(f_sse_cvt, "hyda_f_sse_cvt") {
  __asm__(".intel_syntax noprefix\n"
          "cvtsi2ss xmm0, rdi\n"
          "mulss xmm0, [rsi]\n"
          "cvttss2si rax, xmm0\n"
          "movd xmm1, eax\n"
          "pshufd xmm1, xmm1, 0x00\n"
          "movq [rdx], xmm1\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_sse_cvt[];

HYDA_FN(f_sse, "hyda_f_sse") {
  __asm__(".intel_syntax noprefix\n"
          "movss xmm0, [rdi]\n"
          "movss xmm1, [rsi]\n"
          "addss xmm0, xmm1\n"
          "movss [rdx], xmm0\n"
          "mov eax, 1\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_sse[];

HYDA_FN(f_sse_cmp, "hyda_f_sse_cmp") {
  __asm__(".intel_syntax noprefix\n"
          "movss xmm0, [rdi]\n"
          "comiss xmm0, [rsi]\n"
          "seta al\n"
          "movzx eax, al\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_sse_cmp[];

HYDA_FN(f_sse4, "hyda_f_sse4") {
  __asm__(".intel_syntax noprefix\n"
          "movupd xmm0, [rdi]\n"
          "movupd xmm1, [rsi]\n"
          "pxor xmm2, xmm2\n"
          "addps xmm0, xmm2\n"
          "addps xmm0, xmm1\n"
          "movupd [rdx], xmm0\n"
          "mov eax, 4\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_sse4[];

HYDA_FN(f_sse2, "hyda_f_sse2") {
  __asm__(".intel_syntax noprefix\n"
          "movdqu xmm0, [rdi]\n"
          "movdqu xmm1, [rsi]\n"
          "paddsb xmm0, xmm1\n"
          "pmullw xmm0, xmm1\n"
          "pcmpeqd xmm2, xmm2\n"
          "pxor xmm0, xmm2\n"
          "psllq xmm0, 3\n"
          "punpcklbw xmm0, xmm1\n"
          "psrldq xmm0, 2\n"
          "movdqu [rdx], xmm0\n"
          "mov rax, [rdx]\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_sse2[];

HYDA_FN(f_avx, "hyda_f_avx") {
  __asm__(".intel_syntax noprefix\n"
          "vmovups xmm0, [rdi]\n"
          "vmovups xmm1, [rsi]\n"
          "vaddps xmm2, xmm0, xmm1\n"
          "vmulps xmm3, xmm2, xmm0\n"
          "vxorps xmm4, xmm4, xmm4\n"
          "vsubps xmm5, xmm3, xmm1\n"
          "vmovups [rdx], xmm5\n"
          "mov rax, [rdx]\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_avx[];

HYDA_FN(f_avx256, "hyda_f_avx256") {
  __asm__(".intel_syntax noprefix\n"
          "vmovups ymm0, [rdi]\n"
          "vmovups ymm1, [rsi]\n"
          "vaddps ymm2, ymm0, ymm1\n"
          "vmulps ymm3, ymm2, ymm0\n"
          "vsubps ymm4, ymm3, ymm1\n"
          "vxorps ymm5, ymm5, ymm5\n"
          "vpsubd ymm6, ymm3, ymm5\n"
          "vpaddd ymm7, ymm6, ymm4\n"
          "vmovups [rdx], ymm7\n"
          "mov rax, [rdx]\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_avx256[];

HYDA_FN(f_avx256_gate, "hyda_f_avx256_gate") {
  __asm__(".intel_syntax noprefix\n"
          "vmovups ymm0, [rdi]\n"
          "vmovups ymm1, [rsi]\n"
          "vaddps ymm0, ymm0, ymm1\n"
          "phaddd xmm3, xmm3\n"
          "vmulps ymm0, ymm0, ymm1\n"
          "vmovups [rdx], ymm0\n"
          "mov rax, [rdx]\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_avx256_gate[];

extern "C" {
float hyda_mut_c1 = 3.25f;
float hyda_mut_c2 = 1.5f;
}

HYDA_FN(f_sse_rip, "hyda_f_sse_rip") {
  __asm__("movss hyda_mut_c1(%rip), %xmm0\n"
          "mulss hyda_mut_c2(%rip), %xmm0\n"
          "movss %xmm0, (%rdx)\n"
          "movl $2, %eax\n"
          "ret\n");
}
extern "C" char __stop_hyda_f_sse_rip[];

HYDA_FN(f_x87, "hyda_f_x87") {
  __asm__(".intel_syntax noprefix\n"
          "fld qword ptr [rdi]\n"
          "fld1\n"
          "faddp st(1), st(0)\n"
          "fstp qword ptr [rdi]\n"
          "mov eax, 3\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_x87[];

HYDA_FN(f_cpuid, "hyda_f_cpuid") {
  __asm__(".intel_syntax noprefix\n"
          "xor eax, eax\n"
          "xor ecx, ecx\n"
          "cpuid\n"
          "mov [rdi], rax\n"
          "mov [rdi + 8], rbx\n"
          "mov [rdi + 16], rcx\n"
          "mov [rdi + 24], rdx\n"
          "mov eax, 9\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_cpuid[];

HYDA_FN(f_xmmarg, "hyda_f_xmmarg") {
  __asm__(".intel_syntax noprefix\n"
          "movss [rdi], xmm0\n"
          "addss xmm0, xmm0\n"
          "mov eax, 7\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_xmmarg[];

static uint64_t gate_callee(uint64_t a, uint64_t b) { return a + b + 100; }

extern "C" {
__attribute__((used)) HYDA_INTERNAL uint64_t (*hyda_gate_fnptr)(uint64_t, uint64_t) =
    gate_callee;
}

HYDA_FN(f_icall, "hyda_f_icall") {
  __asm__(".intel_syntax noprefix\n"
          "call [rip + hyda_gate_fnptr]\n"
          "add rax, 7\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_icall[];

extern "C" __attribute__((naked, noinline)) uint64_t test_align_probe(void) {
  __asm__(".intel_syntax noprefix\n"
          "mov rax, rsp\n"
          "and eax, 15\n"
          "ret\n"
          ".att_syntax prefix\n");
}

HYDA_FN(f_dcall, "hyda_f_dcall") {
  __asm__(".intel_syntax noprefix\n"
          "sub rsp, 8\n"
          "call test_align_probe\n"
          "add rsp, 8\n"
          "ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_dcall[];

HYDA_FN(f_switch, "hyda_f_switch") {
  __asm__(".intel_syntax noprefix\n"
          "cmp rdi, 3\n"
          "ja sw_default\n"
          "lea rax, [rip + sw_tab]\n"
          "jmp qword ptr [rax + rdi*8]\n"
          ".pushsection .data\n"
          "sw_tab: .quad sw_0, sw_1, sw_2, sw_3\n"
          ".popsection\n"
          "sw_0: mov rax, 10\n ret\n"
          "sw_1: mov rax, 20\n ret\n"
          "sw_2: mov rax, 30\n ret\n"
          "sw_3: mov rax, 40\n ret\n"
          "sw_default: mov rax, 99\n ret\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_switch[];

extern "C" __attribute__((noinline, used, visibility("hidden")))
uint64_t test_tail_target(uint64_t x) {
  return x * 3 + 7;
}

HYDA_FN(f_tail, "hyda_f_tail") {
  __asm__(".intel_syntax noprefix\n"
          "add rdi, 1\n"
          "jmp test_tail_target\n"
          ".att_syntax prefix\n");
}
extern "C" char __stop_hyda_f_tail[];

extern "C" __attribute__((naked, noinline))
uint64_t test_call_xmm0(uint64_t, uint64_t, uint64_t, uint64_t) {
  __asm__(".intel_syntax noprefix\n"
          "sub rsp, 8\n"
          "movss xmm0, [rdx]\n"
          "mov rax, rdi\n"
          "mov rdi, rsi\n"
          "call rax\n"
          "movss [rcx], xmm0\n"
          "add rsp, 8\n"
          "ret\n"
          ".att_syntax prefix\n");
}

__attribute__((noinline, section("hyda_c1")))
uint64_t c_sum_step(uint64_t a, uint64_t b, uint64_t, uint64_t) {
  uint64_t s = 0;
  for (uint64_t i = 0; i <= (a & 63u); ++i) s = s * 3u + i;
  return s ^ b;
}
extern "C" char __stop_hyda_c1[];

__attribute__((noinline, section("hyda_c2")))
uint64_t c_mix(uint64_t a, uint64_t b, uint64_t c, uint64_t) {
  if (a == 0) return b * c;
  uint64_t r = (a ^ (b << 3)) + (c >> 2);
  return r < a ? r : a;
}
extern "C" char __stop_hyda_c2[];

__attribute__((noinline, section("hyda_c3")))
uint64_t c_run(uint64_t a, uint64_t b, uint64_t c, uint64_t) {
  uint64_t acc = a & 63u;
  for (uint64_t i = 0; i < (b & 15u); ++i) {
    acc = acc * 5u + (i ^ c);
    if (acc & 1u) acc ^= 0x9E3779B97F4A7C15ull;
  }
  return acc;
}
extern "C" char __stop_hyda_c3[];

struct VmCall {
  uint64_t ret;
  uint32_t status;
  uint64_t steps;
};

static VmCall vm_run(const Asm& prog, uint64_t entry,
                     uint64_t a0 = 0, uint64_t a1 = 0,
                     uint64_t a2 = 0, uint64_t a3 = 0,
                     uint64_t image_base = 0) {
  alignas(64) static uint8_t stack[1 << 20];

  VMContext ctx;

  const uint64_t top =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stack)) + sizeof(stack) - 64;
  vm_init(ctx, top);
  ctx.max_steps = 50000000;
  ctx.image_base = image_base;

  ctx.r[vsl(REG_RDI)] = a0;
  ctx.r[vsl(REG_RSI)] = a1;
  ctx.r[vsl(REG_RDX)] = a2;
  ctx.r[vsl(REG_RCX)] = a3;
  vm_set_entry(ctx, entry);

  VmCall out;
  out.status = vm_exec(ctx, prog.code.data(), prog.code.size());
  out.ret = ctx.r[vsl(REG_RAX)];
  out.steps = ctx.steps;
  return out;
}

struct Case {
  uint64_t a, b, c, d;
};

using FnPtr = uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t);
using SkipFn = bool (*)(const Case&);

static std::vector<Case> mk_cases(int n, uint64_t ma, uint64_t mb, uint64_t mc, uint64_t md) {
  static const uint64_t edges[] = {
      0, 1, 2, 3, 7, 8, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x10000,
      0x7fffffff, 0x80000000, 0xffffffff, 0x100000000ull, 0x7fffffffffffffffull,
      0x8000000000000000ull, ~0ull, ~0ull - 1};

  std::vector<Case> v;
  for (uint64_t e : edges) {
    v.push_back(Case{e & ma, (~e) & mb, e & mc, (~e) & md});
  }
  uint64_t s = 0x9E3779B97F4A7C15ull;
  for (int i = 0; i < n; ++i) {
    v.push_back(Case{splitmix64(s) & ma, splitmix64(s) & mb, splitmix64(s) & mc,
                      splitmix64(s) & md});
  }
  return v;
}

static void run_diff(const char* name, FnPtr fn, uintptr_t stop_addr,
                     const std::vector<Case>& cases, SkipFn skip = nullptr) {
  const uintptr_t start = reinterpret_cast<uintptr_t>(fn);
  if (stop_addr <= start) {
    ck(false, std::string(name) + ": invalid section range");
    return;
  }

  LiftOptions opt;
  opt.base_address = start;
  opt.name = name;
  const size_t size = static_cast<size_t>(stop_addr - start);

  const LiftResult r =
      lift_x86_64(reinterpret_cast<const uint8_t*>(start), size, opt);
  ck(r.ok, std::string(name) + ": lift basarili (" + r.error + ")");
  if (!r.ok) {
    for (const UnsupportedInsn& u : r.unsupported) {
      std::printf("       desteklenmiyor: %#llx %-10s %s\n",
                  static_cast<unsigned long long>(u.address), u.mnemonic.c_str(),
                  u.reason.c_str());
    }
    return;
  }

  IRProgram prog = r.prog;
  ir_wrap_callable(prog);

  Asm a;
  const CodegenResult cg = ir_codegen(prog, a);
  ck(cg.ok, std::string(name) + ": bytecode uretildi (" + cg.error + ")");
  if (!cg.ok) return;

  int bad = 0;
  int n = 0;
  for (const Case& cs : cases) {
    if (skip && skip(cs)) continue;
    const uint64_t want = fn(cs.a, cs.b, cs.c, cs.d);
    const VmCall got = vm_run(a, cg.entry_offset, cs.a, cs.b, cs.c, cs.d, start);
    ++n;
    if (got.status != ST_HALT) {
      ck(false, std::string(name) + ": VM did not end with HALT (status=" +
                    std::to_string(got.status) + ")");
      ++bad;
      continue;
    }
    if (got.ret != want) {
      ck(false, std::string(name) + ": a=" + std::to_string(cs.a) +
                    " b=" + std::to_string(cs.b) + " c=" + std::to_string(cs.c) +
                    " d=" + std::to_string(cs.d) + " native=" + std::to_string(want) +
                    " vm=" + std::to_string(got.ret));
      ++bad;
    }
  }
  if (bad == 0) {
    std::printf("  OK  %-12s %3d inputs, %zu x86 insns -> %zu IR insns, %zu bytes bytecode\n",
                name, n, r.decoded, r.emitted, cg.code_size);
  } else {
    std::printf("  FAIL %-12s %d/%d inputs failed\n", name, bad, n);
  }
  ck(bad == 0, std::string(name) + ": " + std::to_string(bad) + "/" +
                   std::to_string(n) + " inputs failed");
}

struct VmOut {
  uint64_t rax, rdx, r8;
  uint32_t status;
};

static VmOut vm_run_out(const Asm& prog, uint64_t entry,
                        uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                        uint64_t image_base = 0) {
  alignas(64) static uint8_t stack[1 << 20];

  VMContext ctx;

  const uint64_t top =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stack)) + sizeof(stack) - 64;
  vm_init(ctx, top);
  ctx.max_steps = 50000000;
  ctx.image_base = image_base;

  ctx.r[vsl(REG_RDI)] = a;
  ctx.r[vsl(REG_RSI)] = b;
  ctx.r[vsl(REG_RDX)] = c;
  ctx.r[vsl(REG_RCX)] = d;
  vm_set_entry(ctx, entry);

  VmOut out;
  out.status = vm_exec(ctx, prog.code.data(), prog.code.size());
  out.rax = ctx.r[vsl(REG_RAX)];
  out.rdx = ctx.r[vsl(REG_RDX)];
  out.r8 = ctx.r[vsl(REG_R8)];
  return out;
}

using MaskFn = uint32_t (*)(const Case&);

static uint32_t mask_cf_of(const Case&) { return 0x03; }
static uint32_t mask_zf(const Case&) { return 0x04; }
static uint32_t mask_cf_zf(const Case&) { return 0x05; }
static uint32_t mask_none(const Case&) { return 0x00; }
static uint32_t mask_all5(const Case&) { return 0x1F; }

static uint32_t shift_mask(unsigned n, unsigned size, bool shlshr) {
  if (n == 0) return 0x1Du;
  if (n == 1) return 0x1Fu;
  if (shlshr && n >= size) return 0x1Cu;
  return 0x1Du;
}

static void diff_cases(const char* name, FnPtr fn, uintptr_t stop_addr,
                       const std::vector<Case>& cases, MaskFn mask,
                       SkipFn skip, uint64_t mutate_seed, size_t* dead_flags,
                       size_t* dead_dropped) {
  const uintptr_t start = reinterpret_cast<uintptr_t>(fn);
  if (stop_addr <= start) {
    ck(false, std::string(name) + ": invalid section range");
    return;
  }

  LiftOptions opt;
  opt.base_address = start;
  opt.name = name;
  opt.mutate_seed = mutate_seed;
  const LiftResult r = lift_x86_64(reinterpret_cast<const uint8_t*>(start),
                                   static_cast<size_t>(stop_addr - start), opt);
  ck(r.ok, std::string(name) + ": lift basarili (" + r.error + ")");
  if (!r.ok) {
    for (const UnsupportedInsn& u : r.unsupported) {
      std::printf("       desteklenmiyor: %#llx %-10s %s\n",
                  static_cast<unsigned long long>(u.address), u.mnemonic.c_str(),
                  u.reason.c_str());
    }
    return;
  }

  IRProgram prog = r.prog;
  ir_wrap_callable(prog);
  Asm a;
  const CodegenResult cg = ir_codegen(prog, a);
  ck(cg.ok, std::string(name) + ": bytecode uretildi (" + cg.error + ")");
  if (!cg.ok) return;
  if (dead_flags) *dead_flags = cg.dead_flags;
  if (dead_dropped) *dead_dropped = cg.dead_dropped;

  static uint64_t o[3];
  static uint64_t want[3];

  int bad = 0;
  int n = 0;
  for (const Case& cs : cases) {
    if (skip && skip(cs)) continue;

    o[0] = o[1] = o[2] = 0;
    fn(cs.a, cs.b, reinterpret_cast<uint64_t>(o), cs.d);
    want[0] = o[0];
    want[1] = o[1];
    want[2] = o[2];

    o[0] = o[1] = o[2] = 0;
    const VmOut got = vm_run_out(a, cg.entry_offset, cs.a, cs.b,
                                 reinterpret_cast<uint64_t>(o), cs.d, start);
    ++n;
    if (got.status != ST_HALT) {
      ck(false, std::string(name) + ": VM did not end with HALT (status=" +
                    std::to_string(got.status) + ")");
      ++bad;
      continue;
    }
    const uint32_t m = mask(cs);
    if (want[0] != o[0] || want[1] != o[1] || ((want[2] ^ o[2]) & m) != 0) {
      std::printf("       FAIL a=%#llx b=%#llx nat=(%#llx,%#llx,%#llx) "
                  "vm=(%#llx,%#llx,%#llx) mask=%#x\n",
                  static_cast<unsigned long long>(cs.a),
                  static_cast<unsigned long long>(cs.b),
                  static_cast<unsigned long long>(want[0]),
                  static_cast<unsigned long long>(want[1]),
                  static_cast<unsigned long long>(want[2]),
                  static_cast<unsigned long long>(o[0]),
                  static_cast<unsigned long long>(o[1]),
                  static_cast<unsigned long long>(o[2]), m);
      ++bad;
    }
  }
  if (bad == 0) {
    std::printf("  OK  %-12s %4d inputs, %zu x86 insns -> %zu bytes bytecode\n",
                name, n, r.decoded, cg.code_size);
  } else {
    std::printf("  FAIL %-12s %d/%d inputs failed\n", name, bad, n);
  }
  ck(bad == 0, std::string(name) + ": " + std::to_string(bad) + "/" +
                   std::to_string(n) + " inputs differ from native");
}

static void run_diff_out(const char* name, FnPtr fn, uintptr_t stop_addr,
                         const std::vector<Case>& cases, MaskFn mask,
                         SkipFn skip = nullptr,
                         size_t* dead_flags = nullptr,
                         size_t* dead_dropped = nullptr) {
  diff_cases(name, fn, stop_addr, cases, mask, skip, 0, dead_flags, dead_dropped);
}

static void run_diff_seeded(const char* name, FnPtr fn, uintptr_t stop_addr,
                            const std::vector<Case>& cases, MaskFn mask,
                            uint64_t mutate_seed) {
  diff_cases(name, fn, stop_addr, cases, mask, nullptr, mutate_seed, nullptr,
             nullptr);
}

static std::vector<Case> mk_shift_cases() {
  static const uint64_t vals[] = {
      0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0x8000, 0xffff, 0x123456789abcdefull,
      0x7fffffff, 0x80000000, 0xffffffff, 0x8000000000000000ull, ~0ull,
      0x1555555555555555ull, 0xaaaaaaaaaaaaaaaaull};
  std::vector<Case> v;
  for (uint64_t x : vals) {
    for (uint64_t cnt = 0; cnt <= 255; ++cnt) {
      v.push_back(Case{x, cnt, 0xdeadbeefull, 0});
    }
  }
  return v;
}

static void coverage(const char* name, FnPtr fn, uintptr_t stop_addr) {
  const uintptr_t start = reinterpret_cast<uintptr_t>(fn);
  if (stop_addr <= start) return;

  LiftOptions opt;
  opt.base_address = start;
  opt.name = name;

  const LiftResult r = lift_x86_64(reinterpret_cast<const uint8_t*>(start),
                                   static_cast<size_t>(stop_addr - start), opt);
  std::printf("  %-12s %2zu commands", name, r.decoded);
  if (r.unsupported.empty()) {
    std::printf("  -> tamami destekleniyor\n");
    return;
  }
  std::printf("  -> %zu desteklenmiyor:\n", r.unsupported.size());
  for (const UnsupportedInsn& u : r.unsupported) {
    std::printf("      %#llx  %-10s  %s\n",
                static_cast<unsigned long long>(u.address), u.mnemonic.c_str(),
                u.reason.c_str());
  }
}

alignas(4096) static uint8_t g_island_area[64 * 1024];

static bool island_area_exec() {
  const long ps = sysconf(_SC_PAGESIZE);
  void* p = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_island_area) &
                                     ~(static_cast<uintptr_t>(ps) - 1));
  return mprotect(p, sizeof(g_island_area), PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

struct Gated {
  Asm asmb;
  CodegenResult cg;
  std::vector<NativeIsland> islands;
  bool ok = false;
  std::string error;
  uint64_t image_base = 0;
};

static uint64_t gate_image_base() {
  static uint64_t base = 0;
  if (base == 0) {
    const uint64_t lo = std::min<uint64_t>(
        reinterpret_cast<uintptr_t>(g_island_area),
        reinterpret_cast<uintptr_t>(&hyda_vm_gate_leave));
    base = lo - 0x20000000ull;
  }
  return base;
}

static Gated gate_lift(const char* name, FnPtr fn, uintptr_t stop) {
  Gated g;
  const uintptr_t start = reinterpret_cast<uintptr_t>(fn);
  LiftOptions opt;
  opt.base_address = start;
  opt.image_base = gate_image_base();
  opt.name = name;
  const LiftResult r = lift_x86_64(reinterpret_cast<const uint8_t*>(start),
                                   static_cast<size_t>(stop - start), opt);
  if (!r.ok) { g.error = "lift: " + r.error; return g; }
  IRProgram prog = r.prog;
  ir_wrap_callable(prog);
  g.cg = ir_codegen(prog, g.asmb);
  if (!g.cg.ok) { g.error = "codegen: " + g.cg.error; return g; }
  g.islands = r.prog.natives;
  g.image_base = gate_image_base();
  g.ok = true;
  return g;
}

struct GatedCall {
  uint64_t ret = 0;
  uint32_t status = 0;
  uint64_t steps = 0;
  bool ok = false;
  std::string error;
};

static void gated_layout(const Gated& g, uint64_t* image_base,
                         uint32_t* first_rva, uint32_t* leave_rva) {
  const uint64_t island_base = reinterpret_cast<uintptr_t>(g_island_area);
  const uint64_t leave_addr = reinterpret_cast<uintptr_t>(&hyda_vm_gate_leave);

  *image_base = g.image_base;
  *first_rva = static_cast<uint32_t>(island_base - *image_base);
  *leave_rva = static_cast<uint32_t>(leave_addr - *image_base);
}

static std::vector<PlacedIsland> g_placed;
static uint64_t g_placed_image_base = 0;
static uint32_t g_placed_first_rva = 0;

// Seeding host XMM0 and calling save_simd must be one indivisible step, and the
// value must be read back in the same block as restore_simd.
extern "C" __attribute__((naked, noinline))
void simd_restore_store(uint64_t out, uint64_t restore_fn) {
  __asm__(".intel_syntax noprefix\n"
          "push rbx\n"
          "mov rbx, rdi\n"
          "mov rax, rsi\n"
          "vxorps ymm0, ymm0, ymm0\n"
          "call rax\n"
          "vmovups [rbx], ymm0\n"
          "pop rbx\n"
          "ret\n"
          ".att_syntax prefix\n");
}

extern "C" __attribute__((naked, noinline))
void simd_seed_ymm(const void* v, uint64_t save_fn) {
  __asm__(".intel_syntax noprefix\n"
          "sub rsp, 8\n"
          "vmovups ymm0, [rdi]\n"
          "call rsi\n"
          "add rsp, 8\n"
          "ret\n"
          ".att_syntax prefix\n");
}

extern "C" __attribute__((naked, noinline))
void simd_seed_xmm0(const float* v, uint64_t save_fn) {
  __asm__(".intel_syntax noprefix\n"
          "sub rsp, 8\n"
          "movss xmm0, [rdi]\n"
          "call rsi\n"
          "add rsp, 8\n"
          "ret\n"
          ".att_syntax prefix\n");
}

extern "C" __attribute__((naked, noinline))
void simd_restore_read_xmm0(uint64_t restore_fn, float* out) {
  __asm__(".intel_syntax noprefix\n"
          "push rbx\n"
          "mov rbx, rsi\n"
          "mov rax, rdi\n"
          "call rax\n"
          "movss [rbx], xmm0\n"
          "pop rbx\n"
          "ret\n"
          ".att_syntax prefix\n");
}

static GatedCall vm_run_gated(Gated& g, uint64_t a0, uint64_t a1, uint64_t a2,
                              uint64_t a3, bool capture_fp = true,
                              float* out_xmm0 = nullptr) {
  GatedCall out;
  uint64_t image_base = 0;
  uint32_t first_rva = 0, leave_rva = 0;
  gated_layout(g, &image_base, &first_rva, &leave_rva);

  std::string err;

  const std::vector<uint32_t> leave_rvas{leave_rva};
  const std::vector<PlacedIsland> placed =
      place_islands(g.islands, first_rva, leave_rvas, image_base, &err);
  if (placed.size() != g.islands.size()) { out.error = err; return out; }
  if (g.cg.native_refs.size() != g.islands.size()) {
    out.error = "NATIVE_GATE reference count != island count";
    return out;
  }
  g_placed = placed;
  g_placed_image_base = image_base;
  g_placed_first_rva = first_rva;

  std::memset(g_island_area, 0xCC, sizeof(g_island_area));
  for (const PlacedIsland& p : placed) {
    std::memcpy(g_island_area + (p.rva - first_rva), p.bytes.data(), p.bytes.size());

    if (!p.header.empty()) {
      std::memcpy(g_island_area + (p.rva - first_rva) - hyda::HYDA_ISLAND_SIZE,
                  p.header.data(), p.header.size());
    }

    if (p.decoy_rva != 0 && !p.decoy.empty()) {
      std::memcpy(g_island_area + (p.decoy_rva - first_rva), p.decoy.data(),
                  p.decoy.size());
    }
  }
  for (const NativeRef& ref : g.cg.native_refs) {
    const uint32_t rva = placed[ref.island].rva;
    std::memcpy(&g.asmb.code[ref.rva_offset], &rva, 4);
  }

  alignas(64) static uint8_t stack[1 << 20];
  VMContext ctx;

  const uint64_t top =
      reinterpret_cast<uintptr_t>(stack) + sizeof(stack) - 64;
  vm_init(ctx, top);
  ctx.max_steps = 50000000;
  ctx.image_base = image_base;
  ctx.r[vsl(REG_RDI)] = a0;
  ctx.r[vsl(REG_RSI)] = a1;
  ctx.r[vsl(REG_RDX)] = a2;
  ctx.r[vsl(REG_RCX)] = a3;
  vm_set_entry(ctx, g.cg.entry_offset);

  if (capture_fp) hyda_vm_save_simd();
  out.status = vm_exec(ctx, g.asmb.code.data(), g.asmb.code.size());
  if (out_xmm0 != nullptr) {
    simd_restore_read_xmm0(reinterpret_cast<uint64_t>(&hyda_vm_restore_simd), out_xmm0);
  } else {
    hyda_vm_restore_simd();
  }
  out.ret = ctx.r[vsl(REG_RAX)];
  out.steps = ctx.steps;
  out.ok = true;
  return out;
}

static VMContext* g_probe_ctx2 = nullptr;
static void* g_probe_island2 = nullptr;
static uint64_t g_probe_depth_before = 0;
static uint64_t g_probe_depth_after = 0;
static uint64_t g_probe_leaf_rsp = 0;

static void seal_manual_island(uint8_t* area, size_t area_off, size_t len,
                                uint32_t idx, uint64_t image_base) {
  const uintptr_t addr = reinterpret_cast<uintptr_t>(area + area_off);
  const uint32_t rva = static_cast<uint32_t>(addr - image_base);
  hyda::IslandHeader ih;
  ih.magic = hyda::island_magic();
  ih.size = static_cast<uint32_t>(len);
  ih.salt = hyda::island_salt_for(idx, rva);
  ih.flags = 0;
  ih.refs = 0;
  ih.import_index = 0;
  ih.reserved2 = 0;
  std::memcpy(area + area_off - hyda::HYDA_ISLAND_SIZE, &ih, sizeof(ih));
  hyda::island_encrypt(area + area_off, static_cast<uint32_t>(len),
                       hyda::island_key_for(ih.salt, rva));
}

static void hyda_nested_probe() {
  g_probe_depth_before = vm_gate_depth();
  hyda_vm_gate_enter(g_probe_ctx2, g_probe_island2);
  g_probe_depth_after = vm_gate_depth();
}

static void gate_section() {
  if (!island_area_exec()) {
    ck(false, "island area could not be made RWX (mprotect)");
    return;
  }

  {
    Gated g = gate_lift("f_sse", f_sse, reinterpret_cast<uintptr_t>(__stop_hyda_f_sse));
    ck(g.ok, std::string("f_sse: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;

    ck(g.islands.size() == 0, "f_sse: expected 0 native islands (fully virtualized), got: " +
                                  std::to_string(g.islands.size()));
    const float xs[] = {0.0f, 1.5f, -3.25f, 1e30f, 1e-30f};
    const float ys[] = {0.0f, 0.5f, -2.0f, 1e30f, -1e-30f};
    int bad = 0, n = 0;
    for (float x : xs) {
      for (float y : ys) {
        float in[2] = {x, y};
        float on = 0.0f, ov = 0.0f;
        const uint64_t rn = f_sse(reinterpret_cast<uint64_t>(in),
                                  reinterpret_cast<uint64_t>(in + 1),
                                  reinterpret_cast<uint64_t>(&on), 0);
        GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(in),
                                    reinterpret_cast<uint64_t>(in + 1),
                                    reinterpret_cast<uint64_t>(&ov), 0);
        if (!gr.ok) { ck(false, std::string("f_sse: gated kosum (") + gr.error + ")"); return; }
        ++n;
        if (gr.status != ST_HALT || gr.ret != rn || ov != on) ++bad;
      }
    }
    ck(bad == 0, "f_sse: native == VM");
    std::printf("  %s  f_sse        %zu islands, %d inputs\n", bad ? "FAIL" : "OK ",
                g.islands.size(), n);
  }

  {
    Gated g = gate_lift("f_sse_cmp", f_sse_cmp,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_cmp));
    ck(g.ok, std::string("f_sse_cmp: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    const float xs[] = {1.0f, 2.0f, -1.0f, 0.0f, 1e30f, -1e30f};
    const float ys[] = {0.0f, 2.0f, -1.0f, 1.0f, 1e30f, 1e30f};
    int bad = 0, n = 0;
    for (float x : xs) {
      for (float y : ys) {
        const uint64_t rn = f_sse_cmp(reinterpret_cast<uint64_t>(&x),
                                      reinterpret_cast<uint64_t>(&y), 0, 0);
        GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(&x),
                                    reinterpret_cast<uint64_t>(&y), 0, 0);
        if (!gr.ok) { ck(false, std::string("f_sse_cmp: gated (") + gr.error + ")"); return; }
        ++n;
        if (gr.status != ST_HALT || gr.ret != rn) ++bad;
      }
    }
    ck(bad == 0, "f_sse_cmp: flags carried through the gate");
    std::printf("  %s  f_sse_cmp    %d inputs (ZF/CF propagated)\n", bad ? "FAIL" : "OK ", n);
  }

  {
    Gated g = gate_lift("f_sse4", f_sse4, reinterpret_cast<uintptr_t>(__stop_hyda_f_sse4));
    ck(g.ok, std::string("f_sse4: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 0, "f_sse4: expected 0 native islands (packed SSE virtualized), got: " +
                                  std::to_string(g.islands.size()));
    const float a[4] = {1.5f, -2.25f, 3.0f, -0.5f};
    const float b[4] = {0.25f, 0.75f, -1.0f, 2.0f};
    float on[4] = {0, 0, 0, 0}, ov[4] = {0, 0, 0, 0};
    const uint64_t rn = f_sse4(reinterpret_cast<uint64_t>(a),
                               reinterpret_cast<uint64_t>(b),
                               reinterpret_cast<uint64_t>(on), 0);
    GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(a),
                                reinterpret_cast<uint64_t>(b),
                                reinterpret_cast<uint64_t>(ov), 0);
    bool same = gr.ok && gr.status == ST_HALT && gr.ret == rn;
    for (int i = 0; i < 4; ++i) same = same && (ov[i] == on[i]);
    ck(same, "f_sse4: native == VM (paketli toplama)");
    std::printf("  %s  f_sse4       0 islands (movupd/pxor/addps virtualized)\n", same ? "OK " : "FAIL");
  }

  {
    Gated g = gate_lift("f_sse2", f_sse2,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_sse2));
    ck(g.ok, std::string("f_sse2: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 0,
       "f_sse2: expected 0 native islands, got: " + std::to_string(g.islands.size()));
    alignas(16) static const uint8_t patterns[4][16] = {
        {0x00, 0x01, 0x7f, 0x80, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0},
        {0x80, 0x80, 0x80, 0x80, 0x01, 0x02, 0x03, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff},
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };
    int bad = 0, n = 0;
    for (int ia = 0; ia < 4; ++ia) {
      for (int ib = 0; ib < 4; ++ib) {
        const uint8_t* pa = patterns[ia];
        const uint8_t* pb = patterns[ib];
        uint8_t on[16] = {}, ov[16] = {};
        const uint64_t rn = f_sse2(reinterpret_cast<uint64_t>(pa),
                                   reinterpret_cast<uint64_t>(pb),
                                   reinterpret_cast<uint64_t>(on), 0);
        GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(pa),
                                    reinterpret_cast<uint64_t>(pb),
                                    reinterpret_cast<uint64_t>(ov), 0);
        if (!gr.ok) { ck(false, std::string("f_sse2: gated (") + gr.error + ")"); return; }
        ++n;
        if (gr.status != ST_HALT || gr.ret != rn) ++bad;
        for (int i = 0; i < 16; ++i) if (on[i] != ov[i]) ++bad;
      }
    }
    ck(bad == 0, "f_sse2: native == VM (tamsayi SIMD)");
    std::printf("  %s  f_sse2      %d inputs (paddsb/pmullw/pcmpeqd/psllq/...)\n",
                bad ? "FAIL" : "OK ", n);
  }

  {
    Gated g = gate_lift("f_avx", f_avx,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_avx));
    ck(g.ok, std::string("f_avx: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 0,
       "f_avx: expected 0 native islands, got: " + std::to_string(g.islands.size()));
    const float a[4] = {1.5f, -2.25f, 3.0f, -0.5f};
    const float b[4] = {0.25f, 0.75f, -1.0f, 2.0f};
    float on[4] = {}, ov[4] = {};
    const uint64_t rn = f_avx(reinterpret_cast<uint64_t>(a),
                              reinterpret_cast<uint64_t>(b),
                              reinterpret_cast<uint64_t>(on), 0);
    GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(a),
                                reinterpret_cast<uint64_t>(b),
                                reinterpret_cast<uint64_t>(ov), 0);
    bool same = gr.ok && gr.status == ST_HALT && gr.ret == rn;
    for (int i = 0; i < 4; ++i) same = same && (on[i] == ov[i]);
    ck(same, "f_avx: native == VM (VEX 3-operand)");
    std::printf("  %s  f_avx        0 islands (vaddps/vmulps/vsubps/vxorps)\n",
                same ? "OK " : "FAIL");
  }

  {
    Gated g = gate_lift("f_avx256", f_avx256,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_avx256));
    ck(g.ok, std::string("f_avx256: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 0,
       "f_avx256: expected 0 native islands, got: " + std::to_string(g.islands.size()));
    alignas(32) const float a[8] = {1.5f, -2.25f, 3.0f, -0.5f,
                                    7.25f, -8.5f, 0.125f, 42.0f};
    alignas(32) const float b[8] = {0.25f, 0.75f, -1.0f, 2.0f,
                                    1.0f, -3.0f, 16.0f, 0.5f};
    alignas(32) float on[8] = {}, ov[8] = {};
    const uint64_t rn = f_avx256(reinterpret_cast<uint64_t>(a),
                                 reinterpret_cast<uint64_t>(b),
                                 reinterpret_cast<uint64_t>(on), 0);
    GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(a),
                                reinterpret_cast<uint64_t>(b),
                                reinterpret_cast<uint64_t>(ov), 0);
    bool same = gr.ok && gr.status == ST_HALT && gr.ret == rn;
    for (int i = 0; i < 8; ++i) same = same && (on[i] == ov[i]);
    ck(same, "f_avx256: native == VM (256-bit YMM)");
    std::printf("  %s  f_avx256    0 islands (ymm: vaddps/vmulps/vpsubd/vpaddd)\n",
                same ? "OK " : "FAIL");
  }

  {
    Gated g = gate_lift("f_avx256_gate", f_avx256_gate,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_avx256_gate));
    ck(g.ok, std::string("f_avx256_gate: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() >= 1,
       "f_avx256_gate: expected at least 1 island (phaddd), got: " + std::to_string(g.islands.size()));
    if (!hyda::fp_supports_avx()) {
      std::printf("  SKIP f_avx256_gate: no AVX on this host\n");
    } else {
      alignas(32) const float a[8] = {1.5f, -2.25f, 3.0f, -0.5f,
                                      7.25f, -8.5f, 0.125f, 42.0f};
      alignas(32) const float b[8] = {0.25f, 0.75f, -1.0f, 2.0f,
                                      1.0f, -3.0f, 16.0f, 0.5f};
      alignas(32) float on[8] = {}, ov[8] = {};
      const uint64_t rn = f_avx256_gate(reinterpret_cast<uint64_t>(a),
                                        reinterpret_cast<uint64_t>(b),
                                        reinterpret_cast<uint64_t>(on), 0);
      GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(a),
                                  reinterpret_cast<uint64_t>(b),
                                  reinterpret_cast<uint64_t>(ov), 0);
      bool same = gr.ok && gr.status == ST_HALT && gr.ret == rn;
      for (int i = 0; i < 8; ++i) same = same && (on[i] == ov[i]);
      if (!same) {
        std::printf("  diag f_avx256_gate: status=%u ret native=%#llx vm=%#llx\n",
                    gr.status, static_cast<unsigned long long>(rn),
                    static_cast<unsigned long long>(gr.ret));
        for (int i = 0; i < 8; ++i)
          std::printf("    [%d] native=%g vm=%g\n", i,
                      static_cast<double>(on[i]), static_cast<double>(ov[i]));
      }
      ck(same, "f_avx256_gate: gate carries YMM correctly (native == VM)");
      std::printf("  %s  f_avx256_gate %zu islands (YMM gate transfer)\n",
                  same ? "OK " : "FAIL", g.islands.size());
    }
  }

  {
    Gated g = gate_lift("f_sse_cvt", f_sse_cvt,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_cvt));
    ck(g.ok, std::string("f_sse_cvt: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    const int64_t ins[] = {0, 1, -1, 123456789, -2147483648LL, 2147483647LL,
                           9007199254740993LL, -9007199254740993LL};
    const float ms[] = {1.0f, -0.5f, 3.25f, 0.001f, -7.5f};
    int bad = 0, n = 0;
    for (int64_t v : ins) {
      for (float m : ms) {
        uint64_t on8 = 0, ov8 = 0;
        float m2 = m;
        const uint64_t rn = f_sse_cvt(static_cast<uint64_t>(v),
                                      reinterpret_cast<uint64_t>(&m2),
                                      reinterpret_cast<uint64_t>(&on8), 0);
        GatedCall gr = vm_run_gated(g, static_cast<uint64_t>(v),
                                    reinterpret_cast<uint64_t>(&m2),
                                    reinterpret_cast<uint64_t>(&ov8), 0);
        if (!gr.ok) { ck(false, std::string("f_sse_cvt: gated (") + gr.error + ")"); return; }
        ++n;
        if (gr.status != ST_HALT || gr.ret != rn || ov8 != on8) ++bad;
      }
    }
    ck(bad == 0, "f_sse_cvt: native == VM (cvtsi2ss/cvttss2si/movd/pshufd)");
    std::printf("  %s  f_sse_cvt    %d inputs (conversion + pshufd)\n", bad ? "FAIL" : "OK ", n);
  }

  {
    Gated g = gate_lift("f_sse_rip", f_sse_rip,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_rip));
    ck(g.ok, std::string("f_sse_rip: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 0, "f_sse_rip: expected 0 native islands (RIP-relative virtualized), got: " +
                                  std::to_string(g.islands.size()));
    float on = 0.0f, ov = 0.0f;
    const uint64_t rn = f_sse_rip(0, 0, reinterpret_cast<uint64_t>(&on), 0);
    GatedCall gr = vm_run_gated(g, 0, 0, reinterpret_cast<uint64_t>(&ov), 0);
    ck(gr.ok && gr.status == ST_HALT && gr.ret == rn && ov == on,
       "f_sse_rip: native == VM (image-relative RVA)");
    std::printf("  %s  f_sse_rip    0 islands (RIP-relative constant)\n",
                (gr.ok && ov == on) ? "OK " : "FAIL");
  }

  {
    Gated g = gate_lift("f_x87", f_x87, reinterpret_cast<uintptr_t>(__stop_hyda_f_x87));
    ck(g.ok, std::string("f_x87: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    const double vals[] = {0.0, 1.5, -2.75, 1e300, -1e-300};
    int bad = 0, n = 0;
    for (double v : vals) {
      double dn = v, dv = v;
      const uint64_t rn = f_x87(reinterpret_cast<uint64_t>(&dn), 0, 0, 0);
      GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(&dv), 0, 0, 0);
      if (!gr.ok) { ck(false, std::string("f_x87: gated (") + gr.error + ")"); return; }
      ++n;
      if (gr.status != ST_HALT || gr.ret != rn || dv != dn) ++bad;
    }
    ck(bad == 0, "f_x87: native == VM (x87 yigini korunuyor)");
    std::printf("  %s  f_x87        %d inputs (x87 stack)\n", bad ? "FAIL" : "OK ", n);
  }

  {
    Gated g = gate_lift("f_cpuid", f_cpuid, reinterpret_cast<uintptr_t>(__stop_hyda_f_cpuid));
    ck(g.ok, std::string("f_cpuid: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    uint64_t on[4] = {0, 0, 0, 0}, ov[4] = {0, 0, 0, 0};
    const uint64_t rn = f_cpuid(reinterpret_cast<uint64_t>(on), 0, 0, 0);
    GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(ov), 0, 0, 0);
    ck(gr.ok, std::string("f_cpuid: gated kosum (") + gr.error + ")");
    if (gr.ok) {
      const bool same = std::memcmp(on, ov, sizeof(on)) == 0;
      ck(same, "f_cpuid: eax/ebx/ecx/edx restored to ctx");
      ck(gr.ret == rn, "f_cpuid: rax esit");
      std::printf("  %s  f_cpuid      closed register writes\n", same ? "OK " : "FAIL");
    }
  }

  {
    Gated g = gate_lift("f_icall", f_icall, reinterpret_cast<uintptr_t>(__stop_hyda_f_icall));
    ck(g.ok, std::string("f_icall: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 1, "f_icall: expected 1 native island (indirect call)");
    ck(g.islands.size() == 1 && g.islands[0].disp_off >= 0,
       "f_icall: RIP-relative operand found in the island");
    int bad = 0, n = 0;
    for (uint64_t a : {0ull, 5ull, ~0ull}) {
      for (uint64_t b : {0ull, 7ull, 1000ull}) {
        const uint64_t rn = f_icall(a, b, 0, 0);
        GatedCall gr = vm_run_gated(g, a, b, 0, 0);
        if (!gr.ok) { ck(false, std::string("f_icall: gated (") + gr.error + ")"); return; }
        ++n;
        if (gr.status != ST_HALT || gr.ret != rn) ++bad;
      }
    }
    ck(bad == 0, "f_icall: indirect call + RIP-relative fixup correct");
    std::printf("  %s  f_icall      %d inputs (import call)\n", bad ? "FAIL" : "OK ", n);
  }

  {
    Gated g = gate_lift("f_dcall", f_dcall,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_dcall));
    ck(g.ok, std::string("f_dcall: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 1 && g.islands[0].disp_off >= 0,
       "f_dcall: detected 1 island + rel32 field (island=" +
           std::to_string(g.islands.size()) + ")");
    const uint64_t rn = f_dcall(0, 0, 0, 0);
    const GatedCall gr = vm_run_gated(g, 0, 0, 0, 0);
    ck(gr.ok, std::string("f_dcall: gated kosum (") + gr.error + ")");
    if (gr.ok) {
      ck(gr.status == ST_HALT && gr.ret == rn, "f_dcall: native == VM");
      ck(gr.ret == 8, "f_dcall: RSP alignment at call matches the ABI (==8)");
      std::printf("  %s  f_dcall      direct call, RSP%%16=%llu\n",
                  (gr.ret == rn && gr.ret == 8) ? "OK " : "FAIL",
                  static_cast<unsigned long long>(gr.ret));
    }
  }

  {
    Gated g = gate_lift("f_xmmarg", f_xmmarg,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_xmmarg));
    ck(g.ok, std::string("f_xmmarg: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    const float vals[] = {0.0f, 3.25f, -1.5f, 1e20f};
    int bad = 0, n = 0;
    for (float v : vals) {
      float arg = v, on = 0.0f, ov = 0.0f, rn = 0.0f, rv = 0.0f;
      test_call_xmm0(reinterpret_cast<uint64_t>(f_xmmarg),
                     reinterpret_cast<uint64_t>(&on),
                     reinterpret_cast<uint64_t>(&arg),
                     reinterpret_cast<uint64_t>(&rn));
      simd_seed_xmm0(&arg, reinterpret_cast<uint64_t>(&hyda_vm_save_simd));
      GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(&ov), 0, 0, 0, false,
                                  &rv);
      if (!gr.ok) { ck(false, std::string("f_xmmarg: gated (") + gr.error + ")"); return; }
      ++n;
      if (gr.status != ST_HALT || ov != on || rv != rn || gr.ret != 7) ++bad;
    }
    ck(bad == 0, "f_xmmarg: XMM argument and XMM return value carried");
    std::printf("  %s  f_xmmarg     %d inputs (XMM arg/return)\n", bad ? "FAIL" : "OK ", n);
  }

  {
    Gated g = gate_lift("f_tail", f_tail,
                        reinterpret_cast<uintptr_t>(__stop_hyda_f_tail));
    ck(g.ok, std::string("f_tail: lift + kod uretimi (") + g.error + ")");
    if (!g.ok) return;
    ck(g.islands.size() == 1, "f_tail: expected 1 island (tail call), got: " +
                                  std::to_string(g.islands.size()));
    ck(g.islands.size() == 1 && g.islands[0].tail_call,
       "f_tail: island marked as a tail call");
    ck(g.islands.size() == 1 && g.islands[0].disp_off >= 0,
       "f_tail: island carries a rel32 target");
    int bad = 0, n = 0;
    for (uint64_t x : {0ull, 1ull, 41ull, ~0ull - 1}) {
      const uint64_t rn = f_tail(x, 0, 0, 0);
      GatedCall gr = vm_run_gated(g, x, 0, 0, 0);
      if (!gr.ok) { ck(false, std::string("f_tail: gated kosum (") + gr.error + ")"); return; }
      ++n;
      if (gr.status != ST_HALT || gr.ret != rn) ++bad;
    }
    ck(bad == 0, "f_tail: tail-call result native == VM (return value carried)");
    std::printf("  %s  f_tail       tail call (exit stitching), %d inputs\n",
                bad ? "FAIL" : "OK ", n);
  }

  {
    alignas(64) static uint8_t st1[1 << 16], st2[1 << 16];

    const uintptr_t leaf = reinterpret_cast<uintptr_t>(g_island_area) + 64;
    const uintptr_t mid = leaf + 64;
    const uintptr_t leave = reinterpret_cast<uintptr_t>(&hyda_vm_gate_leave);

    g_probe_leaf_rsp = 0;
    g_probe_depth_before = 0;
    g_probe_depth_after = 0;
    g_probe_island2 = reinterpret_cast<void*>(leaf);

    {
      uint8_t* p = g_island_area + 64;
      const int32_t d = static_cast<int32_t>(
          reinterpret_cast<uintptr_t>(&g_probe_leaf_rsp) - (leaf + 7));
      const int32_t j = static_cast<int32_t>(leave - (leaf + 12));
      p[0] = 0x48; p[1] = 0x89; p[2] = 0x25;
      std::memcpy(p + 3, &d, 4);
      p[7] = 0xE9;
      std::memcpy(p + 8, &j, 4);
      seal_manual_island(g_island_area, 64, 12, 0, 0);
    }
    {
      uint8_t* p = g_island_area + 128;
      const int32_t c = static_cast<int32_t>(
          reinterpret_cast<uintptr_t>(&hyda_nested_probe) - (mid + 5));
      const int32_t j = static_cast<int32_t>(leave - (mid + 10));
      p[0] = 0xE8;
      std::memcpy(p + 1, &c, 4);
      p[5] = 0xE9;
      std::memcpy(p + 6, &j, 4);
      seal_manual_island(g_island_area, 128, 10, 1, 0);
    }

    VMContext c1, c2;
    vm_init(c1, reinterpret_cast<uint64_t>(st1) + sizeof(st1) - 64);
    vm_init(c2, reinterpret_cast<uint64_t>(st2) + sizeof(st2) - 64);
    c1.r[vsl(REG_RBX)] = 0x1111111111111111ull;
    c2.r[vsl(REG_RBX)] = 0x2222222222222222ull;
    const uint64_t rsp1 = c1.r[vsl(REG_RSP)], rsp2 = c2.r[vsl(REG_RSP)];
    g_probe_ctx2 = &c2;

    hyda_vm_gate_enter(&c1, reinterpret_cast<void*>(mid));

    const bool depths_ok = g_probe_depth_before == 1 && g_probe_depth_after == 1 &&
                           vm_gate_depth() == 0;
    const bool regs_ok = c1.r[vsl(REG_RBX)] == 0x1111111111111111ull &&
                         c2.r[vsl(REG_RBX)] == 0x2222222222222222ull;
    const bool stack_ok = c1.r[vsl(REG_RSP)] == rsp1 && c2.r[vsl(REG_RSP)] == rsp2;
    const bool own_stack = g_probe_leaf_rsp > reinterpret_cast<uint64_t>(st2) &&
                           g_probe_leaf_rsp <=
                               reinterpret_cast<uint64_t>(st2) + sizeof(st2);
    ck(depths_ok, "nested gate: depth 0->1->2->1->0");
    ck(regs_ok, "nested gate: guest register files of the two layers are separate");
    ck(stack_ok, "nested gate: each layer's guest RSP preserved (call/ret balanced)");
    ck(own_stack, "nested gate: inner layer used its own guest stack");
    std::printf("  %s  nested gate  depth 1->2->1, separate stack (rsp=%llx)\n",
                (depths_ok && regs_ok && stack_ok && own_stack) ? "OK " : "FAIL",
                static_cast<unsigned long long>(g_probe_leaf_rsp));
  }
}

static void island_crypt_section() {
  Gated g = gate_lift("f_sse_mix", f_sse_mix,
                      reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_mix));
  ck(g.ok, std::string("f_sse_mix: lift + kod uretimi (") + g.error + ")");
  if (!g.ok) return;

  float in[4] = {1.5f, -2.25f, 3.0f, -0.5f};
  float on[4] = {0, 0, 0, 0}, ov[4] = {0, 0, 0, 0};
  const uint64_t want =
      f_sse_mix(reinterpret_cast<uint64_t>(in), 0,
                reinterpret_cast<uint64_t>(on), 0);

  GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(in), 0,
                              reinterpret_cast<uint64_t>(ov), 0);
  bool same4 = true;
  for (int i = 0; i < 4; ++i) same4 = same4 && (ov[i] == on[i]);
  ck(gr.ok && gr.status == ST_HALT && gr.ret == want && same4,
     "f_sse_mix: result with encrypted islands native == VM");
  if (!gr.ok) return;

  const std::vector<IslandPlan> plan =
      plan_islands(g.islands, g_placed_first_rva);
  int n = 0, bad_hdr = 0, bad_tail = 0, bad_same = 0;
  for (size_t ai = 0; ai < g_placed.size(); ++ai) {
    const PlacedIsland& p = g_placed[ai];
    const NativeIsland& isl = g.islands[ai];
    const size_t off = static_cast<size_t>(p.rva - g_placed_first_rva);
    if (off < hyda::HYDA_ISLAND_SIZE) { ++bad_hdr; continue; }
    const hyda::IslandHeader* h = reinterpret_cast<const hyda::IslandHeader*>(
        g_island_area + off - hyda::HYDA_ISLAND_SIZE);
    if (!hyda::island_header_check(*h)) { ++bad_hdr; continue; }

    std::vector<uint8_t> plain(h->size);
    std::memcpy(plain.data(), g_island_area + off, h->size);
    hyda::island_decrypt(plain.data(), h->size,
                         hyda::island_key_for(h->salt, p.rva));

    const size_t head = isl.tail_call ? 12u : 0u;
    const size_t tail_off = head + isl.bytes.size() + plan[ai].junk;
    if (tail_off + 5 > plain.size() || plain[tail_off] != 0xE9) ++bad_tail;

    if (std::memcmp(plain.data(), g_island_area + off, h->size) == 0) {
      ++bad_same;
    }
    ++n;
  }
  ck(n == static_cast<int>(g.islands.size()) && bad_hdr == 0,
     "islands: headers valid (magic/size) and count correct");
  ck(bad_tail == 0, "islands: decrypted bytes are valid code (tail E9 = jmp leave)");
  ck(bad_same == 0, "islands: not plaintext (encrypted) ");

  std::vector<uint8_t> before(g_island_area, g_island_area + sizeof(g_island_area));
  GatedCall gr2 = vm_run_gated(g, reinterpret_cast<uint64_t>(in), 0,
                               reinterpret_cast<uint64_t>(ov), 0);
  bool same4b = true;
  for (int i = 0; i < 4; ++i) same4b = same4b && (ov[i] == on[i]);
  ck(gr2.ok && gr2.status == ST_HALT && gr2.ret == want && same4b,
     "f_sse_mix: second run gives the same result");
  ck(std::memcmp(before.data(), g_island_area, sizeof(g_island_area)) == 0,
     "islands: re-encrypted after the run (re-encryption works)");

  {

    const size_t off = static_cast<size_t>(g_placed[0].rva - g_placed_first_rva);
    hyda::IslandHeader* h = reinterpret_cast<hyda::IslandHeader*>(
        g_island_area + off - hyda::HYDA_ISLAND_SIZE);
    const uint32_t saved = h->magic;
    h->magic ^= 0xFFFFFFFFu;
    VMContext ctx;
    alignas(64) static uint8_t stk[1 << 16];
    vm_init(ctx, reinterpret_cast<uint64_t>(stk) + sizeof(stk) - 64);
    ctx.image_base = g_placed_image_base;
    hyda_vm_gate_enter(&ctx, reinterpret_cast<void*>(g_island_area + off));
    const bool refused = (ctx.status == ST_FAULT);
    h->magic = saved;
    ck(refused, "bad island header: gate did NOT open (ST_FAULT), no silent continue");
  }

  std::printf("  %s  island crypt  %zu islands: encrypted, decrypted valid, "
              "re-encryption works\n",
              "OK ", static_cast<size_t>(n));
}

static void island_layout_section() {
  Gated g = gate_lift("f_sse_mix", f_sse_mix,
                      reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_mix));
  ck(g.ok, std::string("f_sse_mix: lift + kod uretimi (") + g.error + ")");
  if (!g.ok) return;

  uint64_t image_base = 0;
  uint32_t first_rva = 0, leave_rva = 0;
  gated_layout(g, &image_base, &first_rva, &leave_rva);
  const std::vector<uint32_t> leave_rvas{leave_rva};
  const std::vector<IslandPlan> plan = plan_islands(g.islands, first_rva);

  std::vector<int> seen(g.islands.size(), 0);
  for (size_t i = 0; i < plan.size(); ++i) {
    ck(plan[i].order < plan.size(), "island order uses valid indices");
    seen[plan[i].order] = 1;
  }
  bool all_seen = true;
  for (int v : seen) all_seen = all_seen && (v == 1);
  ck(all_seen, "island order is a permutation (each island once)");

  {
    std::vector<NativeIsland> dummy(4);
    int non_identity = 0;
    for (uint32_t rva = 0x1000; rva <= 0x8000; rva += 0x1000) {
      const std::vector<IslandPlan> p = plan_islands(dummy, rva);
      bool id = true;
      for (size_t i = 0; i < p.size(); ++i) {
        if (p[i].order != i) id = false;
      }
      if (!id) ++non_identity;
    }
    ck(non_identity > 0,
       "island order shuffled by seed (different seed -> different order)");
  }

  unsigned pads = 0, junks = 0;
  for (const IslandPlan& p : plan) {
    if (p.pad > 0) ++pads;
    if (p.junk > 0) ++junks;
  }
  ck(pads > 0, "padding/decoy bytes present between islands");
  ck(junks > 0, "junk nop variants before the tail");

  std::string err;
  const std::vector<PlacedIsland> placed =
      place_islands(g.islands, first_rva, leave_rvas, image_base, &err);
  ck(!placed.empty() && placed.size() == g.islands.size(),
     std::string("yerlesim: ") + (placed.empty() ? err : "tamam"));
  if (!placed.empty()) {
    bool offsets_ok = true;
    uint32_t expect = first_rva + hyda::HYDA_ISLAND_SIZE;

    uint32_t min_rva = placed[0].rva;
    for (const PlacedIsland& p : placed) {
      if (p.rva < min_rva) min_rva = p.rva;
    }

    for (size_t i = 0; i < placed.size(); ++i) {
      if (plan[i].order == 0 && placed[i].rva != expect) offsets_ok = false;
    }
    ck(offsets_ok, "island offsets match the plan (shuffled order)");
    ck(min_rva == expect, "ilk adanin konumu planla eslesiyor");
  }

  std::printf("  %s  island layout %zu islands: shuffled, %u with gap, "
              "%u with junk nop\n",
              "OK ", plan.size(), pads, junks);
}

static void island_meta_section() {
  Gated g = gate_lift("f_sse_mix", f_sse_mix,
                      reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_mix));
  ck(g.ok, std::string("f_sse_mix: lift + kod uretimi (") + g.error + ")");
  if (!g.ok) return;

  int same = 0, diff = 0, prefixed = 0;
  for (const NativeIsland& isl : g.islands) {

    const size_t orig_size =
        static_cast<size_t>(static_cast<int>(isl.bytes.size()) - isl.meta_delta);
    if (orig_size == 0 || orig_size > isl.bytes.size()) { ++same; continue; }
    const uint8_t* src = reinterpret_cast<const uint8_t*>(isl.orig_addr);
    const std::vector<uint8_t> orig(src, src + orig_size);
    if (isl.meta_delta > 0 && isl.bytes.size() > orig_size) {

      const std::vector<uint8_t> tail(isl.bytes.end() - orig_size,
                                      isl.bytes.end());
      if (tail == orig) {
        ++prefixed;
        ++diff;
        continue;
      }
    }
    if (isl.bytes == orig) {
      ++same;
    } else {
      ++diff;
    }
  }
  ck(diff > 0, "island bytes are not the original compiler output (metamorphic)");
  ck(same == 0, "no island byte remained byte-identical to the original");
  ck(prefixed > 0, "at least one island re-encoded with a legacy segment prefix");
  std::printf("  %s  island meta  %zu islands: %u bytes differ (prefix: %u)\n", "OK ",
              g.islands.size(), static_cast<unsigned>(diff),
              static_cast<unsigned>(prefixed));
}

static void island_mut_section() {

  Gated g = gate_lift("f_sse_mix", f_sse_mix,
                      reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_mix));
  ck(g.ok, std::string("8s: f_sse_mix lift + kod uretimi (") + g.error + ")");
  if (!g.ok) return;

  const float a[4] = {1.5f, -2.25f, 3.0f, -0.5f};
  const float b[4] = {0.25f, 0.75f, -1.0f, 2.0f};
  float on[4] = {0, 0, 0, 0};
  float ov[4] = {0, 0, 0, 0};
  const uint64_t want = f_sse_mix(reinterpret_cast<uint64_t>(a), 0,
                                  reinterpret_cast<uint64_t>(on), 0);

  int bad_k = 0;
  for (uint32_t k = 0; k < 4; ++k) {
    hyda_g_island_mut_k = k;
    std::memset(ov, 0, sizeof(ov));
    GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(a), 0,
                                reinterpret_cast<uint64_t>(ov), 0);
    bool same = gr.ok && gr.status == ST_HALT && gr.ret == want;
    for (int i = 0; i < 4; ++i) same = same && (ov[i] == on[i]);
    if (!same) ++bad_k;
  }
  hyda_g_island_mut_k = 0xFFFFFFFFu;
  ck(bad_k == 0,
     "8s: k=0..3 with forced mutation result == native (packed SSE)");

  struct MutCase {
    const char* name;
    FnPtr fn;
    uintptr_t stop;
    uint64_t a0, a1;
  };
  float rout_n = 0.0f, rout_v = 0.0f;
  const MutCase mut_cases[] = {
      {"f_sse_rip", f_sse_rip, reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_rip),
       0, 0},
      {"f_dcall", f_dcall, reinterpret_cast<uintptr_t>(__stop_hyda_f_dcall), 0, 0},
      {"f_icall", f_icall, reinterpret_cast<uintptr_t>(__stop_hyda_f_icall), 7, 11},
      {"f_tail", f_tail, reinterpret_cast<uintptr_t>(__stop_hyda_f_tail), 5, 0},
  };
  for (const MutCase& mc : mut_cases) {
    Gated gm = gate_lift(mc.name, mc.fn, mc.stop);
    ck(gm.ok, std::string("8s: ") + mc.name + " lift (" + gm.error + ")");
    if (!gm.ok) continue;
    int bad = 0, nisl = 0;
    for (uint32_t k = 0; k < 4; ++k) {
      hyda_g_island_mut_k = k;
      uint64_t want_m = 0, got_m = 0;
      rout_n = 0.0f;
      rout_v = 0.0f;
      if (std::string(mc.name) == "f_sse_rip") {
        want_m = mc.fn(mc.a0, mc.a1, reinterpret_cast<uint64_t>(&rout_n), 0);
        GatedCall gr = vm_run_gated(gm, mc.a0, mc.a1,
                                    reinterpret_cast<uint64_t>(&rout_v), 0);
        if (!gr.ok || gr.status != ST_HALT || gr.ret != want_m ||
            rout_v != rout_n) {
          ++bad;
        }
      } else {
        want_m = mc.fn(mc.a0, mc.a1, 0, 0);
        GatedCall gr = vm_run_gated(gm, mc.a0, mc.a1, 0, 0);
        if (!gr.ok || gr.status != ST_HALT || gr.ret != want_m) ++bad;
      }
    }
    hyda_g_island_mut_k = 0xFFFFFFFFu;
    nisl = static_cast<int>(gm.islands.size());
    ck(bad == 0, std::string("8s: ") + mc.name + " (k=0..3) native == VM (" +
                     std::to_string(nisl) + " island)");
  }

  hyda_g_island_mut_k = 0;
  {
    std::memset(ov, 0, sizeof(ov));
    GatedCall gr = vm_run_gated(g, reinterpret_cast<uint64_t>(a), 0,
                                reinterpret_cast<uint64_t>(ov), 0);
    ck(gr.ok && gr.status == ST_HALT && gr.ret == want,
       "8s: f_sse_mix run for plan verification");
  }
  hyda_g_island_mut_k = 0xFFFFFFFFu;
  int n_plan = 0, bad_plan = 0, n_flip = 0, bad_rt = 0, n_dead = 0;
  for (size_t ai = 0; ai < g_placed.size(); ++ai) {
    const PlacedIsland& p = g_placed[ai];
    const uint32_t off = static_cast<uint32_t>(p.rva - g_placed_first_rva);
    if (off < hyda::HYDA_ISLAND_SIZE) { ++bad_plan; continue; }
    const hyda::IslandHeader* h = reinterpret_cast<const hyda::IslandHeader*>(
        g_island_area + off - hyda::HYDA_ISLAND_SIZE);
    if (!hyda::island_header_check(*h)) { ++bad_plan; continue; }

    std::vector<uint8_t> plain(h->size);
    std::memcpy(plain.data(), g_island_area + off, h->size);
    hyda::island_decrypt(plain.data(), h->size,
                         hyda::island_key_for(h->salt, p.rva));

    hyda::IslandMutPlan mp;
    if (!hyda::island_mut_plan_load(plain.data(), h->size, &mp)) {
      ++bad_plan;
      continue;
    }
    ++n_plan;

    const uint32_t slack = hyda::island_mut_slack(h->size, mp.tail_off);
    if (mp.tail_off + 5u > h->size || plain[mp.tail_off] != 0xE9 ||
        static_cast<uint32_t>(mp.insn_off) + mp.insn_len > mp.tail_off ||
        slack < 3u) {
      ++bad_plan;
      continue;
    }
    if (slack != 0) ++n_dead;
    if (mp.flip != 0) {
      const hyda::SsePair* pr = hyda::sse_pair(mp.flip);
      const uint32_t at = static_cast<uint32_t>(mp.insn_off) + mp.flip_off;
      if (pr == nullptr || at + 4u > h->size || plain[at] != 0x66 ||
          plain[at + 1] != 0x0F || plain[at + 2] != pr->op) {
        ++bad_plan;
        continue;
      }
      ++n_flip;
    }

    for (uint32_t key = 0; key < 24; ++key) {
      std::vector<uint8_t> work = plain;
      uint32_t st = 0;
      if (hyda::island_mutate(work.data(), h->size, key, &st) != hyda::HYDA_MUT_OK) {
        ++bad_rt;
        continue;
      }
      if ((st & 0xFu) > 0u && work == plain) ++bad_rt;
      if (hyda::island_unmutate(work.data(), h->size, st) != hyda::HYDA_MUT_OK) {
        ++bad_rt;
        continue;
      }
      if (work != plain) ++bad_rt;
    }
  }
  ck(n_plan == static_cast<int>(g_placed.size()) && bad_plan == 0,
     "8s: valid mutation plan on every island (tail/commands/slack consistent)");

  {
    int pair_ok = 0, bad_pair = 0;
    for (uint8_t k = 1; k <= hyda::HYDA_SSE_PAIR_COUNT; ++k) {
      const hyda::SsePair* pr = hyda::sse_pair(k);
      if (pr == nullptr) { ++bad_pair; continue; }
      uint8_t buf[4] = {0x66, 0x0F, pr->op, 0x00};
      const uint8_t orig[4] = {buf[0], buf[1], buf[2], buf[3]};
      if (!hyda::sse_flip(buf, k)) { ++bad_pair; continue; }
      if (buf[0] != 0x0F || buf[1] != pr->alt) { ++bad_pair; continue; }
      if (!hyda::sse_unflip(buf, k)) { ++bad_pair; continue; }
      if (std::memcmp(buf, orig, 4) != 0) { ++bad_pair; continue; }
      ++pair_ok;
    }
    ck(bad_pair == 0 && pair_ok == hyda::HYDA_SSE_PAIR_COUNT,
       "8s: SSE equivalence rewrite contract (flip+unflip byte-exact)");
  }
  ck(n_dead == static_cast<int>(g_placed.size()),
     "8s: dead slack for the prefix on every island");
  ck(bad_rt == 0, "8s: mutation + undo byte-exact (bytes become canonical)");

  std::printf("  OK   8s: %d islands planned, %d islands SSE-flipped, %d with slack\n",
              n_plan, n_flip, n_dead);
}

static void island_decoy_section() {

  struct Fn {
    const char* name;
    FnPtr fn;
    uintptr_t stop;
  };

  const Fn fns[] = {
      {"f_sse_mix", f_sse_mix,
       reinterpret_cast<uintptr_t>(__stop_hyda_f_sse_mix)},
      {"f_x87", f_x87, reinterpret_cast<uintptr_t>(__stop_hyda_f_x87)},
      {"f_icall", f_icall, reinterpret_cast<uintptr_t>(__stop_hyda_f_icall)},
      {"f_dcall", f_dcall, reinterpret_cast<uintptr_t>(__stop_hyda_f_dcall)},
  };

  int n_decoy = 0, bad_hdr = 0, plain_leak = 0, n_island = 0;
  for (const Fn& fn : fns) {
    Gated g = gate_lift(fn.name, fn.fn, fn.stop);
    ck(g.ok, std::string(fn.name) + ": lift + kod uretimi (" + g.error + ")");
    if (!g.ok) continue;
    uint64_t image_base = 0;
    uint32_t first_rva = 0, leave_rva = 0;
    gated_layout(g, &image_base, &first_rva, &leave_rva);
    const std::vector<uint32_t> leave_rvas{leave_rva};
    std::string err;
    const std::vector<PlacedIsland> placed =
        place_islands(g.islands, first_rva, leave_rvas, image_base, &err);
    if (g.islands.empty()) continue;
    ck(!placed.empty(),
       std::string(fn.name) + ": yerlesim " + (placed.empty() ? err : "tamam"));
    if (placed.empty()) continue;
    n_island += static_cast<int>(placed.size());
    for (const PlacedIsland& p : placed) {
      if (p.decoy_rva == 0 || p.decoy.empty()) continue;
      ++n_decoy;

      if (p.decoy.size() < hyda::HYDA_ISLAND_SIZE) { ++bad_hdr; continue; }
      const hyda::IslandHeader* h = reinterpret_cast<const hyda::IslandHeader*>(
          p.decoy.data());
      if (!hyda::island_header_check(*h)) { ++bad_hdr; continue; }

      std::vector<uint8_t> plain(h->size);
      std::memcpy(plain.data(), p.decoy.data() + hyda::HYDA_ISLAND_SIZE, h->size);
      hyda::island_decrypt(plain.data(), h->size,
                           hyda::island_key_for(h->salt, p.decoy_rva));
      if (std::memcmp(plain.data(), p.decoy.data() + hyda::HYDA_ISLAND_SIZE,
                      h->size) == 0) {
        ++plain_leak;
      }
    }
  }
  ck(n_island > 0, "island total (for the test)");
  ck(n_decoy > 0, "decoy islands present among the real ones");
  ck(bad_hdr == 0, "decoy island header valid (indistinguishable)");
  ck(plain_leak == 0, "decoy island content also encrypted (no plaintext leak)");
  std::printf("  %s  island decoy %d/%d islands are decoys (header valid, content encrypted)\n",
              "OK ", n_decoy, n_island);
}

// ALU, branches, calls, 8/16/32-bit forms and memory operands.
HYDA_TEST(Int, hand_written, "Hand-written x86-64 bodies: native == VM") {
  g_rep = &r;
run_diff("f_alu", f_alu, reinterpret_cast<uintptr_t>(__stop_hyda_f_alu),
         mk_cases(200, ~0ull, ~0ull, ~0ull, ~0ull));
run_diff("f_cmp", f_cmp, reinterpret_cast<uintptr_t>(__stop_hyda_f_cmp),
         mk_cases(200, ~0ull, ~0ull, 0, 0));
run_diff("f_loop", f_loop, reinterpret_cast<uintptr_t>(__stop_hyda_f_loop),
         mk_cases(80, 3000, 0, 0, 0));
run_diff("f_alu_jcc", f_alu_jcc,
         reinterpret_cast<uintptr_t>(__stop_hyda_f_alu_jcc),
         mk_cases(200, 64, ~0ull, 0, 0));
run_diff("f_shift", f_shift, reinterpret_cast<uintptr_t>(__stop_hyda_f_shift),
         mk_cases(200, ~0ull, ~0ull, ~0ull, 0));
run_diff("f_extend", f_extend, reinterpret_cast<uintptr_t>(__stop_hyda_f_extend),
         mk_cases(200, ~0ull, ~0ull, 0, 0));
run_diff("f_div", f_div, reinterpret_cast<uintptr_t>(__stop_hyda_f_div),
         mk_cases(200, ~0ull, 0xFFFF, 0, 0),
         [](const Case& c) { return c.b == 0; });
run_diff("f_call", f_call, reinterpret_cast<uintptr_t>(__stop_hyda_f_call),
         mk_cases(200, ~0ull, ~0ull, 0, 0));
run_diff("f_32bit", f_32bit, reinterpret_cast<uintptr_t>(__stop_hyda_f_32bit),
         mk_cases(200, ~0ull, ~0ull, ~0ull, 0));
run_diff("f_test32", f_test32, reinterpret_cast<uintptr_t>(__stop_hyda_f_test32),
         mk_cases(200, ~0ull, ~0ull, 0, 0));
run_diff("f_imul_lea", f_imul_lea, reinterpret_cast<uintptr_t>(__stop_hyda_f_imul_lea),
         mk_cases(200, ~0ull, ~0ull, ~0ull, 0));
run_diff("f_cmov32", f_cmov32, reinterpret_cast<uintptr_t>(__stop_hyda_f_cmov32),
         mk_cases(200, ~0ull, 0xFFFFFFFF, ~0ull, 0));
run_diff("f_cmov64", f_cmov64, reinterpret_cast<uintptr_t>(__stop_hyda_f_cmov64),
         mk_cases(200, ~0ull, ~0ull, ~0ull, 0));
run_diff("f_setcc", f_setcc, reinterpret_cast<uintptr_t>(__stop_hyda_f_setcc),
         mk_cases(200, ~0ull, ~0ull, 0, 0));
run_diff("f_switch", f_switch, reinterpret_cast<uintptr_t>(__stop_hyda_f_switch),
         mk_cases(64, 7, 0, 0, 0));

{
  static uint64_t sa[4], sb[4], sd[4];
  const uintptr_t start = reinterpret_cast<uintptr_t>(f_mem);
  LiftOptions opt;
  opt.base_address = start;
  opt.name = "f_mem";
  const LiftResult r = lift_x86_64(reinterpret_cast<const uint8_t*>(start),
                                   static_cast<size_t>(
                                       reinterpret_cast<uintptr_t>(__stop_hyda_f_mem) - start),
                                   opt);
  ck(r.ok, std::string("f_mem: lift basarili (") + r.error + ")");
  if (r.ok) {
    IRProgram prog = r.prog;
    ir_wrap_callable(prog);
    Asm a;
    const CodegenResult cg = ir_codegen(prog, a);
    ck(cg.ok, std::string("f_mem: bytecode uretildi (") + cg.error + ")");
    if (cg.ok) {
      int bad = 0;
      uint64_t s = 0xDEADBEEFCAFEBABEull;
      for (int i = 0; i < 200; ++i) {
        sa[0] = splitmix64(s);
        sb[0] = splitmix64(s);
        sd[0] = 0;
        const uint64_t want = f_mem(reinterpret_cast<uint64_t>(sa),
                                    reinterpret_cast<uint64_t>(sb),
                                    reinterpret_cast<uint64_t>(sd), 0);
        const VmCall got = vm_run(a, cg.entry_offset,
                                  reinterpret_cast<uint64_t>(sa),
                                  reinterpret_cast<uint64_t>(sb),
                                  reinterpret_cast<uint64_t>(sd), 0);
        if (got.status != ST_HALT || got.ret != want || sd[0] != want) ++bad;
      }
      ck(bad == 0, "f_mem: 200 inputs (load/add/store) native == VM");
      std::printf("  %s  %-12s %3d inputs, %zu x86 insns -> %zu bytes bytecode\n",
                  bad == 0 ? "OK  " : "FAIL", "f_mem", 200, r.decoded, cg.code_size);
    }
  }
}
}

// Real gcc output: c_run wraps a loop, a branch and a multiply.
HYDA_TEST(Int, compiler_output, "Compiler -O2 bodies lifted from a real object") {
  g_rep = &r;
run_diff("c_run", c_run, reinterpret_cast<uintptr_t>(__stop_hyda_c3),
         mk_cases(300, ~0ull, 0xFFFF, ~0ull, 0));
}

// One-operand and two-operand forms; compares CF/OF/ZF.
HYDA_TEST(MulDiv, sized_mul_div, "8/16/32-bit mul, imul, div and idiv with flags") {
  g_rep = &r;
{

  const std::vector<Case> mc = mk_cases(300, ~0ull, ~0ull, 0, 0);
  run_diff_out("f_mul8", f_mul8, reinterpret_cast<uintptr_t>(__stop_hyda_f_mul8),
               mc, mask_cf_of);
  run_diff_out("f_imul1_8", f_imul1_8, reinterpret_cast<uintptr_t>(__stop_hyda_f_imul1_8),
               mc, mask_cf_of);
  run_diff_out("f_mul16", f_mul16, reinterpret_cast<uintptr_t>(__stop_hyda_f_mul16),
               mc, mask_cf_of);
  run_diff_out("f_imul1_16", f_imul1_16, reinterpret_cast<uintptr_t>(__stop_hyda_f_imul1_16),
               mc, mask_cf_of);
  run_diff_out("f_mul32", f_mul32, reinterpret_cast<uintptr_t>(__stop_hyda_f_mul32),
               mc, mask_cf_of);
  run_diff_out("f_imul1_32", f_imul1_32, reinterpret_cast<uintptr_t>(__stop_hyda_f_imul1_32),
               mc, mask_cf_of);
  run_diff_out("f_imul2_16", f_imul2_16, reinterpret_cast<uintptr_t>(__stop_hyda_f_imul2_16),
               mc, mask_cf_of);
  run_diff_out("f_imul2_32", f_imul2_32, reinterpret_cast<uintptr_t>(__stop_hyda_f_imul2_32),
               mc, mask_cf_of);

  run_diff_out("f_div32", f_div32, reinterpret_cast<uintptr_t>(__stop_hyda_f_div32),
               mc, mask_none, [](const Case& c) {
                 const uint64_t d = static_cast<uint32_t>(c.b);
                 if (d == 0) return true;
                 return (c.a >> 32) >= d;
               });
  run_diff_out("f_idiv32", f_idiv32, reinterpret_cast<uintptr_t>(__stop_hyda_f_idiv32),
               mc, mask_none, [](const Case& c) {
                 const int32_t b = static_cast<int32_t>(static_cast<uint32_t>(c.b));
                 if (b == 0) return true;

                 return static_cast<int32_t>(static_cast<uint32_t>(c.a)) == INT32_MIN && b == -1;
               });
  run_diff_out("f_div16", f_div16, reinterpret_cast<uintptr_t>(__stop_hyda_f_div16),
               mc, mask_none, [](const Case& c) { return (c.b & 0xffffu) == 0; });
  run_diff_out("f_idiv16", f_idiv16, reinterpret_cast<uintptr_t>(__stop_hyda_f_idiv16),
               mc, mask_none, [](const Case& c) {
                 const int32_t b = static_cast<int16_t>(c.b & 0xffffu);
                 if (b == 0) return true;
                 const int32_t q = static_cast<int32_t>(c.a & 0xffffu) / b;
                 return q < -32768 || q > 32767;
               });
}
}

// Flags that survive the body must still match native.
HYDA_TEST(Flags, dead_elimination, "Dead-flag elimination keeps the observable flags") {
  g_rep = &r;
{
  const std::vector<Case> dc = mk_cases(200, ~0ull, ~0ull, 0, 0);
  size_t df = 0, dd = 0;
  run_diff_out("f_dead_add", f_dead_add,
               reinterpret_cast<uintptr_t>(__stop_hyda_f_dead_add), dc,
               mask_all5, nullptr, &df, &dd);
  ck(df >= 1, "f_dead_add: dead flag command found (elimination applied)");
  ck(dd == 0, "f_dead_add: a result-producing command must NOT be removed");

  df = dd = 0;
  run_diff_out("f_dead_cmp", f_dead_cmp,
               reinterpret_cast<uintptr_t>(__stop_hyda_f_dead_cmp), dc,
               mask_all5, nullptr, &df, &dd);
  ck(df >= 1, "f_dead_cmp: dead flag CMP found");
  ck(dd >= 1, "f_dead_cmp: dead flag-only command REMOVED");

  df = dd = 0;
  run_diff_out("f_live_add", f_live_add,
               reinterpret_cast<uintptr_t>(__stop_hyda_f_live_add), dc,
               mask_all5, nullptr, &df, &dd);
  std::printf("  OK  %-12s live ADD (setcc reads); instructions marked dead: %zu\n",
              "f_live_add", df);
}
}

// Counters read the same result and ZF as the host CPU.
HYDA_TEST(Bits, count_ops, "tzcnt/lzcnt/popcnt with ZF") {
  g_rep = &r;
{
  const std::vector<Case> bc = mk_cases(300, ~0ull, ~0ull, 0, 0);

  if (__builtin_cpu_supports("bmi")) {
    run_diff_out("f_tzcnt32", f_tzcnt32, reinterpret_cast<uintptr_t>(__stop_hyda_f_tzcnt32),
                 bc, mask_cf_zf);
    run_diff_out("f_tzcnt64", f_tzcnt64, reinterpret_cast<uintptr_t>(__stop_hyda_f_tzcnt64),
                 bc, mask_cf_zf);
    run_diff_out("f_tzcnt16", f_tzcnt16, reinterpret_cast<uintptr_t>(__stop_hyda_f_tzcnt16),
                 bc, mask_cf_zf);
    run_diff_out("f_lzcnt32", f_lzcnt32, reinterpret_cast<uintptr_t>(__stop_hyda_f_lzcnt32),
                 bc, mask_cf_zf);
    run_diff_out("f_lzcnt64", f_lzcnt64, reinterpret_cast<uintptr_t>(__stop_hyda_f_lzcnt64),
                 bc, mask_cf_zf);
  } else {
    std::printf("  SKIP  tzcnt/lzcnt: no BMI on this CPU\n");
  }
  if (__builtin_cpu_supports("popcnt")) {
    run_diff_out("f_popcnt32", f_popcnt32, reinterpret_cast<uintptr_t>(__stop_hyda_f_popcnt32),
                 bc, mask_zf);
    run_diff_out("f_popcnt64", f_popcnt64, reinterpret_cast<uintptr_t>(__stop_hyda_f_popcnt64),
                 bc, mask_zf);
  } else {
    std::printf("  SKIP  popcnt: no POPCNT on this CPU\n");
  }
}
}

// Registers the body never writes may stay untouched.
HYDA_TEST(Trampoline, written_regs, "Body write tracking drives the trampoline save mask") {
  g_rep = &r;
{

  auto written = [](uintptr_t start, uintptr_t end) -> uint16_t {
    LiftOptions o;
    o.base_address = start;
    o.name = "yazilan";
    return lift_x86_64(reinterpret_cast<const uint8_t*>(start), end - start, o)
        .written_regs;
  };
  const uint16_t wa = written(reinterpret_cast<uintptr_t>(f_alu),
                              reinterpret_cast<uintptr_t>(__stop_hyda_f_alu));
  ck((wa & (1u << REG_RAX)) != 0, "f_alu: rax 'yaziliyor' isaretlendi");
  ck((wa & ((1u << REG_RCX) | (1u << REG_RDX))) == 0,
     "f_alu: rcx/rdx 'korunuyor' isaretlendi");

  const uint16_t ww = written(reinterpret_cast<uintptr_t>(f_writes),
                              reinterpret_cast<uintptr_t>(__stop_hyda_f_writes));
  ck((ww & ((1u << REG_RAX) | (1u << REG_RDX))) ==
         ((1u << REG_RAX) | (1u << REG_RDX)),
     "f_writes: rax+rdx yaziliyor");
  ck((ww & ((1u << REG_RCX) | (1u << REG_R8) | (1u << REG_R9) |
            (1u << REG_R10) | (1u << REG_R11))) == 0,
     "f_writes: rcx/r8-r11 korunuyor (trampolinde saklanacak)");
  std::printf("  OK    f_alu written=%#x, f_writes written=%#x\n", wa, ww);
}
}

// Instructions the VM cannot express run as encrypted islands.
HYDA_TEST(Gate, call_gate, "Native gate: SSE, AVX, x87, CPUID, indirect call, XMM arg, tail") {
  g_rep = &r;
{
  gate_section();
}
}

// The island area is never valid while the VM is idle.
HYDA_TEST(Island, encryption, "Island bytes decrypt at the gate and re-encrypt on exit") {
  g_rep = &r;
{
  island_crypt_section();
}
}

// Placed islands move around between builds.
HYDA_TEST(Island, layout, "Island layout diversity: order, gaps, junk, leave") {
  g_rep = &r;
{
  island_layout_section();
}
}

// Equivalent encodings are generated per island.
HYDA_TEST(Island, meta, "Metamorphic re-encoding of island bytes") {
  g_rep = &r;
{
  island_meta_section();
}
}

// Decoys must not decrypt to a working island.
HYDA_TEST(Island, decoys, "Decoy islands look valid but carry encrypted content") {
  g_rep = &r;
{
  island_decoy_section();
}
}

// The runtime rewrites island bodies after each gate.
HYDA_TEST(Island, reencode, "Runtime re-encoding of islands") {
  g_rep = &r;
{
  island_mut_section();
}
}

// Mutation on and off must produce the same answers.
HYDA_TEST(Mutate, engine, "Mutation engine: junk, noise and inverse keep results equal") {
  g_rep = &r;
{
  const uintptr_t start = reinterpret_cast<uintptr_t>(f_alu);
  const size_t size =
      static_cast<size_t>(reinterpret_cast<uintptr_t>(__stop_hyda_f_alu) - start);
  const std::vector<Case> cases = mk_cases(120, ~0ull, ~0ull, ~0ull, ~0ull);

  auto count_op = [](const Asm& a, Op want) -> int {
    int n = 0;
    size_t off = 0;
    while (off < a.code.size()) {
      const uint16_t slot = static_cast<uint16_t>(
          a.code[off] | (static_cast<uint16_t>(a.code[off + 1]) << 8));
      const uint16_t op = opcode_map().op_of_slot[slot];
      if (op == BAD_SLOT) return -1;
      if (op == static_cast<uint16_t>(want)) ++n;
      off += kHeaderBytes + op_size(static_cast<Op>(op));
    }
    return off == a.code.size() ? n : -1;
  };

  auto build = [&](bool mutate) {
    LiftOptions o;
    o.base_address = start;
    o.name = "f_alu";
    o.mutate = mutate;
    return lift_x86_64(reinterpret_cast<const uint8_t*>(start), size, o);
  };

  const LiftResult mon = build(true);
  const LiftResult moff = build(false);
  ck(mon.ok && moff.ok, "f_alu: lift (mutation on/off)");
  if (mon.ok && moff.ok) {
    ck(mon.mutate.junk > 0 && mon.mutate.noise > 0 && mon.mutate.inv_r > 0,
       "f_alu: mutation stats populated (junk/noise/inverse)");
    ck(moff.mutate.cmds_after == moff.mutate.cmds_before &&
           moff.mutate.junk == 0 && moff.mutate.noise == 0 &&
           moff.mutate.inv_r == 0,
       "f_alu: mutation off -> zero stats, same command count");

    IRProgram po = mon.prog;
    IRProgram pf = moff.prog;
    ir_wrap_callable(po);
    ir_wrap_callable(pf);
    Asm ao, af;
    const CodegenResult cgo = ir_codegen(po, ao);
    const CodegenResult cgf = ir_codegen(pf, af);
    ck(cgo.ok && cgf.ok, "f_alu: codegen (mutation on/off)");

    const int junk_o = count_op(ao, Op::VM_JUNK);
    const int noise_o = count_op(ao, Op::VM_NOISE);
    const int inv_o = count_op(ao, Op::INV_R);
    const int junk_f = count_op(af, Op::VM_JUNK);
    const int noise_f = count_op(af, Op::VM_NOISE);
    const int inv_f = count_op(af, Op::INV_R);
    ck(junk_o > 0, "f_alu: mutation ON -> VM_JUNK in bytecode");
    ck(noise_o > 0, "f_alu: mutation ON -> VM_NOISE in bytecode");
    ck(inv_o > 0, "f_alu: mutation ON -> INV_R in bytecode");
    ck(junk_f == 0 && noise_f == 0 && inv_f == 0,
       "f_alu: mutation OFF -> no mutation opcode");
    ck(ao.code.size() > af.code.size(), "f_alu: mutation grows the bytecode");

    int bad = 0;
    for (const Case& cs : cases) {
      const uint64_t want = f_alu(cs.a, cs.b, cs.c, cs.d);
      const VmCall g1 = vm_run(ao, cgo.entry_offset, cs.a, cs.b, cs.c, cs.d);
      const VmCall g2 = vm_run(af, cgf.entry_offset, cs.a, cs.b, cs.c, cs.d);
      if (g1.status != ST_HALT || g1.ret != want || g2.status != ST_HALT ||
          g2.ret != want) {
        ++bad;
      }
    }
    ck(bad == 0, "f_alu: mutation ON/OFF result == native");
    std::printf("  %s  f_alu: %d junk, %d noise, %d inverse; %zu -> %zu bytes\n",
                bad == 0 ? "OK  " : "FAIL", junk_o, noise_o, inv_o,
                af.code.size(), ao.code.size());
  }
}
}

// Prints decoded/IR counts; never fails.
HYDA_TEST(Report, corpus, "Informational lift coverage of the C corpus") {
  g_rep = &r;
coverage("c_sum_step", c_sum_step, reinterpret_cast<uintptr_t>(__stop_hyda_c1));
coverage("c_mix", c_mix, reinterpret_cast<uintptr_t>(__stop_hyda_c2));
coverage("c_run", c_run, reinterpret_cast<uintptr_t>(__stop_hyda_c3));

}

// Full YMM file survives save_simd/restore_simd across a call.
HYDA_TEST(Simd, ymm_roundtrip, "YMM save/restore keeps all 256 bits") {
  g_rep = &r;
  if (!hyda::fp_supports_avx()) {
    HYDA_CHECK_MSG(r, true, "skipped: no AVX");
    return;
  }
  alignas(32) uint64_t pat[4], out[4];
  for (int i = 0; i < 4; ++i) pat[i] = 0xC0DE0000C0DE0000ull + static_cast<uint64_t>(i);
  std::memset(out, 0, sizeof(out));

  simd_seed_ymm(pat, reinterpret_cast<uint64_t>(&hyda_vm_save_simd));
  const hyda::HydaFpState* saved = hyda::fp_state();
  const bool save_lo = saved->xmm(0)[0] == pat[0] && saved->xmm(0)[1] == pat[1];
  const bool save_hi = saved->ymm_hi(0)[0] == pat[2] && saved->ymm_hi(0)[1] == pat[3];
  ck(save_lo && save_hi, "save_simd stores both YMM halves");

  simd_restore_store(reinterpret_cast<uint64_t>(out),
                     reinterpret_cast<uint64_t>(&hyda_vm_restore_simd));

  bool ok = true;
  for (int i = 0; i < 4; ++i) ok = ok && (out[i] == pat[i]);
  if (!ok) {
    for (int i = 0; i < 4; ++i) {
      if (out[i] == pat[i]) continue;
      std::printf("     lane %d: pat=%#llx out=%#llx\n", i,
                  static_cast<unsigned long long>(pat[i]),
                  static_cast<unsigned long long>(out[i]));
    }
  }
  ck(ok, "simd save/restore preserves full YMM");
}

// Immediates are blinded, so a 64-bit constant must not appear verbatim.
HYDA_TEST(Codec, const_blinding, "Immediate constants are not emitted literally") {
  g_rep = &r;
  const uint64_t k = 0x1122334455667788ull;
  IRProgram p;
  p.add(IRCommand::mov(IROperand::R(REG_RAX), IROperand::I(static_cast<int64_t>(k))));
  p.add(IRCommand::none(IROp::Halt));
  Asm a;
  const CodegenResult cg = ir_codegen(p, a);
  ck(cg.ok, std::string("const blind: codegen (") + cg.error + ")");
  if (!cg.ok) return;

  bool found = false;
  for (size_t i = 0; i + 8 <= a.code.size(); ++i) {
    uint64_t v = 0;
    std::memcpy(&v, &a.code[i], 8);
    if (v == k) { found = true; break; }
  }
  ck(!found, "const blind: immediate not emitted literally");
}

#define HYDA_SHIFT_BODY(FN, SEC, SZ, SHLSHR)                                   \
  g_rep = &r;                                                                  \
  const std::vector<Case> sc = mk_shift_cases();                               \
  run_diff_out(#FN, FN, reinterpret_cast<uintptr_t>(__stop_##SEC), sc,         \
               [](const Case& c) {                                            \
                 return shift_mask(                                           \
                     static_cast<unsigned>(c.b & 0xffu) & (SZ == 64 ? 63u : 31u), \
                     (unsigned)SZ, SHLSHR);                                   \
               })

// SHL r8, CL: value plus CF/SF/ZF/PF for every count 0..255.
HYDA_TEST(Shift, shl8, "SHL r8, CL") { HYDA_SHIFT_BODY(f_shl8, hyda_f_shl8, 8, true); }
// SHL r16, CL.
HYDA_TEST(Shift, shl16, "SHL r16, CL") { HYDA_SHIFT_BODY(f_shl16, hyda_f_shl16, 16, true); }
// SHL r32, CL.
HYDA_TEST(Shift, shl32, "SHL r32, CL") { HYDA_SHIFT_BODY(f_shl32, hyda_f_shl32, 32, true); }
// SHL r64, CL.
HYDA_TEST(Shift, shl64, "SHL r64, CL") { HYDA_SHIFT_BODY(f_shl64, hyda_f_shl64, 64, true); }
// SHR r8, CL.
HYDA_TEST(Shift, shr8, "SHR r8, CL") { HYDA_SHIFT_BODY(f_shr8, hyda_f_shr8, 8, true); }
// SHR r16, CL.
HYDA_TEST(Shift, shr16, "SHR r16, CL") { HYDA_SHIFT_BODY(f_shr16, hyda_f_shr16, 16, true); }
// SHR r32, CL.
HYDA_TEST(Shift, shr32, "SHR r32, CL") { HYDA_SHIFT_BODY(f_shr32, hyda_f_shr32, 32, true); }
// SHR r64, CL.
HYDA_TEST(Shift, shr64, "SHR r64, CL") { HYDA_SHIFT_BODY(f_shr64, hyda_f_shr64, 64, true); }
// SAR r8, CL.
HYDA_TEST(Shift, sar8, "SAR r8, CL") { HYDA_SHIFT_BODY(f_sar8, hyda_f_sar8, 8, false); }
// SAR r16, CL.
HYDA_TEST(Shift, sar16, "SAR r16, CL") { HYDA_SHIFT_BODY(f_sar16, hyda_f_sar16, 16, false); }
// SAR r32, CL.
HYDA_TEST(Shift, sar32, "SAR r32, CL") { HYDA_SHIFT_BODY(f_sar32, hyda_f_sar32, 32, false); }
// SAR r64, CL.
HYDA_TEST(Shift, sar64, "SAR r64, CL") { HYDA_SHIFT_BODY(f_sar64, hyda_f_sar64, 64, false); }
// ROL r8, CL.
HYDA_TEST(Shift, rol8, "ROL r8, CL") { HYDA_SHIFT_BODY(f_rol8, hyda_f_rol8, 8, false); }
// ROL r16, CL.
HYDA_TEST(Shift, rol16, "ROL r16, CL") { HYDA_SHIFT_BODY(f_rol16, hyda_f_rol16, 16, false); }
// ROL r32, CL.
HYDA_TEST(Shift, rol32, "ROL r32, CL") { HYDA_SHIFT_BODY(f_rol32, hyda_f_rol32, 32, false); }
// ROL r64, CL.
HYDA_TEST(Shift, rol64, "ROL r64, CL") { HYDA_SHIFT_BODY(f_rol64, hyda_f_rol64, 64, false); }
// ROR r8, CL.
HYDA_TEST(Shift, ror8, "ROR r8, CL") { HYDA_SHIFT_BODY(f_ror8, hyda_f_ror8, 8, false); }
// ROR r16, CL.
HYDA_TEST(Shift, ror16, "ROR r16, CL") { HYDA_SHIFT_BODY(f_ror16, hyda_f_ror16, 16, false); }
// ROR r32, CL.
HYDA_TEST(Shift, ror32, "ROR r32, CL") { HYDA_SHIFT_BODY(f_ror32, hyda_f_ror32, 32, false); }
// ROR r64, CL.
HYDA_TEST(Shift, ror64, "ROR r64, CL") { HYDA_SHIFT_BODY(f_ror64, hyda_f_ror64, 64, false); }

#undef HYDA_SHIFT_BODY

#define HYDA_DSHIFT_BODY(FN, SEC)                                              \
  g_rep = &r;                                                                  \
  run_diff_out(#FN, FN, reinterpret_cast<uintptr_t>(__stop_##SEC),             \
               mk_shift_cases(), [](const Case&) { return 0x1Du; })

#define HYDA_DSHIFT_IMM_BODY(FN, SEC)                                          \
  g_rep = &r;                                                                  \
  run_diff_out(#FN, FN, reinterpret_cast<uintptr_t>(__stop_##SEC),             \
               mk_cases(200, ~0ull, ~0ull, 0, 0), [](const Case&) { return 0x1Du; })

// SHLD r64, r64, CL: value and CF for every count, including the no-op 0.
HYDA_TEST(DoubleShift, shld64, "SHLD r64, CL") { HYDA_DSHIFT_BODY(f_shld64, hyda_f_shld64); }
// SHRD r64, r64, CL.
HYDA_TEST(DoubleShift, shrd64, "SHRD r64, CL") { HYDA_DSHIFT_BODY(f_shrd64, hyda_f_shrd64); }
// SHLD r32, r32, CL, including the zero-extended 32-bit write.
HYDA_TEST(DoubleShift, shld32, "SHLD r32, CL") { HYDA_DSHIFT_BODY(f_shld32, hyda_f_shld32); }
// SHRD r32, r32, CL.
HYDA_TEST(DoubleShift, shrd32, "SHRD r32, CL") { HYDA_DSHIFT_BODY(f_shrd32, hyda_f_shrd32); }
// SHLD with an imm8 count.
HYDA_TEST(DoubleShift, shld64_imm, "SHLD r64, imm8") { HYDA_DSHIFT_IMM_BODY(f_shld64_imm, hyda_f_shld64_imm); }
// SHRD with an imm8 count.
HYDA_TEST(DoubleShift, shrd64_imm, "SHRD r64, imm8") { HYDA_DSHIFT_IMM_BODY(f_shrd64_imm, hyda_f_shrd64_imm); }
// SHLD r32 with an imm8 count.
HYDA_TEST(DoubleShift, shld32_imm, "SHLD r32, imm8") { HYDA_DSHIFT_IMM_BODY(f_shld32_imm, hyda_f_shld32_imm); }
// SHRD r32 with an imm8 count.
HYDA_TEST(DoubleShift, shrd32_imm, "SHRD r32, imm8") { HYDA_DSHIFT_IMM_BODY(f_shrd32_imm, hyda_f_shrd32_imm); }
// Count 0 must leave the destination and every flag alone.
HYDA_TEST(DoubleShift, shld32_zero, "SHLD r32, 0") { HYDA_DSHIFT_IMM_BODY(f_shld32_zero, hyda_f_shld32_zero); }
// Count 0 for SHRD, same guarantee.
HYDA_TEST(DoubleShift, shrd32_zero, "SHRD r32, 0") { HYDA_DSHIFT_IMM_BODY(f_shrd32_zero, hyda_f_shrd32_zero); }

#undef HYDA_DSHIFT_BODY
#undef HYDA_DSHIFT_IMM_BODY

// Same bodies lifted under several mutation seeds: obfuscation must not change
// a single result or clobber a live temporary.
HYDA_TEST(DoubleShift, mutation_seeds, "SHLD/SHRD under 4 mutation seeds") {
  g_rep = &r;
  const uint64_t seeds[] = {0x1111111111111111ull, 0x2222222222222222ull,
                            0xDEADBEEFCAFEBABEull, 0x9E3779B97F4A7C15ull};
  const std::vector<Case> sc = mk_shift_cases();
  const std::vector<Case> ac = mk_cases(120, ~0ull, ~0ull, ~0ull, ~0ull);
  for (uint64_t seed : seeds) {
    run_diff_seeded("f_shld64", f_shld64, reinterpret_cast<uintptr_t>(__stop_hyda_f_shld64),
                    sc, [](const Case&) { return 0x1Du; }, seed);
    run_diff_seeded("f_shrd64", f_shrd64, reinterpret_cast<uintptr_t>(__stop_hyda_f_shrd64),
                    sc, [](const Case&) { return 0x1Du; }, seed);
    run_diff_seeded("f_alu", f_alu, reinterpret_cast<uintptr_t>(__stop_hyda_f_alu),
                    ac, [](const Case&) { return 0x1Fu; }, seed);
  }
}

int main(int argc, char** argv) {
  return hyda::test::Registry::instance().run(argc, argv);
}
