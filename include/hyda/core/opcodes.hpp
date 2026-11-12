#pragma once

#include "hyda/core/config.hpp"
#include "hyda/core/instance.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

enum class Opr : uint8_t {
  N = 0,
  R = 1,
  b = 2,
  d = 3,
  q = 4,
};

constexpr unsigned opr_size(Opr o) {
  return o == Opr::N ? 0u
       : o == Opr::R ? 1u
       : o == Opr::b ? 1u
       : o == Opr::d ? 4u
                     : 8u;
}

struct Sig {
  Opr a, b, c, d, e, f;
};

constexpr unsigned sig_size(Sig s) {
  return opr_size(s.a) + opr_size(s.b) + opr_size(s.c) +
         opr_size(s.d) + opr_size(s.e) + opr_size(s.f);
}

#define HYDA_ALU4(X, BASE, HFN)                    \
  X(BASE##8,  R, R, N, N, N, N, HF(HFN<8>))        \
  X(BASE##16, R, R, N, N, N, N, HF(HFN<16>))       \
  X(BASE##32, R, R, N, N, N, N, HF(HFN<32>))       \
  X(BASE##64, R, R, N, N, N, N, HF(HFN<64>))

#define HYDA_NF_ALU4(X, BASE, HFN)                 \
  X(BASE##8_NF,  R, R, N, N, N, N, HF(HFN<8>))     \
  X(BASE##16_NF, R, R, N, N, N, N, HF(HFN<16>))    \
  X(BASE##32_NF, R, R, N, N, N, N, HF(HFN<32>))    \
  X(BASE##64_NF, R, R, N, N, N, N, HF(HFN<64>))

#define HYDA_NF_SZ4(X, BASE, HFN)                  \
  X(BASE##8_NF,  R, N, N, N, N, N, HF(HFN<8>))     \
  X(BASE##16_NF, R, N, N, N, N, N, HF(HFN<16>))    \
  X(BASE##32_NF, R, N, N, N, N, N, HF(HFN<32>))    \
  X(BASE##64_NF, R, N, N, N, N, N, HF(HFN<64>))

#define HYDA_BODY_ALU4(X, BASE, HFN)               \
  X(BASE##32_B, R, R, N, N, N, N, HF(HFN<32>))     \
  X(BASE##64_B, R, R, N, N, N, N, HF(HFN<64>))

#define HYDA_BODY_SZ4(X, BASE, HFN)                \
  X(BASE##32_B, R, N, N, N, N, N, HF(HFN<32>))     \
  X(BASE##64_B, R, N, N, N, N, N, HF(HFN<64>))

#define HYDA_BODY2_ALU4(X, BASE, HFN)              \
  X(BASE##32_B2, R, R, N, N, N, N, HF(HFN<32>))    \
  X(BASE##64_B2, R, R, N, N, N, N, HF(HFN<64>))

#define HYDA_BODY3_ALU4(X, BASE, HFN)              \
  X(BASE##32_B3, R, R, N, N, N, N, HF(HFN<32>))    \
  X(BASE##64_B3, R, R, N, N, N, N, HF(HFN<64>))

#define HYDA_SZ4(X, BASE, HFN)                     \
  X(BASE##8,  R, N, N, N, N, N, HF(HFN<8>))        \
  X(BASE##16, R, N, N, N, N, N, HF(HFN<16>))       \
  X(BASE##32, R, N, N, N, N, N, HF(HFN<32>))       \
  X(BASE,     R, N, N, N, N, N, HF(HFN<64>))

#define HYDA_SHIFTV4(X, BASE, HFN)                 \
  X(BASE##_R8,  R, R, N, N, N, N, HF(HFN<8>))      \
  X(BASE##_R16, R, R, N, N, N, N, HF(HFN<16>))     \
  X(BASE##_R32, R, R, N, N, N, N, HF(HFN<32>))     \
  X(BASE##_R,   R, R, N, N, N, N, HF(HFN<64>))

#define HYDA_OPCODES(X)                                            \
                                        \
  X(NOP,      N, N, N, N, N, N, HF(h_nop))                         \
  X(HALT,     N, N, N, N, N, N, HF(h_halt))                        \
  X(VM_JUNK,  q, N, N, N, N, N, HF(h_vm_junk))                     \
  X(VM_NOISE, R, q, N, N, N, N, HF(h_vm_noise))                    \
   \
   \
   \
  X(INV_R,    R, N, N, N, N, N, HF(h_inv_r))                       \
                                              \
  X(PUSH_IMM, q, N, N, N, N, N, HF(h_push_imm))                    \
  X(PUSH_R,   R, N, N, N, N, N, HF(h_push_r))                      \
  X(POP_R,    R, N, N, N, N, N, HF(h_pop_r))                       \
  X(PUSHF,    N, N, N, N, N, N, HF(h_pushf))                       \
  X(POPF,     N, N, N, N, N, N, HF(h_popf))                        \
  X(CLC,      N, N, N, N, N, N, HF(h_clc))                         \
  X(STC,      N, N, N, N, N, N, HF(h_stc))                         \
  X(CMC,      N, N, N, N, N, N, HF(h_cmc))                         \
                                             \
  X(MOV_RR,   R, R, N, N, N, N, HF(h_mov_rr))                      \
  X(MOV_RR8,  R, R, N, N, N, N, HF(h_mov_rr8))                     \
  X(MOV_RR16, R, R, N, N, N, N, HF(h_mov_rr16))                    \
  X(MOV_RR32, R, R, N, N, N, N, HF(h_mov_rr32))                    \
  X(MOV_RI,   R, q, N, N, N, N, HF(h_mov_ri))                      \
  X(MOV_RI8,  R, q, N, N, N, N, HF(h_mov_ri8))                     \
  X(MOV_RI16, R, q, N, N, N, N, HF(h_mov_ri16))                    \
  X(MOV_RI32, R, q, N, N, N, N, HF(h_mov_ri32))                    \
  X(MOV_RI_BASE, R, q, N, N, N, N, HF(h_mov_ri_base))              \
  X(MOV_RM,   R, R, R, b, d, N, HF(h_mov_rm))                      \
  X(MOV_MR,   R, R, R, b, d, N, HF(h_mov_mr))                      \
  X(LOAD8,    R, R, R, b, d, N, HF(h_load8))                       \
  X(LOAD16,   R, R, R, b, d, N, HF(h_load16))                      \
  X(LOAD32,   R, R, R, b, d, N, HF(h_load32))                      \
  X(STORE8,   R, R, R, b, d, N, HF(h_store8))                      \
  X(STORE16,  R, R, R, b, d, N, HF(h_store16))                     \
  X(STORE32,  R, R, R, b, d, N, HF(h_store32))                     \
                   \
   \
   \
  X(SSE_LD16, R, R, R, b, d, N, HF(h_sse_ld16))                    \
  X(SSE_LD8,  R, R, R, b, d, N, HF(h_sse_ld8))                     \
  X(SSE_LD4,  R, R, R, b, d, N, HF(h_sse_ld4))                     \
  X(SSE_ST16, R, R, R, b, d, N, HF(h_sse_st16))                    \
  X(SSE_ST8,  R, R, R, b, d, N, HF(h_sse_st8))                     \
  X(SSE_ST4,  R, R, R, b, d, N, HF(h_sse_st4))                     \
  X(SSE_MOV,  R, R, b, N, N, N, HF(h_sse_mov))                     \
  X(SSE_BIN,  R, R, b, N, N, N, HF(h_sse_bin))                     \
  X(SSE_BINM, R, R, R, b, d, b, HF(h_sse_binm))                    \
  X(SSE_UN,   R, b, N, N, N, N, HF(h_sse_un))                      \
  X(SSE_CMP,  R, R, b, N, N, N, HF(h_sse_cmp))                     \
  X(SSE_CMPM, R, R, R, b, d, b, HF(h_sse_cmpm))                    \
  X(SSE_CVT,  R, R, b, N, N, N, HF(h_sse_cvt))                     \
  X(SSE_SHUF, R, R, b, b, N, N, HF(h_sse_shuf))                    \
   \
  X(SSE_BIN3, R, R, R, b, N, N, HF(h_sse_bin3))                    \
              \
  X(SSE_SHIFT,R, b, b, N, N, N, HF(h_sse_shift))                   \
    \
  X(AVX_LD256, R, R, R, b, d, N, HF(h_avx_ld256))                  \
  X(AVX_ST256, R, R, R, b, d, N, HF(h_avx_st256))                  \
  X(AVX_MOV256,R, R, N, N, N, N, HF(h_avx_mov256))                 \
  X(AVX_BIN3_256, R, R, R, b, N, N, HF(h_avx_bin3_256))            \
  X(AVX_EX128,   R, R, b, N, N, N, HF(h_avx_ex128))                \
  X(AVX_INS128,  R, R, R, b, N, N, HF(h_avx_ins128))               \
  X(AVX_STL128,  R, R, R, b, d, b, HF(h_avx_stl128))               \
  X(AVX_LDL128,  R, R, R, b, d, b, HF(h_avx_ldl128))               \
  X(AVX_BCAST,   R, R, b, N, N, N, HF(h_avx_bcast))                \
  X(AVX_BINM256, R, R, R, b, d, b, HF(h_avx_binm256))             \
  X(MOVZX8,   R, R, N, N, N, N, HF(h_movzx8))                      \
  X(MOVZX16,  R, R, N, N, N, N, HF(h_movzx16))                     \
  X(MOVSX8,   R, R, N, N, N, N, HF(h_movsx8))                      \
  X(MOVSX16,  R, R, N, N, N, N, HF(h_movsx16))                     \
  X(MOVSXD,   R, R, N, N, N, N, HF(h_movsxd))                      \
  X(LEA,      R, R, R, b, d, N, HF(h_lea))                         \
  X(XCHG,     R, R, N, N, N, N, HF(h_xchg))                        \
  X(CMOV8,    R, R, b, N, N, N, HF(h_cmov8))                       \
  X(CMOV16,   R, R, b, N, N, N, HF(h_cmov16))                      \
  X(CMOV32,   R, R, b, N, N, N, HF(h_cmov32))                      \
  X(CMOV,     R, R, b, N, N, N, HF(h_cmov))                        \
  X(BSWAP,    R, N, N, N, N, N, HF(h_bswap))                       \
  X(CDQ,      N, N, N, N, N, N, HF(h_cdq))                         \
  X(CQO,      N, N, N, N, N, N, HF(h_cqo))                         \
                                 \
  HYDA_ALU4(X, ADD, h_alu_add)                                     \
  HYDA_ALU4(X, ADC, h_alu_adc)                                     \
  HYDA_ALU4(X, SUB, h_alu_sub)                                     \
  HYDA_ALU4(X, SBB, h_alu_sbb)                                     \
  HYDA_ALU4(X, AND, h_alu_and)                                     \
  HYDA_ALU4(X, OR,  h_alu_or)                                      \
  HYDA_ALU4(X, XOR, h_alu_xor)                                     \
  HYDA_ALU4(X, CMP, h_alu_cmp)                                     \
   \
  HYDA_NF_ALU4(X, ADC, h_alu_adc_nf)                               \
  HYDA_NF_ALU4(X, ADD, h_alu_add_nf)                               \
  HYDA_NF_ALU4(X, SUB, h_alu_sub_nf)                               \
  HYDA_NF_ALU4(X, SBB, h_alu_sbb_nf)                               \
  HYDA_NF_ALU4(X, AND, h_alu_and_nf)                               \
  HYDA_NF_ALU4(X, OR,  h_alu_or_nf)                                \
  HYDA_NF_ALU4(X, XOR, h_alu_xor_nf)                               \
  HYDA_NF_SZ4(X, INC, h_inc_nf)                                    \
  HYDA_NF_SZ4(X, DEC, h_dec_nf)                                    \
  HYDA_NF_SZ4(X, NEG, h_neg_nf)                                    \
    \
  HYDA_BODY_ALU4(X, ADD, h_alu_add_b)                              \
  HYDA_BODY_ALU4(X, SUB, h_alu_sub_b)                              \
  HYDA_BODY_ALU4(X, AND, h_alu_and_b)                              \
  HYDA_BODY_ALU4(X, OR,  h_alu_or_b)                               \
  HYDA_BODY_ALU4(X, XOR, h_alu_xor_b)                             \
  X(INC_B,    R, N, N, N, N, N, HF(h_inc_b))                         \
  X(DEC32_B,  R, N, N, N, N, N, HF(h_dec_b<32>))                     \
  X(DEC_B,    R, N, N, N, N, N, HF(h_dec_b<64>))                     \
   \
  HYDA_BODY2_ALU4(X, ADD, h_alu_add_b2)                            \
  HYDA_BODY2_ALU4(X, SUB, h_alu_sub_b2)                            \
  HYDA_BODY2_ALU4(X, AND, h_alu_and_b2)                            \
  HYDA_BODY2_ALU4(X, OR,  h_alu_or_b2)                             \
  HYDA_BODY2_ALU4(X, XOR, h_alu_xor_b2)                            \
  X(INC_B2,   R, N, N, N, N, N, HF(h_inc_b2))                        \
  X(DEC32_B2, R, N, N, N, N, N, HF(h_dec_b2<32>))                    \
  X(DEC_B2,   R, N, N, N, N, N, HF(h_dec_b2<64>))                    \
   \
  HYDA_BODY3_ALU4(X, ADD, h_alu_add_b3)                            \
  HYDA_BODY3_ALU4(X, SUB, h_alu_sub_b3)                            \
  HYDA_BODY3_ALU4(X, AND, h_alu_and_b3)                            \
  HYDA_BODY3_ALU4(X, OR,  h_alu_or_b3)                             \
  HYDA_BODY3_ALU4(X, XOR, h_alu_xor_b3)                            \
  X(INC_B3,   R, N, N, N, N, N, HF(h_inc_b3))                        \
  X(DEC32_B3, R, N, N, N, N, N, HF(h_dec_b3<32>))                    \
  X(DEC_B3,   R, N, N, N, N, N, HF(h_dec_b3<64>))                    \
   \
  X(ADD64_N,  R, R, N, N, N, N, HF(h_alu_add_n<64>))                 \
  X(SUB64_N,  R, R, N, N, N, N, HF(h_alu_sub_n<64>))                 \
  X(XOR64_N,  R, R, N, N, N, N, HF(h_alu_xor_n<64>))                 \
  X(INC8,     R, N, N, N, N, N, HF(h_inc8))                        \
  X(INC16,    R, N, N, N, N, N, HF(h_inc16))                       \
  X(INC32,    R, N, N, N, N, N, HF(h_inc32))                       \
  X(INC,      R, N, N, N, N, N, HF(h_inc))                         \
  X(DEC8,     R, N, N, N, N, N, HF(h_dec8))                        \
  X(DEC16,    R, N, N, N, N, N, HF(h_dec16))                       \
  X(DEC32,    R, N, N, N, N, N, HF(h_dec32))                       \
  X(DEC,      R, N, N, N, N, N, HF(h_dec))                         \
  X(NOT8,     R, N, N, N, N, N, HF(h_not8))                        \
  X(NOT16,    R, N, N, N, N, N, HF(h_not16))                       \
  X(NOT32,    R, N, N, N, N, N, HF(h_not32))                       \
  X(NOT,      R, N, N, N, N, N, HF(h_not))                         \
  X(NEG8,     R, N, N, N, N, N, HF(h_neg8))                        \
  X(NEG16,    R, N, N, N, N, N, HF(h_neg16))                       \
  X(NEG32,    R, N, N, N, N, N, HF(h_neg32))                       \
  X(NEG,      R, N, N, N, N, N, HF(h_neg))                         \
  X(SHL8,     R, b, N, N, N, N, HF(h_shl8))                        \
  X(SHL16,    R, b, N, N, N, N, HF(h_shl16))                       \
  X(SHL32,    R, b, N, N, N, N, HF(h_shl32))                       \
  X(SHL,      R, b, N, N, N, N, HF(h_shl))                         \
  X(SHR8,     R, b, N, N, N, N, HF(h_shr8))                        \
  X(SHR16,    R, b, N, N, N, N, HF(h_shr16))                       \
  X(SHR32,    R, b, N, N, N, N, HF(h_shr32))                       \
  X(SHR,      R, b, N, N, N, N, HF(h_shr))                         \
  X(SAR8,     R, b, N, N, N, N, HF(h_sar8))                        \
  X(SAR16,    R, b, N, N, N, N, HF(h_sar16))                       \
  X(SAR32,    R, b, N, N, N, N, HF(h_sar32))                       \
  X(SAR,      R, b, N, N, N, N, HF(h_sar))                         \
  X(ROL8,     R, b, N, N, N, N, HF(h_rol8))                        \
  X(ROL16,    R, b, N, N, N, N, HF(h_rol16))                       \
  X(ROL32,    R, b, N, N, N, N, HF(h_rol32))                       \
  X(ROL,      R, b, N, N, N, N, HF(h_rol))                         \
  X(ROR8,     R, b, N, N, N, N, HF(h_ror8))                        \
  X(ROR16,    R, b, N, N, N, N, HF(h_ror16))                       \
  X(ROR32,    R, b, N, N, N, N, HF(h_ror32))                       \
  X(ROR,      R, b, N, N, N, N, HF(h_ror))                         \
  HYDA_SHIFTV4(X, SHL, shl_v_impl)                                 \
  HYDA_SHIFTV4(X, SHR, shr_v_impl)                                 \
  HYDA_SHIFTV4(X, SAR, sar_v_impl)                                 \
  HYDA_SHIFTV4(X, ROL, rol_v_impl)                                 \
  HYDA_SHIFTV4(X, ROR, ror_v_impl)                                 \
  HYDA_SZ4(X, MUL,  mul_impl)                                      \
  HYDA_SZ4(X, IMUL, imul1_impl)                                    \
  HYDA_SZ4(X, DIV,  div_impl)                                      \
  HYDA_SZ4(X, IDIV, idiv_impl)                                     \
  X(IMUL2_16, R, R, N, N, N, N, HF(imul2_impl<16>))                \
  X(IMUL2_32, R, R, N, N, N, N, HF(imul2_impl<32>))                \
  X(IMUL2,    R, R, N, N, N, N, HF(imul2_impl<64>))                \
  X(TEST,     R, R, N, N, N, N, HF(h_test))                        \
  X(BSF,      R, R, N, N, N, N, HF(h_bsf))                         \
  X(BSR,      R, R, N, N, N, N, HF(h_bsr))                         \
  X(TZCNT,    R, R, b, N, N, N, HF(h_tzcnt))                       \
  X(LZCNT,    R, R, b, N, N, N, HF(h_lzcnt))                       \
  X(POPCNT,   R, R, b, N, N, N, HF(h_popcnt))                      \
  X(BT,       R, R, N, N, N, N, HF(h_bt))                          \
  X(BTS,      R, R, N, N, N, N, HF(h_bts))                         \
  X(BTR,      R, R, N, N, N, N, HF(h_btr))                         \
  X(BTC,      R, R, N, N, N, N, HF(h_btc))                         \
                                      \
  X(JMP,      d, N, N, N, N, N, HF(h_jmp))                         \
  X(JMP_R,    R, N, N, N, N, N, HF(h_jmp_r))                       \
  X(CALL,     d, N, N, N, N, N, HF(h_call))                        \
  X(RET,      N, N, N, N, N, N, HF(h_ret))                         \
  X(RET_IMM,  d, N, N, N, N, N, HF(h_ret_imm))                     \
  X(JCC_O,    d, N, N, N, N, N, HF(h_jcc_o))                       \
  X(JCC_NO,   d, N, N, N, N, N, HF(h_jcc_no))                      \
  X(JCC_B,    d, N, N, N, N, N, HF(h_jcc_b))                       \
  X(JCC_AE,   d, N, N, N, N, N, HF(h_jcc_ae))                      \
  X(JCC_Z,    d, N, N, N, N, N, HF(h_jcc_z))                       \
  X(JCC_NZ,   d, N, N, N, N, N, HF(h_jcc_nz))                      \
  X(JCC_BE,   d, N, N, N, N, N, HF(h_jcc_be))                      \
  X(JCC_A,    d, N, N, N, N, N, HF(h_jcc_a))                       \
  X(JCC_S,    d, N, N, N, N, N, HF(h_jcc_s))                       \
  X(JCC_NS,   d, N, N, N, N, N, HF(h_jcc_ns))                      \
  X(JCC_P,    d, N, N, N, N, N, HF(h_jcc_p))                       \
  X(JCC_NP,   d, N, N, N, N, N, HF(h_jcc_np))                      \
  X(JCC_L,    d, N, N, N, N, N, HF(h_jcc_l))                       \
  X(JCC_GE,   d, N, N, N, N, N, HF(h_jcc_ge))                      \
  X(JCC_LE,   d, N, N, N, N, N, HF(h_jcc_le))                      \
  X(JCC_G,    d, N, N, N, N, N, HF(h_jcc_g))                       \
    \
   \
  X(CMP_JCC,  R, R, b, b, b, d, HF(h_cmp_jcc))                     \
           \
   \
  X(ALU_JCC,  R, R, b, b, b, d, HF(h_alu_jcc))                     \
                            \
   \
   \
  X(NATIVE_GATE, R, d, N, N, N, N, HF(h_native_gate))

#define HYDA_MK_ENUM(NAME, ...) NAME,
#define HYDA_MK_SIG(NAME, A, B, C, D, E, F, ...) \
  Sig{Opr::A, Opr::B, Opr::C, Opr::D, Opr::E, Opr::F},
#define HYDA_MK_NAME(NAME, ...) #NAME,

enum class Op : uint16_t {
  HYDA_OPCODES(HYDA_MK_ENUM)
  OP_COUNT_
};

constexpr size_t OP_COUNT = static_cast<size_t>(Op::OP_COUNT_);
static_assert(OP_COUNT <= kSlotCount, "opcode count exceeds slot space");
static_assert(sizeof(Op) == 2, "A3: Op must be 16-bit");
static_assert(kSlotCount > 256, "A3: slot space must exceed the 8-bit ceiling");

constexpr Sig OP_SIGS[OP_COUNT] = {HYDA_OPCODES(HYDA_MK_SIG)};
const char* const OP_NAMES[OP_COUNT] = {HYDA_OPCODES(HYDA_MK_NAME)};

constexpr bool is_xmm_op(Op o) {
  return o >= Op::SSE_LD16 && o <= Op::AVX_BINM256;
}

constexpr unsigned op_size(Op o) { return sig_size(OP_SIGS[static_cast<size_t>(o)]); }

#define HYDA_NF_PAIRS(X)                                                       \
  X(ADC8, ADC8_NF) X(ADC16, ADC16_NF) X(ADC32, ADC32_NF) X(ADC64, ADC64_NF)     \
  X(ADD8, ADD8_NF) X(ADD16, ADD16_NF) X(ADD32, ADD32_NF) X(ADD64, ADD64_NF)     \
  X(SUB8, SUB8_NF) X(SUB16, SUB16_NF) X(SUB32, SUB32_NF) X(SUB64, SUB64_NF)     \
  X(SBB8, SBB8_NF) X(SBB16, SBB16_NF) X(SBB32, SBB32_NF) X(SBB64, SBB64_NF)     \
  X(AND8, AND8_NF) X(AND16, AND16_NF) X(AND32, AND32_NF) X(AND64, AND64_NF)     \
  X(OR8, OR8_NF) X(OR16, OR16_NF) X(OR32, OR32_NF) X(OR64, OR64_NF)             \
  X(XOR8, XOR8_NF) X(XOR16, XOR16_NF) X(XOR32, XOR32_NF) X(XOR64, XOR64_NF)     \
  X(INC8, INC8_NF) X(INC16, INC16_NF) X(INC32, INC32_NF) X(INC, INC64_NF)       \
  X(DEC8, DEC8_NF) X(DEC16, DEC16_NF) X(DEC32, DEC32_NF) X(DEC, DEC64_NF)       \
  X(NEG8, NEG8_NF) X(NEG16, NEG16_NF) X(NEG32, NEG32_NF) X(NEG, NEG64_NF)

#define HYDA_BODY_PAIRS(X)                                                    \
  X(ADD32, ADD32_B) X(ADD64, ADD64_B)                                        \
  X(SUB32, SUB32_B) X(SUB64, SUB64_B)                                        \
  X(AND32, AND32_B) X(AND64, AND64_B)                                        \
  X(OR32, OR32_B)   X(OR64, OR64_B)                                          \
  X(XOR32, XOR32_B) X(XOR64, XOR64_B)                                        \
  X(INC, INC_B)                                                              \
  X(DEC32, DEC32_B) X(DEC, DEC_B)

inline Op body_variant(Op o) {
  switch (o) {
#define HYDA_BODY_PAIR_CASE(A, B) case Op::A: return Op::B;
    HYDA_BODY_PAIRS(HYDA_BODY_PAIR_CASE)
#undef HYDA_BODY_PAIR_CASE
    default: return o;
  }
}

inline Op nf_variant(Op o) {
  switch (o) {
#define HYDA_NF_PAIR_CASE(A, B) case Op::A: return Op::B;
    HYDA_NF_PAIRS(HYDA_NF_PAIR_CASE)
#undef HYDA_NF_PAIR_CASE
    default: return o;
  }
}

#define HYDA_BODY2_PAIRS(X)                                                    \
  X(ADD32, ADD32_B2) X(ADD64, ADD64_B2)                                        \
  X(SUB32, SUB32_B2) X(SUB64, SUB64_B2)                                        \
  X(AND32, AND32_B2) X(AND64, AND64_B2)                                        \
  X(OR32, OR32_B2)   X(OR64, OR64_B2)                                          \
  X(XOR32, XOR32_B2) X(XOR64, XOR64_B2)                                        \
  X(INC, INC_B2)                                                              \
  X(DEC32, DEC32_B2) X(DEC, DEC_B2)

inline Op body2_variant(Op o) {
  switch (o) {
#define HYDA_BODY2_PAIR_CASE(A, B) case Op::A: return Op::B;
    HYDA_BODY2_PAIRS(HYDA_BODY2_PAIR_CASE)
#undef HYDA_BODY2_PAIR_CASE
    default: return o;
  }
}

#define HYDA_BODY3_PAIRS(X)                                                    \
  X(ADD32, ADD32_B3) X(ADD64, ADD64_B3)                                        \
  X(SUB32, SUB32_B3) X(SUB64, SUB64_B3)                                        \
  X(AND32, AND32_B3) X(AND64, AND64_B3)                                        \
  X(OR32, OR32_B3)   X(OR64, OR64_B3)                                          \
  X(XOR32, XOR32_B3) X(XOR64, XOR64_B3)                                        \
  X(INC, INC_B3)                                                              \
  X(DEC32, DEC32_B3) X(DEC, DEC_B3)

inline Op body3_variant(Op o) {
  switch (o) {
#define HYDA_BODY3_PAIR_CASE(A, B) case Op::A: return Op::B;
    HYDA_BODY3_PAIRS(HYDA_BODY3_PAIR_CASE)
#undef HYDA_BODY3_PAIR_CASE
    default: return o;
  }
}

inline Op pick_body(Op base, uint64_t seed, uint64_t site) {
  uint64_t s = seed ^ (site * 0x9E3779B97F4A7C15ull);
  s += 0x9E3779B97F4A7C15ull;
  s = (s ^ (s >> 30)) * 0xBF58476D1CE4E5B9ull;
  s = (s ^ (s >> 27)) * 0x94D049BB133111EBull;
  s ^= s >> 31;
  switch (s % 4u) {
    case 1: return body_variant(base);
    case 2: return body2_variant(base);
    case 3: return body3_variant(base);
    default: return base;
  }
}

constexpr unsigned leading_reg_count(Sig s) {
  const Opr k[6] = {s.a, s.b, s.c, s.d, s.e, s.f};
  unsigned n = 0;
  while (n < 6 && k[n] == Opr::R) ++n;
  return n;
}

constexpr bool reg_operands_are_leading(Sig s) {
  const Opr k[6] = {s.a, s.b, s.c, s.d, s.e, s.f};
  bool after = false;
  for (unsigned i = 0; i < 6; ++i) {
    if (k[i] == Opr::R) {
      if (after) return false;
    } else if (k[i] != Opr::N) {
      after = true;
    }
  }
  return true;
}

constexpr bool all_reg_operands_leading() {
  for (size_t i = 0; i < OP_COUNT; ++i) {
    if (!reg_operands_are_leading(OP_SIGS[i])) return false;
  }
  return true;
}

static_assert(all_reg_operands_leading(),
              "register operands must come first in the signature: the dispatcher's "
              "register validation relies on this invariant");

constexpr uint64_t splitmix64(uint64_t& x) {
  x += 0x9E3779B97F4A7C15ull;
  uint64_t z = x;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

inline constexpr uint64_t kCodegenSeed = HYDA_VM_SEED ^ 0x8B1F2C3D4E5A6B7Cull;

inline uint64_t codegen_seed() {
  return vm_seed() ^ 0x8B1F2C3D4E5A6B7Cull;
}

inline bool body_variant_pick(Op o, uint64_t seed) {
  uint64_t s = seed ^ (static_cast<uint64_t>(o) * 0x9E3779B97F4A7C15ull);
  return (splitmix64(s) & 1u) != 0;
}

inline Op nested_op(uint64_t seed) {
  uint64_t s = seed ^ 0x7C9E1D3B5A284F61ull;
  const uint64_t k = splitmix64(s) % 3u;
  return k == 0 ? Op::ADD64 : (k == 1 ? Op::SUB64 : Op::XOR64);
}

inline Op nested_variant(Op o) {
  switch (o) {
    case Op::ADD64: return Op::ADD64_N;
    case Op::SUB64: return Op::SUB64_N;
    case Op::XOR64: return Op::XOR64_N;
    default: return o;
  }
}

constexpr uint16_t BAD_SLOT = 0xFFFF;

inline void opmap_fill(uint16_t* op_of_slot, uint16_t* slot_of_op,
                       uint64_t seed) {
  volatile uint16_t* vd = op_of_slot;
  for (size_t i = 0; i < kSlotCount; ++i) vd[i] = BAD_SLOT;

  uint16_t pool[kSlotCount];
  for (size_t i = 0; i < kSlotCount; ++i) pool[i] = static_cast<uint16_t>(i);

  uint64_t s = seed;
  for (size_t op = 0; op < OP_COUNT; ++op) {
    const uint64_t r = splitmix64(s) % (kSlotCount - op);
    const uint16_t slot = pool[r];
    pool[r] = pool[kSlotCount - 1 - op];
    op_of_slot[slot] = static_cast<uint16_t>(op);
    slot_of_op[op] = slot;
  }
}

struct OpcodeMap {
  uint16_t op_of_slot[kSlotCount] = {};
  uint16_t slot_of_op[OP_COUNT] = {};
};

inline OpcodeMap g_opmap;
inline uint64_t g_opmap_used = 0;

inline void opmap_rebuild() {
  const uint64_t s = vm_seed();
  opmap_fill(g_opmap.op_of_slot, g_opmap.slot_of_op, s);
  g_opmap_used = s;
}

inline const OpcodeMap& opcode_map() {

  if (g_opmap_used != vm_seed()) opmap_rebuild();
  return g_opmap;
}

}
