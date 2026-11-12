#include "hyda/vm/vm.hpp"

#include "hyda/vm/dispatch.hpp"
#include "hyda/vm/dispatch_ring.hpp"

#include <cstddef>
#include <cstdint>

namespace {

// Dispatcher loop in raw x86-64. Contract:
//   rbx=ctx  r12=code  r13=size  r14=ring tables  r15=crypt key  rbp=table base
// Literals below mirror the C++ headers; static_asserts fail the build on drift.

#define HYDA_S2(x) #x
#define HYDA_S(x) HYDA_S2(x)

#define HYDA_CTX_RIP      128
#define HYDA_CTX_STATUS   2048
#define HYDA_CTX_STEPS    2056
#define HYDA_CTX_MAXSTEPS 2064

#define HYDA_NVREG      25
#define HYDA_NO_MEM     255
#define HYDA_ST_BAD_OPCODE 2
#define HYDA_ST_FAULT      3
#define HYDA_ST_STEP_LIMIT 5
#define HYDA_ST_BAD_REG    6

#define HYDA_DISP_SECRET 0x51ED2701B3F4A9C7
#define HYDA_DISP_BK1    0x3C6EF372
#define HYDA_DISP_BK2    0x5BD1E995
#define HYDA_DISP_K1     0x1B873593
#define HYDA_DISP_K2     0x27D4EB2D
#define HYDA_ENTRY_OPSZ_SHIFT   32
#define HYDA_ENTRY_REGCNT_SHIFT 40

#define HYDA_RING_SEL_K1 0x2545F491
#define HYDA_RING_SEL_K2 0x27D4EB2D
#define HYDA_RING_SEL_SHIFT 13
#define HYDA_RING_MASK   7
#define HYDA_RING_SHIFT  14
#define HYDA_RING_TABLES 8

#define HYDA_SLOTMASK    1023

#define HYDA_CRYPT_M1 0x2C1B3C6D
#define HYDA_CRYPT_M2 0x297A2D39
#define HYDA_CRYPT_M3 0x1B873593

static_assert(hyda::REG_RIP == 16, "REG_RIP changed");
static_assert(offsetof(hyda::VMContext, r) + hyda::REG_RIP * 8 == HYDA_CTX_RIP,
              "VMContext.r/REG_RIP ofseti degisti");
static_assert(offsetof(hyda::VMContext, status) == HYDA_CTX_STATUS,
              "VMContext.status offset changed");
static_assert(offsetof(hyda::VMContext, steps) == HYDA_CTX_STEPS,
              "VMContext.steps offset changed");
static_assert(offsetof(hyda::VMContext, max_steps) == HYDA_CTX_MAXSTEPS,
              "VMContext.max_steps offset changed");
static_assert(hyda::NVREG == HYDA_NVREG, "NVREG changed");
static_assert(hyda::NO_MEM == HYDA_NO_MEM, "NO_MEM changed");
static_assert(hyda::ST_BAD_OPCODE == HYDA_ST_BAD_OPCODE, "ST_BAD_OPCODE changed");
static_assert(hyda::ST_FAULT == HYDA_ST_FAULT, "ST_FAULT changed");
static_assert(hyda::ST_STEP_LIMIT == HYDA_ST_STEP_LIMIT, "ST_STEP_LIMIT changed");
static_assert(hyda::ST_BAD_REG == HYDA_ST_BAD_REG, "ST_BAD_REG changed");
static_assert(hyda::kDispatchSecret == 0x51ED2701B3F4A9C7ull,
              "handler table salt changed (asm mismatch)");
static_assert(hyda::kDispatchOpszShift == HYDA_ENTRY_OPSZ_SHIFT,
              "entry opsz field changed (asm mismatch)");
static_assert(hyda::kDispatchRegcntShift == HYDA_ENTRY_REGCNT_SHIFT,
              "entry regcnt field changed (asm mismatch)");
static_assert(hyda::kRingTables == HYDA_RING_TABLES,
              "ring size changed (asm mask mismatch)");
static_assert(hyda::kSlotMask == HYDA_SLOTMASK, "slot mask changed");
static_assert(hyda::kRingTableBytes == (1u << hyda::kRingIndexShift),
              "table stride mismatch");
static_assert((1u << HYDA_RING_SHIFT) == hyda::kRingTableBytes,
              "asm table stride mismatch");
static_assert(hyda::kRingSelK1 == HYDA_RING_SEL_K1, "ring selection K1 mismatch");
static_assert(hyda::kRingSelK2 == HYDA_RING_SEL_K2, "ring selection K2 mismatch");
static_assert(hyda::kRingSelShift == HYDA_RING_SEL_SHIFT,
              "ring selection shift mismatch");
static_assert(offsetof(hyda::DispatchProfile, key_variant) == 4,
              "profile key_variant offset changed");
static_assert(offsetof(hyda::DispatchProfile, base_variant) == 8,
              "profile base_variant offset changed");
static_assert(offsetof(hyda::DispatchProfile, entry_shift) == 12,
              "profile entry_shift offset changed");
static_assert(offsetof(hyda::DispatchProfile, call_style) == 16,
              "profile call_style offset changed");
static_assert(offsetof(hyda::DispatchProfile, crypt_variant) == 20,
              "profile crypt_variant offset changed");

#define HYDA_OFF_REGCNT  16
#define HYDA_OFF_SHIFT   20
#define HYDA_OFF_KEYVAR  24
#define HYDA_OFF_CALLST  28
#define HYDA_OFF_CRYPTV  32
#define HYDA_OFF_Z       40
#define HYDA_OFF_IDX     48
#define HYDA_OFF_E       56
#define HYDA_OFF_KEY     64
#define HYDA_OFF_BASE    72
#define HYDA_OFF_EPOCH   136

#define HYDA_OFF_K0      144
#define HYDA_OFF_K1      148
#define HYDA_OFF_EPOCHK  152
#define HYDA_FRAME       168

}

// codec_mix_core(i) for i = 0..255, used to decode slot bytes (see codec.hpp).
extern "C" const uint8_t hyda_sbox[256] = {
    0x00, 0x85, 0x0e, 0x70, 0x5a, 0x65, 0xe1, 0xf3, 0x99, 0x52, 0x3d, 0x9e, 0xce, 0xf9, 0x4d, 0x3e,
    0x7f, 0x50, 0xad, 0xec, 0x57, 0xdb, 0xfa, 0xaf, 0x7e, 0x8a, 0x61, 0xca, 0x51, 0x8d, 0x19, 0x03,
    0xff, 0x7b, 0xa0, 0x89, 0xf1, 0x54, 0xe4, 0x86, 0xda, 0x77, 0xd7, 0x6a, 0xf8, 0x96, 0x3f, 0x6d,
    0xfd, 0x8b, 0x10, 0x6e, 0x35, 0x83, 0xd9, 0x26, 0x55, 0x4a, 0xb0, 0x48, 0x81, 0x45, 0x73, 0xd3,
    0x01, 0x6c, 0xf7, 0x92, 0x69, 0xa5, 0x66, 0x62, 0x11, 0xf5, 0xd4, 0xa4, 0xcd, 0xe3, 0x7c, 0x5c,
    0xb9, 0xc7, 0xef, 0x64, 0xcf, 0x7a, 0x5b, 0xe2, 0x8e, 0xc8, 0x93, 0x44, 0xd6, 0xb8, 0x6f, 0x22,
    0x39, 0xee, 0x27, 0xa8, 0x23, 0x75, 0x24, 0xba, 0x0a, 0x97, 0x05, 0xdd, 0x76, 0x07, 0xb7, 0x06,
    0xe7, 0x79, 0x1a, 0x8c, 0x67, 0xab, 0x5e, 0x74, 0xed, 0xc2, 0x28, 0x38, 0x68, 0x56, 0xa1, 0x13,
    0x84, 0xa3, 0x31, 0xf4, 0x9b, 0xc5, 0xa6, 0xd5, 0x43, 0x15, 0xfc, 0xf6, 0x0b, 0x5d, 0xac, 0x7d,
    0x37, 0xfb, 0x29, 0x8f, 0xfe, 0x98, 0x41, 0xe8, 0xbf, 0xe9, 0xc1, 0x71, 0x36, 0x09, 0xd8, 0x9a,
    0x42, 0xdf, 0x0d, 0xd1, 0x30, 0xb5, 0x59, 0x2b, 0xbd, 0x2f, 0x94, 0x2d, 0xb6, 0x32, 0xe5, 0x25,
    0x18, 0x0f, 0x9d, 0xb4, 0x95, 0xcb, 0x91, 0xa2, 0x16, 0xea, 0x58, 0xa9, 0xe6, 0x80, 0xb2, 0x3b,
    0xc0, 0x14, 0x90, 0x53, 0x33, 0x3c, 0xa7, 0xc6, 0x72, 0x34, 0x0c, 0x20, 0x49, 0xcc, 0x1b, 0x1f,
    0x1d, 0x02, 0x2a, 0xae, 0x2e, 0xbb, 0xbe, 0x5f, 0xc9, 0x12, 0xf0, 0xe0, 0x6b, 0x87, 0xeb, 0xc3,
    0x82, 0x4e, 0x40, 0xf2, 0x60, 0xdc, 0xde, 0x9c, 0xaa, 0x4f, 0xc4, 0x1c, 0xbc, 0x21, 0x17, 0x4c,
    0x9f, 0x3a, 0xd0, 0x2c, 0x04, 0x63, 0x78, 0xb1, 0x46, 0x08, 0x88, 0x1e, 0x47, 0xd2, 0x4b, 0xb3,
};

extern "C" __attribute__((naked, noinline))
uint32_t hyda_vm_run_asm(hyda::VMContext* , const uint8_t* ,
                         size_t , uint64_t ) {
  __asm__(
#if defined(_WIN32)

      ".seh_proc hyda_vm_run_asm\n"
#endif
      ".intel_syntax noprefix\n"

      "push rbx\n"
      "push rbp\n"
      "push rsi\n"
      "push rdi\n"
      "push r12\n"
      "push r13\n"
      "push r14\n"
      "push r15\n"
      "sub rsp, " HYDA_S(HYDA_FRAME) "\n"
#if defined(_WIN32)
      ".seh_pushreg rbx\n"
      ".seh_pushreg rbp\n"
      ".seh_pushreg rsi\n"
      ".seh_pushreg rdi\n"
      ".seh_pushreg r12\n"
      ".seh_pushreg r13\n"
      ".seh_pushreg r14\n"
      ".seh_pushreg r15\n"
      ".seh_stackalloc " HYDA_S(HYDA_FRAME) "\n"
      ".seh_endprologue\n"
#endif

#if defined(_WIN32)
      "mov rbx, rcx\n"
      "mov r12, rdx\n"
      "mov r13, r8\n"
      "mov r15, r9\n"
#else
      "mov rbx, rdi\n"
      "mov r12, rsi\n"
      "mov r13, rdx\n"
      "mov r15, rcx\n"
#endif

      "lea r14, [rip + hyda_ring_tab]\n"

      "mov eax, dword ptr [rip + g_dispatch_profile + 4]\n"
      "mov dword ptr [rsp + " HYDA_S(HYDA_OFF_KEYVAR) "], eax\n"
      "mov eax, dword ptr [rip + g_dispatch_profile + 12]\n"
      "mov dword ptr [rsp + " HYDA_S(HYDA_OFF_SHIFT) "], eax\n"
      "mov eax, dword ptr [rip + g_dispatch_profile + 16]\n"
      "mov dword ptr [rsp + " HYDA_S(HYDA_OFF_CALLST) "], eax\n"
      "mov eax, dword ptr [rip + g_dispatch_profile + 20]\n"
      "mov dword ptr [rsp + " HYDA_S(HYDA_OFF_CRYPTV) "], eax\n"

      "mov eax, dword ptr [rsp + " HYDA_S(HYDA_OFF_CRYPTV) "]\n"
      "imul rax, rax, 0x27D4EB2D\n"
      "xor rax, r15\n"
      "movabs rdx, 0xA24BAED4963EE407\n"
      "xor rax, rdx\n"
      "mov rdx, rax\n"
      "shr rdx, 31\n"
      "xor rax, rdx\n"
      "movabs rdx, 0x9E3779B97F4A7C15\n"
      "imul rax, rdx\n"
      "mov rdx, rax\n"
      "shr rdx, 29\n"
      "xor rax, rdx\n"
      "movabs rdx, 0xC2B2AE3D27D4EB4F\n"
      "imul rax, rdx\n"
      "mov rdx, rax\n"
      "shr rdx, 27\n"
      "xor rax, rdx\n"
      "mov dword ptr [rsp + " HYDA_S(HYDA_OFF_K0) "], eax\n"
      "mov rdx, rax\n"
      "shr rdx, 8\n"
      "mov dword ptr [rsp + " HYDA_S(HYDA_OFF_K1) "], edx\n"

      "mov rax, [rip + hyda_vm_epoch]\n"
      "add rax, 1\n"
      "mov [rip + hyda_vm_epoch], rax\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_EPOCH) "], rax\n"
      "imul rax, rax, " HYDA_S(HYDA_RING_SEL_K2) "\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_EPOCHK) "], rax\n"

      "xor r8d, r8d\n"
      "mov eax, dword ptr [rip + g_dispatch_profile + 8]\n"
      "cmp eax, 1\n"
      "je Lh_base_loop1\n"
      "cmp eax, 2\n"
      "je Lh_base_loop2\n"
      "cmp eax, 3\n"
      "je Lh_base_loop3\n"
      "jmp Lh_base_loop0\n"

      "Lh_base_loop0:\n"
      "mov rdx, r8\n"
      "shl rdx, " HYDA_S(HYDA_RING_SHIFT) "\n"
      "add rdx, r14\n"
      "movabs rax, " HYDA_S(HYDA_DISP_SECRET) "\n"
      "xor rax, rdx\n"
      "mov rsi, rax\n"
      "shr rsi, 31\n"
      "xor rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK1) "\n"
      "mov rsi, rax\n"
      "shr rsi, 29\n"
      "xor rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK2) "\n"
      "mov rsi, rax\n"
      "shr rsi, 31\n"
      "xor rax, rsi\n"
      "mov [rsp + r8*8 + " HYDA_S(HYDA_OFF_BASE) "], rax\n"
      "add r8, 1\n"
      "cmp r8, " HYDA_S(HYDA_RING_TABLES) "\n"
      "jb Lh_base_loop0\n"
      "jmp Lh_basedone\n"

      "Lh_base_loop1:\n"
      "mov rdx, r8\n"
      "shl rdx, " HYDA_S(HYDA_RING_SHIFT) "\n"
      "add rdx, r14\n"
      "movabs rax, " HYDA_S(HYDA_DISP_SECRET) "\n"
      "add rax, rdx\n"
      "mov rsi, rax\n"
      "shr rsi, 29\n"
      "xor rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK1) "\n"
      "mov rsi, rax\n"
      "shr rsi, 31\n"
      "xor rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK2) "\n"
      "mov rsi, rax\n"
      "shr rsi, 27\n"
      "xor rax, rsi\n"
      "mov [rsp + r8*8 + " HYDA_S(HYDA_OFF_BASE) "], rax\n"
      "add r8, 1\n"
      "cmp r8, " HYDA_S(HYDA_RING_TABLES) "\n"
      "jb Lh_base_loop1\n"
      "jmp Lh_basedone\n"

      "Lh_base_loop2:\n"
      "mov rdx, r8\n"
      "shl rdx, " HYDA_S(HYDA_RING_SHIFT) "\n"
      "add rdx, r14\n"
      "movabs rax, " HYDA_S(HYDA_DISP_SECRET) "\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK1) "\n"
      "xor rax, rdx\n"
      "mov rsi, rax\n"
      "shr rsi, 31\n"
      "xor rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK2) "\n"
      "mov rsi, rax\n"
      "shr rsi, 29\n"
      "xor rax, rsi\n"
      "movabs rsi, " HYDA_S(HYDA_DISP_SECRET) "\n"
      "add rax, rsi\n"
      "mov [rsp + r8*8 + " HYDA_S(HYDA_OFF_BASE) "], rax\n"
      "add r8, 1\n"
      "cmp r8, " HYDA_S(HYDA_RING_TABLES) "\n"
      "jb Lh_base_loop2\n"
      "jmp Lh_basedone\n"

      "Lh_base_loop3:\n"
      "mov rdx, r8\n"
      "shl rdx, " HYDA_S(HYDA_RING_SHIFT) "\n"
      "add rdx, r14\n"
      "movabs rax, " HYDA_S(HYDA_DISP_SECRET) "\n"
      "xor rax, rdx\n"
      "mov esi, " HYDA_S(HYDA_DISP_BK2) "\n"
      "add rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK1) "\n"
      "mov rsi, rax\n"
      "shr rsi, 31\n"
      "xor rax, rsi\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_BK2) "\n"
      "mov rsi, rax\n"
      "shr rsi, 27\n"
      "xor rax, rsi\n"
      "mov [rsp + r8*8 + " HYDA_S(HYDA_OFF_BASE) "], rax\n"
      "add r8, 1\n"
      "cmp r8, " HYDA_S(HYDA_RING_TABLES) "\n"
      "jb Lh_base_loop3\n"
      "Lh_basedone:\n"

      "Lh_loop:\n"

      "mov rax, [rbx + " HYDA_S(HYDA_CTX_RIP) "]\n"
      "cmp rax, r13\n"
      "jae Lh_fault\n"
      "mov r11, rax\n"

      "mov r8, rax\n"
      "shr r8, 3\n"
      "add r8, rax\n"
      "imul r8, r8, " HYDA_S(HYDA_RING_SEL_K1) "\n"
      "add r8, [rsp + " HYDA_S(HYDA_OFF_EPOCHK) "]\n"
      "mov rdx, r8\n"
      "shr rdx, " HYDA_S(HYDA_RING_SEL_SHIFT) "\n"
      "xor r8, rdx\n"
      "and r8d, " HYDA_S(HYDA_RING_MASK) "\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_E) "], r8\n"

      "lea rdx, [r11 + 2]\n"
      "cmp rdx, r13\n"
      "ja Lh_fault\n"
      "test r15, r15\n"
      "jz Lh_plain_slot\n"

      "mov rax, r11\n"
      "xor rax, r15\n"
      "imul rax, rax, " HYDA_S(HYDA_CRYPT_M1) "\n"
      "mov rdx, rax\n"
      "shr rdx, 29\n"
      "xor rax, rdx\n"
      "imul rax, rax, " HYDA_S(HYDA_CRYPT_M2) "\n"
      "mov rdx, rax\n"
      "shr rdx, 32\n"
      "xor rax, rdx\n"
      "imul rax, rax, " HYDA_S(HYDA_CRYPT_M3) "\n"
      "mov rdx, rax\n"
      "shr rdx, 29\n"
      "xor rax, rdx\n"
      "mov rbp, rax\n"

      "movzx ecx, byte ptr [rsp + " HYDA_S(HYDA_OFF_K0) "]\n"
      "xor cl, al\n"
      "movzx edi, byte ptr [rsp + " HYDA_S(HYDA_OFF_K1) "]\n"
      "mov rdx, rax\n"
      "shr rdx, 16\n"
      "xor dil, dl\n"
      "mov r9, rax\n"
      "shr r9, 8\n"
      "mov r10, rax\n"
      "shr r10, 24\n"

      "movzx eax, byte ptr [r12 + r11]\n"
      "xor al, r9b\n"
      "xor al, cl\n"
      "lea rdx, [rip + hyda_sbox]\n"
      "movzx eax, byte ptr [rdx + rax]\n"
      "movzx esi, al\n"

      "movzx edx, byte ptr [r12 + r11 + 1]\n"
      "xor dl, dil\n"
      "lea rdi, [rip + hyda_sbox]\n"
      "movzx edx, byte ptr [rdi + rdx]\n"

      "mov eax, esi\n"
      "xor al, r10b\n"
      "movzx eax, al\n"
      "shl edx, 8\n"
      "or eax, edx\n"
      "and eax, " HYDA_S(HYDA_SLOTMASK) "\n"
      "mov ecx, eax\n"

      "mov edx, ecx\n"
      "imul rdx, rdx, 0x27D4EB2D\n"
      "xor rbp, rdx\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_Z) "], rbp\n"
      "Lh_slot_ready:\n"

      "mov rdx, r8\n"
      "shl rdx, 11\n"
      "lea r9, [rip + hyda_ring_perm]\n"
      "add rdx, r9\n"
      "movzx r10d, word ptr [rdx + rcx*2]\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_IDX) "], r10\n"

      "mov rbp, [rsp + r8*8 + " HYDA_S(HYDA_OFF_BASE) "]\n"

      "cmp dword ptr [rsp + " HYDA_S(HYDA_OFF_KEYVAR) "], 0\n"
      "jne Lh_key1\n"

      "mov edx, r10d\n"
      "imul rdx, rdx, " HYDA_S(HYDA_DISP_K1) "\n"
      "xor rdx, rbp\n"
      "mov rax, rdx\n"
      "shr rax, 27\n"
      "xor rax, rdx\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_K2) "\n"
      "mov rdx, rax\n"
      "shr rdx, 31\n"
      "xor rax, rdx\n"
      "jmp Lh_keydone\n"

      "Lh_key1:\n"
      "mov edx, r10d\n"
      "imul rdx, rdx, " HYDA_S(HYDA_DISP_K2) "\n"
      "add rdx, rbp\n"
      "mov rax, rdx\n"
      "shr rax, 31\n"
      "xor rax, rdx\n"
      "imul rax, rax, " HYDA_S(HYDA_DISP_K1) "\n"
      "mov rdx, rax\n"
      "shr rdx, 29\n"
      "xor rax, rdx\n"
      "xor rax, rbp\n"
      "Lh_keydone:\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_KEY) "], rax\n"

      "mov rdi, r8\n"
      "shl rdi, " HYDA_S(HYDA_RING_SHIFT) "\n"
      "add rdi, r14\n"
      "mov ecx, dword ptr [rsp + " HYDA_S(HYDA_OFF_SHIFT) "]\n"
      "mov rdx, r10\n"
      "shl rdx, cl\n"
      "add rdx, rdi\n"
      "mov rdx, [rdx]\n"
      "xor rdx, rax\n"

      "movsxd r9, edx\n"
      "add r9, rdi\n"

      "cmp r9, [rip + hyda_handler_lo]\n"
      "jb Lh_fault\n"
      "cmp r9, [rip + hyda_handler_hi]\n"
      "jae Lh_fault\n"

      "mov rsi, rdx\n"
      "shr rsi, " HYDA_S(HYDA_ENTRY_OPSZ_SHIFT) "\n"
      "and esi, 0xFF\n"
      "mov rdi, rdx\n"
      "shr rdi, " HYDA_S(HYDA_ENTRY_REGCNT_SHIFT) "\n"
      "mov [rsp + " HYDA_S(HYDA_OFF_REGCNT) "], dil\n"

      "lea rdx, [r11 + rsi + 2]\n"
      "cmp rdx, r13\n"
      "ja Lh_fault\n"
      "mov [rbx + " HYDA_S(HYDA_CTX_RIP) "], rdx\n"

      "mov rdi, [rbx + " HYDA_S(HYDA_CTX_MAXSTEPS) "]\n"
      "test rdi, rdi\n"
      "jz Lh_nosteps\n"
      "mov r8, [rbx + " HYDA_S(HYDA_CTX_STEPS) "]\n"
      "inc r8\n"
      "mov [rbx + " HYDA_S(HYDA_CTX_STEPS) "], r8\n"
      "cmp r8, rdi\n"
      "ja Lh_steplimit\n"
      "Lh_nosteps:\n"

      "lea r10, [r12 + r11 + 2]\n"
      "test r15, r15\n"
      "jz Lh_plain\n"
      "test esi, esi\n"
      "jz Lh_plain\n"

      "mov rax, [rsp + " HYDA_S(HYDA_OFF_Z) "]\n"

      "xor edi, edi\n"
      "Lh_crypt:\n"
      "cmp edi, esi\n"
      "jae Lh_cryptdone\n"

      "cmp dword ptr [rsp + " HYDA_S(HYDA_OFF_CRYPTV) "], 0\n"
      "je Lh_crypt_v0\n"
      "mov ecx, edi\n"
      "xor ecx, 1\n"
      "and ecx, 7\n"
      "shl ecx, 3\n"
      "mov rdx, rax\n"
      "shr rdx, cl\n"
      "mov ecx, edi\n"
      "add ecx, 4\n"
      "xor ecx, 1\n"
      "and ecx, 7\n"
      "shl ecx, 3\n"
      "mov r8, rax\n"
      "shr r8, cl\n"
      "xor dl, r8b\n"
      "jmp Lh_crypt_xordone\n"
      "Lh_crypt_v0:\n"
      "mov ecx, edi\n"
      "and ecx, 7\n"
      "shl ecx, 3\n"
      "mov rdx, rax\n"
      "shr rdx, cl\n"
      "add ecx, 32\n"
      "and ecx, 63\n"
      "mov r8, rax\n"
      "shr r8, cl\n"
      "xor dl, r8b\n"
      "Lh_crypt_xordone:\n"
      "cmp edi, 8\n"
      "jb Lh_noflip\n"
      "xor dl, 0xA5\n"
      "Lh_noflip:\n"
      "mov r8b, [r10 + rdi]\n"
      "sub r8b, dl\n"
      "test edi, edi\n"
      "jz Lh_nofb\n"
      "sub r8b, [r10 + rdi - 1]\n"
      "Lh_nofb:\n"
      "mov [rsp + rdi], r8b\n"
      "inc edi\n"
      "jmp Lh_crypt\n"
      "Lh_cryptdone:\n"
      "mov rsi, rsp\n"
      "jmp Lh_call\n"
      "Lh_plain:\n"
      "mov rsi, r10\n"
      "Lh_call:\n"

      "movzx ecx, byte ptr [rsp + " HYDA_S(HYDA_OFF_REGCNT) "]\n"
      "test ecx, ecx\n"
      "jz Lh_regok\n"
      "xor edi, edi\n"
      "Lh_regchk:\n"
      "movzx edx, byte ptr [rsi + rdi]\n"
      "cmp edx, " HYDA_S(HYDA_NVREG) "\n"
      "jb Lh_regnext\n"
      "cmp edx, " HYDA_S(HYDA_NO_MEM) "\n"
      "jne Lh_badreg\n"
      "Lh_regnext:\n"
      "inc edi\n"
      "cmp edi, ecx\n"
      "jb Lh_regchk\n"
      "Lh_regok:\n"

#if defined(_WIN32)
      "mov rcx, rbx\n"
      "mov rdx, rsi\n"
#else
      "mov rdi, rbx\n"
#endif

      "cmp dword ptr [rsp + " HYDA_S(HYDA_OFF_CALLST) "], 0\n"
      "je Lh_calldirect\n"

      "mov r10, [rsp + " HYDA_S(HYDA_OFF_IDX) "]\n"
      "mov rax, [rsp + " HYDA_S(HYDA_OFF_E) "]\n"
      "shl rax, 13\n"
      "lea r11, [rip + hyda_ring_call]\n"
      "add r11, rax\n"
      "mov rax, [r11 + r10*8]\n"
      "xor rax, [rsp + " HYDA_S(HYDA_OFF_KEY) "]\n"
      "call rax\n"
      "jmp Lh_calldone\n"
      "Lh_calldirect:\n"
      "call r9\n"
      "Lh_calldone:\n"
      "cmp dword ptr [rbx + " HYDA_S(HYDA_CTX_STATUS) "], 0\n"
      "jne Lh_ret\n"
      "jmp Lh_loop\n"

      "Lh_plain_slot:\n"
      "movzx ecx, word ptr [r12 + r11]\n"
      "and ecx, " HYDA_S(HYDA_SLOTMASK) "\n"
      "jmp Lh_slot_ready\n"

      "Lh_fault:\n"
      "mov dword ptr [rbx + " HYDA_S(HYDA_CTX_STATUS) "], " HYDA_S(HYDA_ST_FAULT) "\n"
      "jmp Lh_ret\n"
      "Lh_badreg:\n"
      "mov dword ptr [rbx + " HYDA_S(HYDA_CTX_STATUS) "], " HYDA_S(HYDA_ST_BAD_REG) "\n"
      "jmp Lh_ret\n"
      "Lh_steplimit:\n"
      "mov dword ptr [rbx + " HYDA_S(HYDA_CTX_STATUS) "], " HYDA_S(HYDA_ST_STEP_LIMIT) "\n"

      "Lh_ret:\n"
      "mov eax, [rbx + " HYDA_S(HYDA_CTX_STATUS) "]\n"
      "add rsp, " HYDA_S(HYDA_FRAME) "\n"
      "pop r15\n"
      "pop r14\n"
      "pop r13\n"
      "pop r12\n"
      "pop rdi\n"
      "pop rsi\n"
      "pop rbp\n"
      "pop rbx\n"
      "ret\n"
      ".att_syntax prefix\n"
#if defined(_WIN32)
      ".seh_endproc\n"
#endif
      );
}
