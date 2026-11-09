#include "hyda/ir/assembler.hpp"
#include "hyda/ir/disasm.hpp"
#include "hyda/vm/vm.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#endif

using namespace hyda;

static int g_checks = 0;
static int g_fails = 0;

static void ck(bool ok, const char* what) {
  ++g_checks;
  if (!ok) {
    ++g_fails;
    std::printf("  FAIL: %s\n", what);
  }
}

static void ck_eq(uint64_t got, uint64_t want, const char* what) {
  ++g_checks;
  if (got != want) {
    ++g_fails;
    std::printf("  FAIL: %s  (got %llu, want %llu)\n", what,
                (unsigned long long)got, (unsigned long long)want);
  }
}

struct VmCall {
  uint64_t ret;
  uint32_t status;
  uint64_t rsp_after;
  uint64_t rsp_before;
  uint64_t steps;
  uint64_t rcx;
  uint64_t rflags;
  uint64_t noise;
};

static bool fbit(uint64_t flags, unsigned bit) {
  return ((flags >> bit) & 1u) != 0;
}

static VmCall vm_call(const Asm& prog, uint64_t entry,
                      uint64_t a0 = 0, uint64_t a1 = 0,
                      uint64_t a2 = 0, uint64_t a3 = 0) {
  alignas(64) static uint8_t stack[1 << 20];

  VMContext ctx;
  const uint64_t top =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stack)) + sizeof(stack) - 64;
  vm_init(ctx, top);

  ctx.max_steps = 20000000;

  ctx.r[vsl(REG_RCX)] = a0;
  ctx.r[vsl(REG_RDX)] = a1;
  ctx.r[vsl(REG_R8)] = a2;
  ctx.r[vsl(REG_R9)] = a3;
  vm_set_entry(ctx, entry);

  VmCall out;
  out.rsp_before = ctx.r[vsl(REG_RSP)];
  out.status = vm_exec(ctx, prog.code.data(), prog.code.size());
  out.rsp_after = ctx.r[vsl(REG_RSP)];
  out.ret = ctx.r[vsl(REG_RAX)];
  out.steps = ctx.steps;
  out.rcx = ctx.r[vsl(REG_RCX)];
  out.rflags = ctx.r[vsl(REG_RFLAGS)];
  out.noise = ctx.r[vsl(REG_NOISE)];
  return out;
}

static void test_add_halt() {
  Asm a;
  a.i_rr(Op::ADD64, REG_RCX, REG_RDX);
  a.i_rr(Op::ADD64, REG_R8, REG_R9);
  a.i_rr(Op::ADD64, REG_RCX, REG_R8);
  a.i_rr(Op::MOV_RR, REG_RAX, REG_RCX);
  a.i0(Op::HALT);
  a.finalize();

  const VmCall r = vm_call(a, 0, 1, 2, 3, 4);
  ck(r.status == ST_HALT, "ends with HALT");
  ck_eq(r.ret, 10, "1+2+3+4");
  ck_eq(r.rsp_after, r.rsp_before, "stack balanced");
}

static uint64_t native_fib(uint64_t n) { return n < 2 ? n : native_fib(n - 1) + native_fib(n - 2); }

static void test_recursive_fib() {

  Asm a;
  a.i_rq(Op::MOV_RI, REG_T0, 1);
  a.i_rq(Op::MOV_RI, REG_T1, 2);

  size_t fib = a.label();
  size_t rec = a.label();

  a.i_j(Op::CALL, fib);
  a.i0(Op::HALT);
  a.bind(fib);
  a.i_rr(Op::CMP64, REG_RCX, REG_T0);
  a.i_j(Op::JCC_A, rec);
  a.i_rr(Op::MOV_RR, REG_RAX, REG_RCX);
  a.i0(Op::RET);

  a.bind(rec);
  a.i_r(Op::PUSH_R, REG_RCX);
  a.i_rr(Op::SUB64, REG_RCX, REG_T0);
  a.i_j(Op::CALL, fib);
  a.i_r(Op::PUSH_R, REG_RAX);
  a.i_mem(Op::MOV_RM, REG_RCX, REG_RSP, NO_MEM, 1, 8);
  a.i_rr(Op::SUB64, REG_RCX, REG_T1);
  a.i_j(Op::CALL, fib);
  a.i_r(Op::POP_R, REG_RDX);
  a.i_rr(Op::ADD64, REG_RAX, REG_RDX);
  a.i_r(Op::POP_R, REG_RCX);
  a.i0(Op::RET);
  a.finalize();

  struct { uint64_t n, want; } cases[] = {
      {0, 0}, {1, 1}, {2, 1}, {5, 5}, {10, 55}, {15, 610}, {20, 6765}, {24, 46368}};

  for (const auto& c : cases) {
    const VmCall r = vm_call(a, 0, c.n);
    ck(r.status == ST_HALT, "fib: ends with HALT");
    ck_eq(r.ret, c.want, "fib(n)");
    ck_eq(r.ret, native_fib(c.n), "fib(n) == native");
    ck_eq(r.rsp_after, r.rsp_before, "fib: stack balanced");
  }
}

static void test_memory_writes() {
  static uint64_t buf[64];

  Asm a;
  a.i_rq(Op::MOV_RI, REG_RBX, (int64_t)(intptr_t)buf);
  a.i_rq(Op::MOV_RI, REG_RCX, 64);
  a.i_rq(Op::MOV_RI, REG_RAX, 0);

  size_t loop = a.label();
  a.bind(loop);
  a.i_mem(Op::MOV_MR, REG_RAX, REG_RBX, REG_RAX, 8, 0);
  a.i_r(Op::INC, REG_RAX);
  a.i_rr(Op::CMP64, REG_RAX, REG_RCX);
  a.i_j(Op::JCC_NZ, loop);
  a.i0(Op::HALT);
  a.finalize();

  std::memset(buf, 0, sizeof(buf));
  const VmCall r = vm_call(a, 0);
  ck(r.status == ST_HALT, "mem: ends with HALT");

  int bad = 0;
  for (unsigned i = 0; i < 64; ++i) {
    if (buf[i] != i) ++bad;
  }
  ck(bad == 0, "buf[i] == i (64 entries)");
}

static void test_mutation_ops() {

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, (int64_t)0x0F0F0F0F0F0F0F0Full);
    a.i_rr(Op::TEST, REG_RAX, REG_RAX);
    a.i_rq(Op::MOV_RI, REG_RCX, 1);
    a.i_r(Op::INV_R, REG_RAX);
    const size_t skip = a.label();
    a.i_j(Op::JCC_Z, skip);
    a.i_rq(Op::MOV_RI, REG_RCX, 2);
    a.i0(Op::HALT);
    a.bind(skip);
    a.i0(Op::HALT);
    a.finalize();

    const VmCall r = vm_call(a, 0);
    ck(r.status == ST_HALT, "inv_r: ends with HALT");
    ck_eq(r.ret, ~0x0F0F0F0F0F0F0F0Full, "inv_r: ~x");
    ck_eq(r.rcx, 2, "inv_r: JCC_Z not taken (flags preserved)");
    ck(!fbit(r.rflags, F_ZF), "inv_r: ZF preserved");
  }

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 0x1234);
    a.i_rr(Op::TEST, REG_RAX, REG_RAX);
    a.i_q(Op::VM_JUNK, (int64_t)0xDEADBEEFCAFEBABEull);
    a.i0(Op::HALT);
    a.finalize();

    const VmCall r = vm_call(a, 0);
    ck_eq(r.ret, 0x1234, "junk: rax preserved");
    ck(!fbit(r.rflags, F_ZF), "junk: flags preserved");
  }

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RAX, 0x1111);
    a.i_rq(Op::MOV_RI, REG_RCX, 0x2222);
    a.i_rq(Op::MOV_RI, REG_RDX, 0x3333);
    a.i_rq(Op::VM_NOISE, REG_NOISE, (int64_t)0xABCDEF);
    a.i0(Op::HALT);
    a.finalize();

    const VmCall r = vm_call(a, 0);
    ck_eq(r.ret, 0x1111, "noise: rax untouched");
    ck_eq(r.rcx, 0x2222, "noise: rcx untouched");
    ck(r.noise != 0, "noise: REG_NOISE changed");
  }
}

static void test_pe_context() {
#if defined(_WIN32)
  char exe[MAX_PATH] = {0};
  GetModuleFileNameA(nullptr, exe, MAX_PATH);
  std::printf("  module: %s\n", exe);

  std::FILE* f = std::fopen(exe, "rb");
  ck(f != nullptr, "own PE file opens");
  if (f) {
    uint8_t hdr[0x200];
    const size_t n = std::fread(hdr, 1, sizeof(hdr), f);
    std::fclose(f);
    ck(n >= 0x40, "DOS header readable");
    ck(hdr[0] == 'M' && hdr[1] == 'Z', "MZ signature");
    const uint32_t pe_off = *reinterpret_cast<uint32_t*>(hdr + 0x3C);
    ck(pe_off + 6 <= 0x200, "sane PE offset");
    ck(hdr[pe_off] == 'P' && hdr[pe_off + 1] == 'E' && hdr[pe_off + 2] == 0,
       "PE\\0 signature");
    const uint16_t magic = *reinterpret_cast<uint16_t*>(hdr + pe_off + 24);
    std::printf("  PE magic: 0x%04x (%s)\n", magic,
                magic == 0x20B ? "PE32+" : magic == 0x10B ? "PE32" : "unknown");
    ck(magic == 0x20B || magic == 0x10B, "PE32/PE32+");
  }
#else
  ck(false, "this test requires Windows");
#endif
}

static void test_blob_header() {
  ck(sizeof(BlobHeader) == 48, "blob header is 48 bytes");

  BlobHeader h;
  h.magic = hyda::blob_magic();
  h.code_size = 8;
  h.entry_offset = 0;
  h.code_crc32 = 0;
  h.version = HYDA_BLOB_VERSION;
  h.flags = 0;
  h.islands_rva = 0;
  h.island_count = 0;
  h.island_span = 0;
  h.import_tab_rva = 0;
  h.shard_mask = 0;
  ck(blob_header_check(h), "valid header accepted");
  ck(!blob_no_crypt(h), "blob without flags uses encrypted mode");

  h.flags = HYDA_BLOB_NO_CRYPT;
  ck(blob_header_check(h) && blob_no_crypt(h), "NO_CRYPT flag recognized");

  h.flags = HYDA_BLOB_KNOWN_FLAGS | 0x80000000u;
  ck(!blob_header_check(h), "unknown flag rejected");
  h.flags = 0;

  h.version = HYDA_BLOB_VERSION + 1;
  ck(!blob_header_check(h), "unknown version rejected");
  h.version = HYDA_BLOB_VERSION;

  h.code_size = 0;
  ck(!blob_header_check(h), "zero size rejected");
  h.code_size = 8;

  h.islands_rva = 0x90000;
  h.island_count = 2;
  h.island_span = 128;
  ck(blob_header_check(h), "island field accepted");
  h.island_count = 0;
  ck(!blob_header_check(h), "rva without count rejected");
  h.island_count = 2;
  h.island_span = 0;
  ck(!blob_header_check(h), "rva without span rejected");
  h.islands_rva = 0;
  h.island_count = 1;
  h.island_span = 64;
  ck(!blob_header_check(h), "count without rva rejected");
  h.islands_rva = 0;
  h.island_count = 0;
  h.island_span = 0;

  Asm a;
  a.i_rq(Op::MOV_RI, REG_RAX, 7);
  a.i_rq(Op::MOV_RI, REG_RCX, 35);
  a.i_rr(Op::ADD64, REG_RAX, REG_RCX);
  a.i_rq(Op::MOV_RI, REG_RDX, 5);
  a.i_rr(Op::IMUL2, REG_RAX, REG_RDX);
  a.i0(Op::HALT);
  a.finalize();

  const uint32_t blob_rva = 0x86000;
  const uint64_t key = crypt_key_for(blob_rva);

  std::vector<uint8_t> enc = a.code;
  crypt_operands_encrypt(enc.data(), enc.size(), key);
  BlobHeader he = h;
  he.code_size = static_cast<uint32_t>(enc.size());
  he.code_crc32 = crc32(enc.data(), static_cast<uint32_t>(enc.size()));
  const uint64_t key_e = blob_no_crypt(he) ? 0 : key;
  ck(blob_header_check(he) && crc32(enc.data(), he.code_size) == he.code_crc32,
     "encrypted blob passes integrity gate");

  std::vector<uint8_t> plain = a.code;
  BlobHeader hn = h;
  hn.flags = HYDA_BLOB_NO_CRYPT;
  hn.code_size = static_cast<uint32_t>(plain.size());
  hn.code_crc32 = crc32(plain.data(), static_cast<uint32_t>(plain.size()));
  const uint64_t key_n = blob_no_crypt(hn) ? 0 : key;
  ck_eq(key_n, 0, "NO_CRYPT blob uses key 0 (decryption off)");

  VMContext c1;
  vm_init(c1, 0);
  ck(vm_exec(c1, enc.data(), enc.size(), key_e) == ST_HALT, "encrypted blob: HALT");
  ck_eq(c1.r[vsl(REG_RAX)], 210, "encrypted blob result");

  VMContext c2;
  vm_init(c2, 0);
  ck(vm_exec(c2, plain.data(), plain.size(), key_n) == ST_HALT,
     "plaintext blob: HALT");
  ck_eq(c2.r[vsl(REG_RAX)], 210, "plaintext blob result (same)");

  VMContext c3;
  vm_init(c3, 0);
  const uint32_t st3 = vm_exec(c3, plain.data(), plain.size(), key);
  ck(st3 != ST_HALT || c3.r[vsl(REG_RAX)] != 210, "wrong mode corrupts result");
}

int main() {
  std::printf("HydaVM PE self-test (x64)\n");
  std::printf("  opcodes: %zu\n", OP_COUNT);

  {
    Asm a;
    a.i_rr(Op::ADD64, REG_RCX, REG_RDX);
    a.i_rr(Op::MOV_RR, REG_RAX, REG_RCX);
    a.i0(Op::HALT);
    a.finalize();
    const VmCall r = vm_call(a, 0, 40, 2);
    ck(r.status == ST_HALT, "add64: HALT");
    ck_eq(r.ret, 42, "40 + 2");
  }

  test_add_halt();
  test_recursive_fib();
  test_memory_writes();
  test_mutation_ops();
  test_pe_context();
  test_blob_header();

  {
    Asm a;
    a.i_rq(Op::MOV_RI, REG_RCX, 10);
    a.i_rq(Op::MOV_RI, REG_RAX, 1);
    size_t l = a.label();
    a.bind(l);
    a.i_rr(Op::IMUL2, REG_RAX, REG_RCX);
    a.i_r(Op::DEC, REG_RCX);
    a.i_rq(Op::MOV_RI, REG_T0, 1);
    a.i_rr(Op::CMP64, REG_RCX, REG_T0);
    a.i_j(Op::JCC_GE, l);
    a.i0(Op::HALT);
    a.finalize();

    std::printf("\n--- 10! computation, VM bytecode (%zu bytes)\n", a.code.size());
    disasm(a.code.data(), a.code.size());

    const VmCall r = vm_call(a, 0);
    std::printf("    10! = %llu\n\n", (unsigned long long)r.ret);
    ck_eq(r.ret, 3628800, "10!");
  }

  std::printf("summary: %d checks, %d failures\n", g_checks, g_fails);
  return g_fails == 0 ? 0 : 1;
}
