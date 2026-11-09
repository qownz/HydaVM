#pragma once

#include "hyda/codec/codec.hpp"
#include "hyda/core/config.hpp"
#include "hyda/codec/crypt.hpp"
#include "hyda/core/opcodes.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace hyda {

inline const char* vreg_name(int i) {
  static const char* const names[NVREG] = {
      "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
      "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
      "rip", "flags",
      "t0",  "t1",  "t2",  "t3",  "t4",  "t5",
      "noise"};
  if (i >= 0 && i < NVREG) return names[i];
  return "?";
}

inline unsigned disasm_operands(const uint8_t* p, Sig sig, char* out, size_t outsz) {
  const Opr kinds[6] = {sig.a, sig.b, sig.c, sig.d, sig.e, sig.f};
  const char* sep = "";
  size_t used = 0;
  out[0] = 0;

  for (int i = 0; i < 6; ++i) {
    if (kinds[i] == Opr::N) break;
    char tmp[64];
    switch (kinds[i]) {
      case Opr::R: {
        const int v = p[used];
        used += 1;
        if (v == static_cast<int>(NO_MEM)) snprintf(tmp, sizeof(tmp), "%snone", sep);
        else snprintf(tmp, sizeof(tmp), "%s%s", sep, vreg_name(v));
        break;
      }
      case Opr::b: {
        snprintf(tmp, sizeof(tmp), "%s%d", sep, static_cast<int>(static_cast<int8_t>(p[used])));
        used += 1;
        break;
      }
      case Opr::d: {
        int32_t v;
        std::memcpy(&v, p + used, 4);
        snprintf(tmp, sizeof(tmp), "%s%+d", sep, v);
        used += 4;
        break;
      }
      case Opr::q: {
        int64_t v;
        std::memcpy(&v, p + used, 8);
        snprintf(tmp, sizeof(tmp), "%s0x%llx", sep, static_cast<unsigned long long>(v));
        used += 8;
        break;
      }
      default:
        tmp[0] = 0;
        break;
    }
    strncat(out, tmp, outsz - strlen(out) - 1);
    sep = ", ";
  }
  return used;
}

inline void disasm(const uint8_t* code, size_t size, std::FILE* f = stdout) {
  size_t off = 0;
  while (off + kHeaderBytes <= size) {
    const size_t start = off;
    const uint16_t slot = static_cast<uint16_t>(
        code[off] | (static_cast<uint16_t>(code[off + 1]) << 8));
    const uint16_t op = opcode_map().op_of_slot[slot];
    off += kHeaderBytes;

    if (op == BAD_SLOT) {
      std::fprintf(f, "%05zx: .byte 0x%02x                 ; invalid slot\n", start, slot);
      continue;
    }

    const Sig sig = OP_SIGS[static_cast<size_t>(op)];
    const unsigned n = sig_size(sig);

    char ops[160];
    disasm_operands(code + off, sig, ops, sizeof(ops));

    std::fprintf(f, "%05zx: %08x  %-9s %s\n", start,
                 static_cast<unsigned>(slot), OP_NAMES[op], ops);
    off += n;
  }
}

inline void disasm_encrypted(const uint8_t* code, size_t size, uint64_t key,
                             uint32_t variant = 0, std::FILE* f = stdout) {
  if (key == 0) {
    disasm(code, size, f);
    return;
  }
  const OpcodeMap& m = opcode_map();
  CodecKey ck;
  codec_init(ck, detail::codec_stream_key(key, variant));

  size_t off = 0;
  while (off + kHeaderBytes <= size) {
    const size_t start = off;
    const uint64_t z = crypt_mix(start, key);
    const uint16_t slot = codec_decode(ck, code[off], code[off + 1], z);
    const uint16_t op = m.op_of_slot[slot];
    off += kHeaderBytes;
    if (op == BAD_SLOT) {
      std::fprintf(f, "%05zx: .byte 0x%02x                 ; invalid slot\n",
                   start, static_cast<unsigned>(slot));
      break;
    }
    const Sig sig = OP_SIGS[static_cast<size_t>(op)];
    const unsigned n = sig_size(sig);
    if (off + n > size) break;

    uint8_t tmp[16] = {};
    const uint64_t zs = z ^ (static_cast<uint64_t>(slot) * 0x27D4EB2Du);
    uint8_t prev = 0;
    for (unsigned i = 0; i < n; ++i) {
      const uint8_t k = crypt_ks_byte_v(zs, i, variant);
      const uint8_t c = code[off + i];
      tmp[i] = static_cast<uint8_t>(c - k - prev);
      prev = c;
    }

    char ops[160];
    disasm_operands(tmp, sig, ops, sizeof(ops));
    std::fprintf(f, "%05zx: %08x  %-9s %s\n", start,
                 static_cast<unsigned>(slot), OP_NAMES[op], ops);
    off += n;
  }
}

}
