#pragma once

#include "hyda/ir/assembler.hpp"
#include "hyda/ir/ir.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hyda {

struct NativeRef {
  uint32_t rva_offset = 0;
  uint32_t island = 0;
};

struct CodegenResult {
  bool ok = false;
  size_t entry_offset = 0;
  size_t code_size = 0;
  std::string error;

  size_t dead_flags = 0;

  size_t body_variant_count = 0;

  size_t nested_count = 0;
  size_t dead_emitted = 0;
  size_t dead_dropped = 0;

  std::vector<NativeRef> native_refs;

  bool op_used[OP_COUNT] = {};
};

CodegenResult ir_codegen(const IRProgram& prog, Asm& out);

}
