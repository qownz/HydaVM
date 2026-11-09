#pragma once

#include "hyda/mutate/fuse.hpp"
#include "hyda/mutate/obf.hpp"
#include "hyda/ir/ir.hpp"
#include "hyda/mutate/mutate.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hyda {

struct LiftOptions {

  uint64_t base_address = 0;

  uint64_t image_base = 0;

  std::string name = "lifted";

  bool mutate = true;
  uint64_t mutate_seed = 0;

  bool fuse = true;

  bool obfuscate = true;
};

struct UnsupportedInsn {
  uint64_t address = 0;
  std::string mnemonic;
  std::string reason;
};

struct LiftResult {
  bool ok = false;
  std::string error;
  IRProgram prog;

  std::vector<UnsupportedInsn> unsupported;

  size_t decoded = 0;
  size_t emitted = 0;
  size_t pruned = 0;

  size_t image_relocs = 0;

  size_t address_fixups = 0;

  uint16_t written_regs = 0;

  size_t native_islands = 0;

  MutateStats mutate;

  FuseStats fuse;

  ObfStats obf;
};

LiftResult lift_x86_64(const uint8_t* code, size_t size, const LiftOptions& opt);

}
