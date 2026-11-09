#pragma once

#include "hyda/ir/ir.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

struct MutateOptions {

  uint64_t seed = 0;

  bool junk = true;
  bool noise = true;
  bool inverse = true;

  unsigned junk_pct = 40;
  unsigned noise_pct = 25;
  unsigned inverse_pct = 50;
};

struct MutateStats {
  size_t cmds_before = 0;
  size_t cmds_after = 0;
  size_t junk = 0;
  size_t noise = 0;
  size_t inv_r = 0;
  size_t inverted_stores = 0;
  size_t normalized = 0;
  bool inverse_disabled = false;
  const char* inverse_disabled_reason = nullptr;
};

MutateStats ir_mutate(IRProgram& p, const MutateOptions& opt = MutateOptions());

}
