#pragma once

#include "hyda/ir/ir.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

struct ObfStats {
  size_t cmds_before = 0;
  size_t cmds_after = 0;
  size_t opaque = 0;
  size_t dead_blocks = 0;
  size_t dead_cmds = 0;
};

ObfStats ir_bogus_cfg(IRProgram& p, uint64_t seed);

}
