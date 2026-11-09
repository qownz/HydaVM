#pragma once

#include "hyda/ir/ir.hpp"

#include <cstddef>

namespace hyda {

struct FuseStats {
  size_t cmds_before = 0;
  size_t cmds_after = 0;
  size_t fused = 0;
  size_t mem_source = 0;
};

FuseStats ir_fuse(IRProgram& p);

}
