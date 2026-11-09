#pragma once

#include "hyda/core/config.hpp"
#include "hyda/core/context.hpp"
#include "hyda/core/opcodes.hpp"

namespace hyda {

using HandlerFn = void (*)(VMContext&, const uint8_t*);

bool cond_true(const VMContext& c, unsigned cc);

uint64_t mem_addr(const VMContext& c, int base, int index, int scale, int32_t disp);

}
