#pragma once

#include "hyda/core/context.hpp"
#include "hyda/core/export.hpp"

HYDA_ENTRY void hyda_vm_gate_enter(hyda::VMContext* ctx, const void* island);

HYDA_ENTRY void hyda_vm_gate_leave(void);
HYDA_ENTRY void hyda_vm_gate_leave_a(void);
HYDA_ENTRY void hyda_vm_gate_leave_b(void);
HYDA_ENTRY void hyda_vm_gate_leave_c(void);

HYDA_ENTRY void hyda_vm_save_simd(void);
HYDA_ENTRY void hyda_vm_restore_simd(void);

namespace hyda {

constexpr unsigned kMaxVmDepth = 8;

unsigned vm_gate_depth();

}
