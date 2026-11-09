#pragma once

#include "hyda/core/config.hpp"
#include "hyda/core/context.hpp"
#include "hyda/codec/hydak.hpp"
#include "hyda/core/opcodes.hpp"

#include <cstddef>
#include <cstdint>

namespace hyda {

uint32_t vm_exec(VMContext& ctx, const uint8_t* code, size_t size,
                 uint64_t crypt_key = 0);

extern "C" uint32_t hyda_vm_run_asm(VMContext* ctx, const uint8_t* code,
                                    size_t size, uint64_t crypt_key);

uint32_t install_handler_shards(const HandlerShardDesc* descs, unsigned count,
                                uint64_t* arena_lo = nullptr,
                                uint64_t* arena_hi = nullptr);

inline void vm_set_entry(VMContext& ctx, uint64_t bytecode_offset) {
  ctx.r[REG_RIP] = bytecode_offset;
}

}
