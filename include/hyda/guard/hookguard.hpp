#pragma once

#include <cstddef>
#include <cstdint>

namespace hyda {

struct HookRef {
  uint32_t iat_rva;
  uint64_t resolved;
  uint32_t dll_hash;
};

constexpr uint32_t HYDA_HOOKREF_MAX = 4096;

constexpr uint32_t HYDA_HOOKREF_BATCH = 8;

}
