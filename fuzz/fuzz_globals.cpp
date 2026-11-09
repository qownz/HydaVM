// Seed globals normally provided by hyda_vm. The fuzz targets only exercise
// the header-only parsers, so initializing them to the default seed matches
// the formats the protector emits, without linking the asm-heavy VM.
#include <cstdint>

#include "hyda/core/instance.hpp"

extern "C" {
uint64_t g_vm_seed = hyda::kSeedDefaultMasked();
uint64_t g_seed_salt = hyda::kSeedSaltDefault;
}