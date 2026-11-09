#pragma once

#include <cstddef>
#include <cstdint>

namespace hyda {

constexpr uint32_t HYDA_RIMPTAB_MAGIC = 0x52494D50u;

constexpr uint32_t HYDA_RIMPENT_ORDINAL = 1u << 0;

struct RuntimeImportEntry {
  uint32_t dll_name_off;
  uint32_t dll_name_len;
  uint32_t func_hash;
  uint32_t flags;
  uint16_t ordinal;
  uint16_t reserved;
  uint32_t iat_rva;
};
static_assert(sizeof(RuntimeImportEntry) == 24, "runtime import entry is 24 bytes");

struct RuntimeImportTable {
  uint32_t magic;
  uint32_t count;
  uint32_t orig_entry_rva;
  uint32_t name_key;

  uint32_t integrity_rva;
  uint32_t reserved;
  RuntimeImportEntry entries[1];
};
static_assert(sizeof(RuntimeImportTable) == 48,
              "runtime import table header is 24 + 1 entry = 48 bytes");

inline void runtime_import_name_crypt(uint8_t* p, size_t n, uint32_t key) {
  for (size_t i = 0; i < n; ++i) {
    p[i] = static_cast<uint8_t>(p[i] ^ static_cast<uint8_t>(key >> ((i & 3u) * 8u)) ^
                                static_cast<uint8_t>(i * 31u));
  }
}

}
