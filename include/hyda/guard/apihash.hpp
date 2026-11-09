#pragma once

#include <cstddef>
#include <cstdint>

namespace hyda {

inline uint32_t api_name_hash(const char* name) {
  uint32_t h = 2166136261u;
  for (const char* p = name; *p; ++p) {
    uint8_t c = static_cast<uint8_t>(*p);
    if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c - 'A' + 'a');
    h ^= c;
    h *= 16777619u;
  }
  return h ? h : 1u;
}

inline constexpr uint32_t api_hash_c(const char* s) {
  uint32_t h = 2166136261u;
  for (const char* p = s; *p; ++p) {
    uint8_t c = static_cast<uint8_t>(*p);
    if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c - 'A' + 'a');
    h ^= c;
    h *= 16777619u;
  }
  return h ? h : 1u;
}

inline uint32_t api_name_hash16(const uint16_t* name, size_t len) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < len; ++i) {
    uint16_t c = name[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<uint16_t>(c - 'A' + 'a');
    if (c > 0x7F) c = '?';
    h ^= static_cast<uint8_t>(c & 0xFF);
    h *= 16777619u;
  }
  return h ? h : 1u;
}

constexpr uint32_t HYDA_IMPTAB_MAGIC = 0x49504D48u;

constexpr uint32_t HYDA_IMPENT_ORDINAL = 1u << 0;

struct ImportProtectEntry {
  uint32_t dll_hash;
  uint32_t func_hash;
  uint32_t flags;
  uint16_t ordinal;
  uint16_t reserved;
};
static_assert(sizeof(ImportProtectEntry) == 16, "import entry must be 16 bytes");

struct ImportProtectTable {
  uint32_t magic;
  uint32_t count;
  uint32_t reserved;
  uint32_t reserved2;
  ImportProtectEntry entries[1];
};
static_assert(sizeof(ImportProtectTable) == 32,
              "import table header is 32 bytes (16 + 1 entry)");

}
