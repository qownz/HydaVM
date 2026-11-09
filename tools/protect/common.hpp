#pragma once
// Shared byte/IO helpers for the protector tool.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "hyda/core/instance.hpp"

namespace hyda::prot {

inline uint16_t rd16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t rd64(const uint8_t* p) {
  return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}
inline void wr16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v);
  p[1] = static_cast<uint8_t>(v >> 8);
}
inline void wr32(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v); p[1] = static_cast<uint8_t>(v >> 8);
  p[2] = static_cast<uint8_t>(v >> 16); p[3] = static_cast<uint8_t>(v >> 24);
}
inline void wr64(uint8_t* p, uint64_t v) {
  wr32(p, static_cast<uint32_t>(v));
  wr32(p + 4, static_cast<uint32_t>(v >> 32));
}
inline uint32_t align_up(uint32_t v, uint32_t a) { return a ? (v + a - 1) / a * a : v; }

inline uint64_t mutate_seed_for(const std::string& name) {
  uint64_t h = 0xCBF29CE484222325ull;
  for (unsigned char c : name) {
    h ^= c;
    h *= 0x100000001B3ull;
  }
  return hyda::vm_seed() ^ (h * 0x9E3779B97F4A7C15ull);
}

inline bool read_file(const char* path, std::vector<uint8_t>* out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  f.seekg(0, std::ios::end);
  const std::streamoff n = f.tellg();
  f.seekg(0, std::ios::beg);
  out->resize(static_cast<size_t>(n));
  if (n > 0) f.read(reinterpret_cast<char*>(out->data()), n);
  return static_cast<bool>(f) || f.eof();
}

inline bool write_file(const char* path, const std::vector<uint8_t>& data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) return false;
  f.write(reinterpret_cast<const char*>(data.data()),
          static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(f);
}

}  // namespace hyda::prot