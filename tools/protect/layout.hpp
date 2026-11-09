#pragma once
// Trampoline/blob layout, handler sharding and container building.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "handlers.hpp"
#include "hyda/codec/hydak.hpp"
#include "hyda/ir/ir.hpp"
#include "hyda/ir/ir_codegen.hpp"
#include "hyda/native/island.hpp"

namespace hyda::prot {

constexpr size_t kTrampAlign = 16;
constexpr uint32_t kTrampMaxFrame = 128;
constexpr uint16_t kVolatileMask = hyda::kWin64VolatileMask;

struct TrampSyms {
  uint32_t dispatch = 0;
  uint32_t save_simd = 0;
  uint32_t restore_simd = 0;
};

struct UnwindEntry {
  uint32_t begin = 0;
  uint32_t end = 0;
  uint32_t unwind = 0;
};

struct Protected {
  std::string name;
  uint32_t func_rva = 0;
  uint32_t func_size = 0;
  std::vector<uint8_t> code;
  size_t entry = 0;
  uint32_t blob_rva = 0;
  uint32_t tramp_rva = 0;
  uint32_t tramp_size = 0;
  uint32_t tramp_code_size = 0;
  uint32_t tramp_frame = 0;
  uint16_t preserve = 0;

  std::vector<hyda::NativeIsland> islands;
  std::vector<hyda::NativeRef> native_refs;
  uint32_t islands_rva = 0;

  bool no_crypt = false;

  uint64_t shard_mask = 0;
  bool op_used[hyda::OP_COUNT] = {};
};

struct PartPlan {
  std::vector<uint32_t> chunk;
  std::vector<uint32_t> off;
  uint32_t code_size = 0;
  uint32_t chunks_off = 0;
  uint32_t opmap_off = 0;
  uint32_t total = 0;
  uint32_t rva = 0;
  uint16_t bad_local = hyda::HYDA_HYDAK_NO_CHUNK;
  uint64_t seed = 0;
};

struct Block {
  bool real = false;
  uint32_t part = 0;
  uint32_t off = 0;
  uint32_t total = 0;
  uint64_t seed = 0;
};

struct ContainerPlan {
  std::string name;
  uint32_t rva = 0;
  uint32_t total = 0;
  uint32_t raw_addr = 0;
  uint32_t raw_size = 0;
  std::vector<Block> blocks;
};

struct PartSet {
  std::vector<PartPlan> parts;
  std::vector<ContainerPlan> containers;
  std::vector<uint32_t> new_rva;
  uint32_t virt_end = 0;
};

uint32_t tramp_frame(uint16_t preserve);
std::vector<uint8_t> build_trampoline(uint32_t blob_rva, uint16_t preserve,
                                      uint32_t tramp_va, const TrampSyms& syms);
void build_tramp_unwind(uint8_t* w, uint32_t frame);
void set_section_name(uint8_t* h, const std::string& name,
                      std::vector<uint8_t>* strtab);

bool plan_handler_parts(const HandlerSet& hs, uint64_t seed, unsigned want_parts,
                        unsigned want_decoys, unsigned want_containers,
                        uint32_t first_rva, uint32_t section_align,
                        uint32_t file_align, uint32_t file_start, PartSet* out,
                        std::string* err);
bool fill_part(const PeFile& pe, const HandlerSet& hs, const PartSet& ps,
               unsigned k, std::vector<uint8_t>* out, std::string* err);
bool build_container(const PartSet& ps,
                     const std::vector<std::vector<uint8_t>>& parts_bytes,
                     unsigned c, std::vector<uint8_t>* out, std::string* err);

}  // namespace hyda::prot
