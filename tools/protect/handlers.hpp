#pragma once
// Handler discovery and relocation-safety checks.

#include <cstdint>
#include <string>
#include <vector>

#include <capstone/capstone.h>

#include "hyda/core/opcodes.hpp"
#include "pe.hpp"

namespace hyda::prot {

constexpr uint32_t kHydakMaxChunk = 8192;

struct HandlerSet {
  struct Chunk {
    uint32_t rva = 0;
    uint32_t size = 0;
    uint32_t erase = 0;
  };
  std::vector<Chunk> chunks;
  std::vector<uint16_t> op_chunk;
  std::vector<uint32_t> by_rva;
  uint32_t region_lo = 0;
  uint32_t region_hi = 0;
  unsigned pdata_used = 0;
};

struct PdataRange {
  uint32_t begin = 0;
  uint32_t end = 0;
};

struct BranchRel {
  bool direct = false;
  uint8_t size = 0;
  uint8_t off = 0;
  int64_t target = 0;
};

int chunk_of_rva(const HandlerSet& hs, int64_t rva);
int section_of_rva(const PeFile& pe, uint32_t rva);
uint32_t coff_symbol_rva(const PeFile& pe, const std::string& want, bool* found);
void coff_symbol_rvas_in_section(const PeFile& pe, int sec_idx,
                                 std::vector<uint32_t>* out);
uint32_t coff_function_symbols_in_section(const PeFile& pe, int sec_idx);

bool discover_handlers(const PeFile& pe, HandlerSet* out, std::string* err);
bool branch_rel(const cs_x86& x, BranchRel* out);
bool relocate_chunk(csh h, const HandlerSet& hs,
                    const std::vector<uint32_t>& new_rva, const uint8_t* src,
                    uint32_t len, uint32_t orig_rva, uint8_t* shard,
                    uint32_t dst_off, uint32_t shard_rva, std::string* err);
bool check_erased_tails(const PeFile& pe, const HandlerSet& hs,
                        std::string* err);
bool check_no_inbound_refs(const PeFile& pe, const HandlerSet& hs,
                           std::string* err);
bool check_no_rel_tables(const PeFile& pe, const HandlerSet& hs,
                         std::string* err);

}  // namespace hyda::prot
