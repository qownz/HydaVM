#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hyda::prot {

struct ReportFn {
  std::string name;
  uint32_t rva = 0;
  uint32_t x86_bytes = 0;
  uint32_t bytecode_bytes = 0;
  uint32_t islands = 0;
  uint32_t fused = 0;
  uint32_t variants = 0;
  uint32_t dead_flags = 0;
  uint32_t opcodes = 0;
  bool encrypted = false;
};

struct ReportSkip {
  std::string name;
  std::string reason;
};

struct Report {
  std::string input;
  std::string output;
  bool dry_run = false;
  bool strict = false;
  uint64_t image_base = 0;
  uint64_t vm_seed = 0;
  uint64_t hydak_seed = 0;
  uint32_t prof_mask = 0;
  uint32_t prof_key = 0;
  uint32_t prof_base = 0;
  uint32_t prof_shift = 0;
  uint32_t prof_call = 0;
  uint32_t prof_crypt = 0;
  uint32_t identities = 0;
  std::vector<ReportFn> functions;
  std::vector<ReportSkip> skipped;
};

bool write_report(const Report& r, const std::string& path, std::string* err);

}  // namespace hyda::prot