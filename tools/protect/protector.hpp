#pragma once
// Top-level protector pipeline: orchestrates PE parsing, lifting, handler
// sharding, blob layout and final image assembly.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "cli.hpp"
#include "common.hpp"
#include "handlers.hpp"
#include "layout.hpp"
#include "lift.hpp"
#include "native_island.hpp"
#include "pe.hpp"

#include "hyda/codec/blob.hpp"
#include "hyda/codec/crypt.hpp"
#include "hyda/codec/datblob.hpp"
#include "hyda/codec/hydak.hpp"
#include "hyda/core/instance.hpp"
#include "hyda/core/opcodes.hpp"
#include "hyda/guard/apihash.hpp"
#include "hyda/guard/audit.hpp"
#include "hyda/guard/hookguard.hpp"
#include "hyda/guard/imports.hpp"
#include "hyda/guard/integrity.hpp"
#include "hyda/ir/assembler.hpp"
#include "hyda/ir/disasm.hpp"
#include "hyda/ir/ir.hpp"
#include "hyda/ir/ir_codegen.hpp"
#include "hyda/ir/ir_rw.hpp"
#include "hyda/native/island.hpp"

namespace hyda::prot {

class Protector {
 public:
  int run(const Options& opt);

 private:
  int do_list_handlers();
  int protect_file();

  // --- pipeline stages -------------------------------------------------
  int validate_runtime();
  int apply_profile();
  int apply_vm_seed();
  int apply_audit_policy();
  int collect_integrity();
  int prepare_entry();
  int build_import_table();
  int lift_functions();
  int setup_handlers();
  bool in_protected(uint32_t rva) const;
  int parse_unwind();
  int plan_layout();
  int plan_handler_layout();
  int build_shards();
  int build_blob();
  int apply_crypt();
  int build_tramp_blob();
  int build_unwind();
  int patch_entry_imports();
  int patch_bodies();
  int wipe_handlers();
  int neutralize_list();
  int rewrite_sections();
  int apply_rebase();
  int build_integrity_data();
  int write_output();

  // --- options ---------------------------------------------------------
  bool list_only = false;
  bool list_handlers = false;
  bool do_rebase = false;
  bool do_mutate = true;
  bool has_hydak_seed = false;
  uint64_t hydak_seed_opt = 0;
  unsigned hydak_parts = 6;
  unsigned hydak_decoys = 4;
  unsigned hydak_containers = 3;
  uint32_t audit_period = 1;
  uint32_t audit_chunks = 1;
  uint32_t audit_refs = 0;
  uint64_t rebase_to = 0;
  std::vector<std::string> no_crypt_names;
  std::string prof_fixed_str;
  std::string vm_seed_str;
  const char* in_path = nullptr;
  const char* out_path = nullptr;

  // --- pipeline state --------------------------------------------------
  PeFile pe;
  uint64_t vm_seed_val = 0;
  uint64_t seed_salt = 0;
  uint64_t hydak_seed = 0;
  std::vector<size_t> targets;

  TrampSyms syms;
  std::vector<uint32_t> leave_rvas;
  std::vector<Protected> prot;

  uint32_t prof_mask = 0;
  uint32_t prof_key = 0;
  uint32_t prof_base = 0;
  uint32_t prof_shift = 3;
  uint32_t prof_call = 0;
  uint32_t prof_crypt = 0;

  std::vector<ImportInfo> imports;
  std::vector<hyda::IntegrityRegion> integrity_regions;
  std::vector<hyda::RelocHole> integrity_holes;
  std::vector<hyda::IntegrityChunk> integrity_chunks;

  uint32_t orig_entry_rva = 0;
  uint32_t entry_stub_rva = 0;

  std::vector<hyda::RuntimeImportEntry> imp_entries;
  std::vector<uint8_t> imp_names;
  std::map<uint32_t, uint32_t> iat_to_index;
  uint32_t imp_name_key = 0;
  unsigned n_import_refs = 0;

  uint32_t new_va = 0;
  HandlerSet hset;
  std::string herr;

  std::vector<UnwindEntry> old_pdata;
  uint32_t exc_rva = 0;
  uint32_t exc_size = 0;
  int64_t exc_off = -1;

  uint32_t cursor = 0;
  uint32_t import_tab_rva = 0;
  uint32_t integrity_rva = 0;
  uint32_t integrity_chunk_count = 0;
  uint32_t pdata_rva = 0;
  uint32_t pdata_count = 0;
  uint32_t xdata_rva = 0;
  uint32_t virt_size = 0;
  uint32_t raw_off = 0;
  uint32_t raw_size = 0;
  uint32_t hydak_first_rva = 0;
  uint32_t hydak_first_raw = 0;

  PartSet partset;
  unsigned ncont = 0;
  uint32_t dat_rva = 0;
  uint32_t dat_raw = 0;
  uint32_t dat_raw_size = 0;
  uint32_t dat_total = 0;
  unsigned ndat = 0;
  std::vector<std::vector<uint8_t>> part_bytes;
  std::vector<std::vector<uint8_t>> cont_bytes;
  uint32_t decoy_total = 0;
  unsigned decoy_blocks = 0;
  uint32_t hydak_size_total = 0;
  uint32_t hydak_code_total = 0;
  uint32_t hydak_part_total = 0;

  std::vector<uint8_t> blob;
  std::vector<uint8_t> dat_bytes;
};

}  // namespace hyda::prot