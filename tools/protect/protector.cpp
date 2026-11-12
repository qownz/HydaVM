#include "protector.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace hyda::prot {

namespace {

void scrub_signatures(PeFile& pe, uint64_t seed) {
  if (pe.cof_off + 12 > pe.data.size() || pe.opt_off + 4 > pe.data.size()) return;
  uint64_t s = seed ^ 0x5C3B1D2E4F607180ull;
  auto rnd = [&]() -> uint8_t {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return static_cast<uint8_t>((s >> 24) | 1u);
  };

  wr32(&pe.data[pe.cof_off + 8], 0);

  if (pe.export_rva != 0 && pe.export_size != 0) {
    const int64_t eoff = pe.rva_to_off(pe.export_rva);
    if (eoff >= 0 && static_cast<size_t>(eoff) + 40 <= pe.data.size()) {
      const uint32_t nnames = rd32(&pe.data[static_cast<size_t>(eoff) + 24]);
      const int64_t names_off =
          pe.rva_to_off(rd32(&pe.data[static_cast<size_t>(eoff) + 32]));
      if (names_off >= 0 && nnames < 4096) {
        for (uint32_t i = 0; i < nnames; ++i) {
          const int64_t ent = names_off + static_cast<int64_t>(4u * i);
          if (ent + 4 > static_cast<int64_t>(pe.data.size())) break;
          const int64_t noff = pe.rva_to_off(rd32(&pe.data[ent]));
          if (noff < 0) continue;
          for (int64_t k = 0; k < 128 && noff + k < static_cast<int64_t>(pe.data.size()) &&
                              pe.data[noff + k] != 0;
               ++k) {
            pe.data[noff + k] = rnd();
          }
        }
      }

      for (uint32_t i = 0; i < pe.export_size; ++i) {
        const size_t at = static_cast<size_t>(eoff) + i;
        if (at >= pe.data.size()) break;
        pe.data[at] = rnd();
      }
    }
    const bool pe32plus = rd16(&pe.data[pe.opt_off]) == 0x20b;
    const uint32_t dir = pe.opt_off + (pe32plus ? 112u : 96u);
    if (dir + 8 <= pe.data.size()) {
      wr32(&pe.data[dir], 0);
      wr32(&pe.data[dir + 4], 0);
    }
  }

  for (int64_t i = 0x40; i + 8 < static_cast<int64_t>(pe.opt_off); ++i) {
    if (pe.data[i] == 'R' && pe.data[i + 1] == 'i' && pe.data[i + 2] == 'c' &&
        pe.data[i + 3] == 'h') {
      int64_t j = i;
      for (; j >= 0x40; --j) {
        if (pe.data[j] == 'D' && pe.data[j + 1] == 'a' &&
            pe.data[j + 2] == 'n' && pe.data[j + 3] == 'S') {
          break;
        }
      }
      if (j >= 0x40) {
        for (int64_t k = j; k < i + 8 && k < static_cast<int64_t>(pe.data.size());
             ++k) {
          pe.data[k] = 0;
        }
      }
      break;
    }
  }
}

}  // namespace

// ---------------------------------------------------------------- run()
int Protector::run(const Options& opt) {
  list_only = opt.mode == Options::Mode::ListSections;
  list_handlers = opt.mode == Options::Mode::ListHandlers;
  do_mutate = opt.do_mutate;
  strict_opt = opt.strict;
  dry_run = opt.dry_run;
  report_path = opt.report_path;
  do_rebase = opt.do_rebase;
  rebase_to = opt.rebase_to;
  hydak_parts = opt.hydak_parts;
  hydak_decoys = opt.hydak_decoys;
  hydak_containers = opt.hydak_containers;
  has_hydak_seed = opt.has_hydak_seed;
  hydak_seed_opt = opt.hydak_seed;
  audit_period = opt.audit_period;
  audit_chunks = opt.audit_chunks;
  audit_refs = opt.has_audit_refs ? opt.audit_refs : hyda::HYDA_HOOKREF_BATCH;
  no_crypt_names = opt.no_crypt;
  prof_fixed_str = opt.dispatch_profile;
  vm_seed_str = opt.vm_seed;
  in_path = opt.input.c_str();
  out_path = opt.output.c_str();


  if (!vm_seed_str.empty()) {
    vm_seed_val = std::strtoull(vm_seed_str.c_str(), nullptr, 0);
    if (vm_seed_val == 0) {
      std::printf("error: --vm-seed cannot be 0\n");
      return 1;
    }
  } else {
    uint64_t r = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    r ^= static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&vm_seed_val));
    r ^= static_cast<uint64_t>(std::random_device{}());
    r += 0x9E3779B97F4A7C15ull;
    uint64_t z = r;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    vm_seed_val = (z ^ (z >> 31)) | 1u;
  }

  seed_salt = vm_seed_val;
  seed_salt ^= seed_salt >> 33;
  seed_salt *= 0xff51afd7ed558ccdull;
  seed_salt ^= seed_salt >> 33;
  ::g_seed_salt = seed_salt;
  ::g_vm_seed = vm_seed_val ^ hyda::seed_salt_mix(seed_salt);
  hyda::opmap_rebuild();

  if (!read_file(in_path, &pe.data)) {
    std::printf("error: cannot read %s\n", in_path);
    return 1;
  }
  std::string err;
  if (!pe.parse(&err)) {
    std::printf("error: %s: %s\n", in_path, err.c_str());
    return 1;
  }

  std::printf("HydaVM protector\n");
  std::printf("  input       : %s\n", in_path);
  std::printf("  image base  : %#llx\n", static_cast<unsigned long long>(pe.image_base));
  std::printf("  alignment   : %#x / file %#x\n", pe.section_align, pe.file_align);
  std::printf("  sections    : %u\n", pe.num_sections);

  hydak_seed =
      has_hydak_seed
          ? hydak_seed_opt
          : (0x9E3779B97F4A7C15ull ^ hyda::vm_seed() ^
             (static_cast<uint64_t>(pe.size_of_image) << 1) ^
             static_cast<uint64_t>(pe.sections.size()));


  if (list_handlers) return do_list_handlers();



  for (size_t i = 0; i < pe.sections.size(); ++i) {
    if (pe.sections[i].name.compare(0, 7, "hydafn_") == 0) targets.push_back(i);
  }
  std::printf("  protect     : %zu functions\n", targets.size());

  if (list_only) {
    for (size_t i = 0; i < pe.sections.size(); ++i) {
      const Section& s = pe.sections[i];
      std::printf("    [%2zu] %-18s rva=%#010x vsz=%u raw=%#x rsz=%u ch=%#x\n", i,
                  s.name.c_str(), s.virt_addr, s.virt_size, s.raw_addr, s.raw_size,
                  s.characteristics);
    }
  }

  if (targets.empty()) {
    std::printf("error: no `hydafn_*` section\n");
    return 1;
  }

  if (list_only) {
    for (size_t idx : targets) {
      const Section& s = pe.sections[idx];
      std::printf("    %-24s rva=%#x size=%u (%s)\n", s.name.c_str(), s.virt_addr,
                  s.virt_size,
                  (s.characteristics & 0x20) ? "code" : "data?");
    }
    std::string e2;
    const uint32_t d = pe.find_export("hyda_vm_dispatch", &e2);
    std::printf("  hyda_vm_dispatch rva=%#x\n", d);
    return 0;
  }

  return protect_file();
}

// ---------------------------------------------------------------- list
int Protector::do_list_handlers() {

    HandlerSet hs;
    std::string herr;
    if (!discover_handlers(pe, &hs, &herr)) {
      std::printf("error: handler discovery: %s\n", herr.c_str());
      return 1;
    }
    std::printf("  unique handlers: %zu\n", hs.chunks.size());
    for (size_t i = 0; i < hs.chunks.size(); ++i) {
      std::printf("    [%3zu] rva=%#010x size=%u (erase %u)\n", i,
                  hs.chunks[i].rva, hs.chunks[i].size, hs.chunks[i].erase);
    }
    uint32_t code_bytes = 0;
    for (const HandlerSet::Chunk& c : hs.chunks) code_bytes += c.size;
    std::printf("  range: [%#x, %#x) = %u bytes (bodies %u + padding %u; "
                "%u/%zu bounded by `.pdata`)\n",
                hs.region_lo, hs.region_hi, hs.region_hi - hs.region_lo,
                code_bytes, hs.region_hi - hs.region_lo - code_bytes,
                hs.pdata_used, hs.chunks.size());
    if (!check_erased_tails(pe, hs, &herr)) {
      std::printf("  AUDIT FAILED: %s\n", herr.c_str());
    }
    if (!check_no_inbound_refs(pe, hs, &herr)) {
      std::printf("  AUDIT FAILED: %s\n", herr.c_str());
    }
    if (!check_no_rel_tables(pe, hs, &herr)) {
      std::printf("  AUDIT FAILED: %s\n", herr.c_str());
    } else {
      std::printf("  out-of-body branches / relative tables: CLEAN\n");
    }

    bool nfound = false;
    const uint32_t neutral_rva =
        coff_symbol_rva(pe, "hyda_handler_neutral", &nfound);
    if (!nfound) {
      std::printf("  ERROR: missing `hyda_handler_neutral` symbol\n");
    } else if (chunk_of_rva(hs, neutral_rva) >= 0 ||
               (neutral_rva >= hs.region_lo && neutral_rva < hs.region_hi)) {
      std::printf("  ERROR: neutral target (%#x) is inside the relocated range\n",
                  neutral_rva);
    } else {
      std::printf("  neutral target: hyda_handler_neutral rva=%#x (outside "
                  "range)\n", neutral_rva);
    }
    std::printf("  hydak seed: %#llx, parts: %u, decoys: %u, containers: %u\n",
                static_cast<unsigned long long>(hydak_seed), hydak_parts,
                hydak_decoys, hydak_containers);
    return 0;

}

bool Protector::in_protected(uint32_t rva) const {
  for (const Protected& p : prot) {
    if (rva >= p.func_rva && rva < p.func_rva + p.func_size) return true;
  }
  for (const HandlerSet::Chunk& c : hset.chunks) {
    if (rva >= c.rva && rva < c.rva + c.size) return true;
  }
  return false;
}

// ---------------------------------------------------------------- pipeline
int Protector::protect_file() {

  if (validate_runtime()) return 1;

  if (apply_profile()) return 1;

  if (apply_vm_seed()) return 1;

  if (apply_audit_policy()) return 1;

  if (collect_integrity()) return 1;

  if (prepare_entry()) return 1;

  build_import_table();

  if (lift_functions() != 0) {
    build_report();
    emit_report();
    return 1;
  }

  if (setup_handlers()) return 1;

  if (parse_unwind()) return 1;

  plan_layout();

  if (plan_handler_layout()) return 1;

  if (build_shards()) return 1;

  if (build_blob()) return 1;

  if (apply_crypt()) return 1;

  if (build_tramp_blob()) return 1;

  build_unwind();

  if (patch_entry_imports()) return 1;

  if (patch_bodies()) return 1;

  if (wipe_handlers()) return 1;

  if (neutralize_list()) return 1;

  if (rewrite_sections()) return 1;

  if (apply_rebase()) return 1;

  if (build_integrity_data()) return 1;

  build_report();
  if (emit_report()) return 1;

  if (dry_run) {
    std::printf("  dry run      : %s not written\n",
                out_path != nullptr && out_path[0] != 0 ? out_path : "(no output)");
    return 0;
  }

  if (write_output()) return 1;

  return 0;
}


int Protector::validate_runtime() {

  std::string eerr;
  const uint32_t dispatch_va = pe.find_export("hyda_vm_dispatch", &eerr);
  if (dispatch_va == 0) {
    std::printf("error: %s (target must export `hyda_vm_dispatch`)\n", eerr.c_str());
    return 1;
  }
  std::printf("  dispatch rva : %#x\n", dispatch_va);

  syms.dispatch = dispatch_va;
  syms.save_simd = pe.find_export("hyda_vm_save_simd", &eerr);
  syms.restore_simd = pe.find_export("hyda_vm_restore_simd", &eerr);
  const uint32_t gate_leave_va = pe.find_export("hyda_vm_gate_leave", &eerr);
  if (syms.save_simd == 0 || syms.restore_simd == 0 || gate_leave_va == 0) {
    std::printf("error: native gate symbols not found (%s)\n", eerr.c_str());
    std::printf("       target must link the current runtime\n");
    return 1;
  }

  leave_rvas.push_back(gate_leave_va);
  {
    static const char* kAliasNames[] = {"hyda_vm_gate_leave_a",
                                        "hyda_vm_gate_leave_b",
                                        "hyda_vm_gate_leave_c"};
    for (const char* nm : kAliasNames) {
      std::string aerr;
      const uint32_t va = pe.find_export(nm, &aerr);
      if (va == 0) {
        std::printf("error: gate-leave alias not found: %s (%s)\n", nm,
                    aerr.c_str());
        std::printf("       target must link the current runtime\n");
        return 1;
      }
      leave_rvas.push_back(va);
    }
  }
  std::printf("  native gate : leave=%#x (+%zu aliases) save=%#x restore=%#x\n",
              gate_leave_va, leave_rvas.size() - 1, syms.save_simd,
              syms.restore_simd);

  return 0;
}


int Protector::apply_profile() {

  {
    std::string perr;
    const uint32_t prof_rva = pe.find_export("g_dispatch_profile", &perr);
    if (prof_rva == 0) {
      std::printf("error: dispatch profile not found (%s)\n", perr.c_str());
      std::printf("       target must link the current runtime\n");
      return 1;
    }
    const int64_t prof_off = pe.rva_to_off(prof_rva);
    if (prof_off < 0) {
      std::printf("error: cannot parse dispatch profile\n");
      return 1;
    }

    uint64_t rnd = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    rnd ^= static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&prof_off));
    rnd ^= static_cast<uint64_t>(std::random_device{}());
    auto next = [&rnd]() {
      rnd += 0x9E3779B97F4A7C15ull;
      uint64_t z = rnd;
      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
      return z ^ (z >> 31);
    };
    if (!prof_fixed_str.empty()) {

      unsigned v[6] = {0, 0, 0, 3, 0, 0};
      if (std::sscanf(prof_fixed_str.c_str(), "%x,%x,%x,%x,%x,%x", &v[0], &v[1],
                      &v[2], &v[3], &v[4], &v[5]) != 6) {
        std::printf("error: --dispatch-profile format: mask,key,base,shift,call,crypt "
                    "(hex)\n");
        return 1;
      }
      prof_mask = v[0] & 0xFFu;
      prof_key = v[1] & 1u;
      prof_base = v[2] & 3u;
      prof_shift = (v[3] == 4u) ? 4u : 3u;
      prof_call = v[4] & 1u;
      prof_crypt = v[5] & 1u;
    } else {
      prof_mask = static_cast<uint32_t>(next() & 0xFFu);
      prof_key = static_cast<uint32_t>(next() & 1u);
      prof_base = static_cast<uint32_t>(next() & 3u);
      prof_shift = (next() & 1u) ? 4u : 3u;
      prof_call = static_cast<uint32_t>(next() & 1u);
      prof_crypt = static_cast<uint32_t>(next() & 1u);
    }
    wr32(&pe.data[prof_off + 0], prof_mask);
    wr32(&pe.data[prof_off + 4], prof_key);
    wr32(&pe.data[prof_off + 8], prof_base);
    wr32(&pe.data[prof_off + 12], prof_shift);
    wr32(&pe.data[prof_off + 16], prof_call);
    wr32(&pe.data[prof_off + 20], prof_crypt);
    std::printf("  dispatch profile: mask=%#x key=%u base=%u size=%uB call=%u "
                "crypt=%u (per-binary)\n",
                prof_mask, prof_key, prof_base, 8u << prof_shift, prof_call,
                prof_crypt);
  }

  return 0;
}


int Protector::apply_vm_seed() {

  {
    std::string serr;
    const uint32_t seed_rva = pe.find_export("g_vm_seed", &serr);
    if (seed_rva == 0) {
      std::printf("error: VM seed (g_vm_seed) not found (%s)\n",
                  serr.c_str());
      std::printf("       target must link the current runtime\n");
      return 1;
    }
    const int64_t seed_off = pe.rva_to_off(seed_rva);
    if (seed_off < 0) {
      std::printf("error: cannot parse VM seed\n");
      return 1;
    }

    const uint64_t target_build_seed =
        rd64(&pe.data[static_cast<size_t>(seed_off)]) ^
        hyda::seed_salt_mix(hyda::kSeedSaltDefault);
    if (target_build_seed != static_cast<uint64_t>(HYDA_VM_SEED)) {
      std::printf(
          "error: target build seed %#llx, protector %#llx\n"
          "       register permutation is fixed at compile time; both sides "
          "must be built with the SAME HYDA_VM_SEED\n",
          static_cast<unsigned long long>(target_build_seed),
          static_cast<unsigned long long>(HYDA_VM_SEED));
      return 1;
    }

    wr64(&pe.data[static_cast<size_t>(seed_off)], ::g_vm_seed);
    std::string salterr;
    const uint32_t salt_rva = pe.find_export("g_seed_salt", &salterr);
    if (salt_rva == 0) {
      std::printf("error: seed salt (g_seed_salt) not found (%s)\n",
                  salterr.c_str());
      return 1;
    }
    const int64_t salt_off = pe.rva_to_off(salt_rva);
    if (salt_off < 0) {
      std::printf("error: cannot parse seed salt\n");
      return 1;
    }
    wr64(&pe.data[static_cast<size_t>(salt_off)], ::g_seed_salt);
    std::printf("  VM seed     : %#018llx (per-binary)\n",
                static_cast<unsigned long long>(vm_seed_val));
  }

  return 0;
}


int Protector::apply_audit_policy() {

  {
    std::string aerr;
    const uint32_t ap_rva = pe.find_export("g_audit_policy", &aerr);
    if (ap_rva == 0) {
      std::printf("error: audit policy not found (%s)\n", aerr.c_str());
      return 1;
    }
    const int64_t ap_off = pe.rva_to_off(ap_rva);
    if (ap_off < 0) {
      std::printf("error: cannot parse audit policy\n");
      return 1;
    }
    wr32(&pe.data[ap_off + 0], audit_period);
    wr32(&pe.data[ap_off + 4], audit_chunks);
    wr32(&pe.data[ap_off + 8], audit_refs);
    wr32(&pe.data[ap_off + 12], 0);
    std::printf("  audit policy: period=%u calls, parts=%u, slots=%u "
                "per audit, rva %#x\n",
                audit_period, audit_chunks, audit_refs, ap_rva);
  }

  return 0;
}


int Protector::collect_integrity() {

  std::string imp_err;
  imports = pe.parse_imports(&imp_err);

  {

    for (size_t i = 0; i < pe.sections.size(); ++i) {
      const Section& s = pe.sections[i];
      if (s.name == ".edata") continue;
      if (s.name.compare(0, 7, ".debug_") == 0) continue;
      const uint32_t ch = s.characteristics;
      if ((ch & 0x80000000u) != 0 || (ch & 0x02000000u) != 0) continue;
      if (s.virt_size == 0 || s.raw_size == 0) continue;

      const uint32_t n = s.virt_size < s.raw_size ? s.virt_size : s.raw_size;
      hyda::IntegrityRegion reg;
      reg.rva = s.virt_addr;
      reg.size = n;
      reg.raw = s.raw_addr;
      integrity_regions.push_back(reg);
    }

    const uint32_t rel_rva = pe.dir_rva(5);
    const uint32_t rel_size = pe.dir_size(5);
    if (rel_rva != 0 && rel_size != 0) {
      const int64_t rel_off = pe.rva_to_off(rel_rva);
      if (rel_off < 0) {
        std::printf("error: cannot parse relocation directory (rva %#x)\n", rel_rva);
        return 1;
      }

      std::vector<hyda::RelocHole> holes(65536);
      const uint32_t hn = hyda::integrity_collect_holes(
          pe.data.data(), static_cast<uint32_t>(rel_off), rel_size, holes.data(),
          static_cast<uint32_t>(holes.size()));
      if (hn == holes.size()) {
        std::printf("error: too many relocation holes\n");
        return 1;
      }
      holes.resize(hn);

      const uint32_t iat_rva = pe.dir_rva(12);
      const uint32_t iat_size = pe.dir_size(12);
      if (iat_rva != 0 && iat_size != 0) {
        hyda::RelocHole h;
        h.rva = iat_rva;
        h.size = iat_size;
        holes.push_back(h);
      }

      std::sort(holes.begin(), holes.end(),
                [](const hyda::RelocHole& a, const hyda::RelocHole& b) {
                  return a.rva < b.rva;
                });
      integrity_holes = holes;
    }

    std::vector<hyda::IntegrityChunk> tmp(
        hyda::HYDA_INTEGRITY_MAX_CHUNKS);
    for (const hyda::IntegrityRegion& reg : integrity_regions) {
      const uint32_t n = hyda::integrity_split_region(
          reg.rva, reg.rva + reg.size, integrity_holes.data(),
          static_cast<uint32_t>(integrity_holes.size()), tmp.data(),
          static_cast<uint32_t>(tmp.size()));
      if (n >= tmp.size()) {
        std::printf("error: too many integrity chunks\n");
        return 1;
      }
      integrity_chunks.insert(integrity_chunks.end(), tmp.begin(),
                              tmp.begin() + n);
    }
  }

  return 0;
}


int Protector::prepare_entry() {

  std::string eerr;

  orig_entry_rva = rd32(&pe.data[pe.opt_off + 16]);
  entry_stub_rva = pe.find_export("hyda_vm_entry_stub", &eerr);
  if (entry_stub_rva == 0) {
    std::printf("error: entry-point stub not found (%s)\n", eerr.c_str());
    std::printf("       target must link the current runtime\n");
    return 1;
  }

  return 0;
}


int Protector::build_import_table() {

  imp_name_key =
      static_cast<uint32_t>(hyda::crypt_key_for(0x1D0FFu) ^ 0x5A5A1234u);
  for (const ImportInfo& im : imports) {
    if (iat_to_index.count(im.iat_rva) != 0) continue;
    hyda::RuntimeImportEntry e;
    e.dll_name_off = static_cast<uint32_t>(imp_names.size());
    e.dll_name_len = static_cast<uint32_t>(im.dll.size() + 1);
    e.func_hash = im.by_ordinal ? 0u : hyda::api_name_hash(im.func.c_str());
    e.flags = im.by_ordinal ? hyda::HYDA_RIMPENT_ORDINAL : 0u;
    e.ordinal = im.ordinal;
    e.reserved = 0;
    e.iat_rva = im.iat_rva;

    imp_names.insert(imp_names.end(), im.dll.begin(), im.dll.end());
    imp_names.push_back(0);
    hyda::runtime_import_name_crypt(imp_names.data() + e.dll_name_off,
                                    e.dll_name_len, imp_name_key);
    imp_entries.push_back(e);
    iat_to_index[im.iat_rva] = static_cast<uint32_t>(imp_entries.size() - 1);
  }

  return 0;
}


int Protector::lift_functions() {

  auto has_unwind_handler = [this](uint32_t rva) -> bool {
    const uint32_t ex_rva = pe.dir_rva(3);
    const uint32_t ex_size = pe.dir_size(3);
    if (ex_rva == 0 || ex_size == 0 || (ex_size % 12u) != 0) return false;
    const int off = pe.rva_to_off(ex_rva);
    if (off < 0) return false;
    const uint8_t* pd = &pe.data[static_cast<size_t>(off)];
    for (uint32_t k = 0; k + 12 <= ex_size; k += 12) {
      if (rd32(pd + k) != rva) continue;
      const uint32_t unw = rd32(pd + k + 8);
      if ((unw & 1u) != 0) return false;
      const int ui = pe.rva_to_off(unw);
      if (ui < 0) return false;
      return ((pe.data[static_cast<size_t>(ui)] >> 3) & 0x3u) != 0;
    }
    return false;
  };

  auto thunk_iat = [this](uint64_t target_va) -> uint32_t {
    if (target_va < pe.image_base) return 0;
    const uint64_t r64 = target_va - pe.image_base;
    if (r64 > 0xFFFFFFFFull) return 0;
    const int off = pe.rva_to_off(static_cast<uint32_t>(r64));
    if (off < 0) return 0;
    const size_t at = static_cast<size_t>(off);
    if (at + 6 > pe.data.size()) return 0;
    if (pe.data[at] != 0xFF || pe.data[at + 1] != 0x25) return 0;
    int32_t rel = 0;
    std::memcpy(&rel, &pe.data[at + 2], 4);
    const uint64_t iat = target_va + 6 + static_cast<int64_t>(rel);
    if (iat < pe.image_base) return 0;
    const uint64_t r = iat - pe.image_base;
    return r <= 0xFFFFFFFFull ? static_cast<uint32_t>(r) : 0;
  };

  auto calls_throw_helper = [this, &thunk_iat](const Protected& p) -> bool {
    for (const hyda::NativeIsland& isl : p.islands) {
      if (isl.disp_target == 0) continue;
      uint32_t iat = 0;
      const int64_t t = static_cast<int64_t>(isl.disp_target) -
                        static_cast<int64_t>(pe.image_base);
      if (t >= 0 && t <= 0xFFFFFFFFll) iat = static_cast<uint32_t>(t);
      for (const ImportInfo& im : imports) {
        if (im.iat_rva != iat) continue;
        if (im.func == "__cxa_throw" || im.func == "_CxxThrowException") {
          return true;
        }
      }
      iat = thunk_iat(isl.disp_target);
      for (const ImportInfo& im : imports) {
        if (im.iat_rva != iat) continue;
        if (im.func == "__cxa_throw" || im.func == "_CxxThrowException") {
          return true;
        }
      }
    }
    return false;
  };

  auto skip = [this](const Section& s, const std::string& why) -> int {
    if (strict_opt) {
      std::printf("error: cannot protect %s: %s\n", s.name.c_str(), why.c_str());
      return 1;
    }
    std::printf("warning: skipping %s: %s\n", s.name.c_str(), why.c_str());
    skipped.push_back(ReportSkip{s.name, why});
    return 0;
  };

  for (size_t idx : targets) {
    const Section& s = pe.sections[idx];
    const uint32_t size = s.virt_size ? s.virt_size : s.raw_size;

    const uint32_t fn_syms = coff_function_symbols_in_section(pe, static_cast<int>(idx));
    if (fn_syms > 1) {
      if (skip(s, std::to_string(fn_syms) +
                      " function symbols in one section (use -fno-ipa-cp-clone)") != 0) {
        return 1;
      }
      continue;
    }
    if (static_cast<uint64_t>(s.raw_addr) + size > pe.data.size()) {
      std::printf("error: section %s outside file\n", s.name.c_str());
      return 1;
    }
    if (size < 5) {
      if (skip(s, "section too small for a jmp rel32") != 0) return 1;
      continue;
    }
    if (has_unwind_handler(s.virt_addr)) {
      if (skip(s, "unwind info declares an exception handler") != 0) return 1;
      continue;
    }

    hyda::LiftOptions opt;
    opt.base_address = pe.image_base + s.virt_addr;
    opt.image_base = pe.image_base;
    opt.name = s.name;

    opt.mutate = do_mutate;
    opt.mutate_seed = do_mutate ? mutate_seed_for(s.name) : 0;
    const hyda::LiftResult r =
        hyda::lift_x86_64(&pe.data[s.raw_addr], size, opt);

    if (!r.ok) {
      std::string why = r.error;
      if (!r.unsupported.empty()) {
        why = std::to_string(r.unsupported.size()) + " unsupported instruction(s), first: " +
              r.unsupported.front().mnemonic + " (" + r.unsupported.front().reason + ")";
      }
      if (skip(s, why) != 0) {
        for (const hyda::UnsupportedInsn& u : r.unsupported) {
          std::printf("        %#llx %-10s %s\n",
                      static_cast<unsigned long long>(u.address),
                      u.mnemonic.c_str(), u.reason.c_str());
        }
        return 1;
      }
      for (size_t k = 0; k < r.unsupported.size() && k < 3; ++k) {
        std::printf("        %#llx %-10s %s\n",
                    static_cast<unsigned long long>(r.unsupported[k].address),
                    r.unsupported[k].mnemonic.c_str(),
                    r.unsupported[k].reason.c_str());
      }
      continue;
    }
    if (r.address_fixups != 0) {
      if (skip(s, std::to_string(r.address_fixups) +
                      " absolute address(es) that cannot be relocated") != 0) {
        return 1;
      }
      continue;
    }

    hyda::IRProgram prog = r.prog;
    hyda::ir_wrap_callable(prog);
    hyda::Asm asmb;
    const hyda::CodegenResult cg = hyda::ir_codegen(prog, asmb);
    if (!cg.ok) {
      if (skip(s, "codegen: " + cg.error) != 0) return 1;
      continue;
    }

    Protected p;
    p.name = s.name;
    p.func_rva = s.virt_addr;
    p.func_size = size;
    p.code = asmb.code;
    p.entry = cg.entry_offset;
    p.islands = r.prog.natives;
    p.native_refs = cg.native_refs;
    for (size_t k = 0; k < hyda::OP_COUNT; ++k) p.op_used[k] = cg.op_used[k];

    for (hyda::NativeIsland& isl : p.islands) {
      if (isl.disp_off < 0 || !isl.disp_read || isl.disp_size != 8) continue;
      const int64_t tgt = static_cast<int64_t>(isl.disp_target) -
                          static_cast<int64_t>(pe.image_base);
      if (tgt < 0 || tgt > 0xFFFFFFFFll) continue;
      const uint32_t rva = static_cast<uint32_t>(tgt);

      const ImportInfo* info = nullptr;
      for (const ImportInfo& im : imports) {
        if (im.iat_rva == rva) { info = &im; break; }
      }
      if (info == nullptr) continue;

      auto it = iat_to_index.find(rva);
      if (it == iat_to_index.end()) continue;
      isl.import_index = it->second + 1;
      ++n_import_refs;
    }

    if (calls_throw_helper(p)) {
      if (skip(s, "calls a C++ throw helper") != 0) return 1;
      continue;
    }

    p.preserve = static_cast<uint16_t>(kVolatileMask & ~r.written_regs);
    p.st_decoded = static_cast<uint32_t>(r.decoded);
    p.st_ir = static_cast<uint32_t>(r.emitted);
    p.st_islands = static_cast<uint32_t>(p.islands.size());
    p.st_fused = static_cast<uint32_t>(r.fuse.fused);
    p.st_variants = static_cast<uint32_t>(cg.body_variant_count);
    p.st_dead_flags = static_cast<uint32_t>(cg.dead_flags);
    for (size_t op = 0; op < hyda::OP_COUNT; ++op) {
      if (p.op_used[op]) ++p.st_opcodes;
    }
    prot.push_back(std::move(p));

    std::printf("  %-22s %4zu B x86 -> %3zu B bytecode (%zu IR, %zu RVA, "
                "%zu islands, keep: %#x, mut: %zu junk + %zu noise + %zu "
                "inv[%zu])\n",
                s.name.c_str(), static_cast<size_t>(size), cg.code_size,
                prog.cmds.size(), r.image_relocs, r.native_islands, p.preserve,
                r.mutate.junk, r.mutate.noise, r.mutate.inv_r,
                r.mutate.inverted_stores);
    if (r.mutate.inverse_disabled) {
      std::printf("  %-22s inverse disabled (%s)\n", "",
                  r.mutate.inverse_disabled_reason ? r.mutate.inverse_disabled_reason
                                                   : "?");
    }

    if (r.fuse.fused != 0) {
      std::printf("  %-22s fused: %zu pairs (%zu mem), "
                  "%zu -> %zu insns\n", "", r.fuse.fused, r.fuse.mem_source,
                  r.fuse.cmds_before, r.fuse.cmds_after);
    }

    if (cg.body_variant_count > 0) {
      std::printf("  %-22s body variants: %zu insns (same semantics)\n",
                  "", cg.body_variant_count);
    }

    if (cg.nested_count > 0) {
      std::printf("  %-22s nested VM: %zu insns\n", "",
                  cg.nested_count);
    }
    if (cg.dead_flags > 0) {
      std::printf("  %-22s dead flags: %zu insns (%zu flag-skip variants, "
                  "%zu removed)\n",
                  "", cg.dead_flags, cg.dead_emitted, cg.dead_dropped);
    }
  }

  if (prot.empty()) {
    std::printf("error: no function could be protected\n");
    return 1;
  }
  std::printf("  protected    : %zu of %zu functions (%zu skipped)\n",
              prot.size(), targets.size(), skipped.size());

  return 0;
}


int Protector::setup_handlers() {

  if (n_import_refs > 0) {
    std::printf("  import hiding: %u island calls routed to hidden slots "
                "(no API refs in static image)\n",
                n_import_refs);
  }

  new_va = align_up(pe.size_of_image, pe.section_align);

  if (!discover_handlers(pe, &hset, &herr)) {
    std::printf("error: handler discovery: %s\n", herr.c_str());
    return 1;
  }
  if (!check_erased_tails(pe, hset, &herr)) {
    std::printf("error: handler padding/boundary check: %s\n", herr.c_str());
    return 1;
  }
  if (!check_no_inbound_refs(pe, hset, &herr)) {
    std::printf("error: handlers cannot be relocated: %s\n", herr.c_str());
    return 1;
  }
  if (!check_no_rel_tables(pe, hset, &herr)) {
    std::printf("error: handler code cannot be relocated: %s\n", herr.c_str());
    return 1;
  }
  uint32_t hcode = 0;
  for (const HandlerSet::Chunk& c : hset.chunks) hcode += c.size;
  std::printf("  handlers: %zu unique bodies (%u bytes code, "
              "range [%#x,%#x) = %u bytes; %u bounded by `.pdata`)\n",
              hset.chunks.size(), hcode, hset.region_lo, hset.region_hi,
              hset.region_hi - hset.region_lo, hset.pdata_used);

  return 0;
}


int Protector::parse_unwind() {

  exc_rva = pe.dir_rva(3);
  exc_size = pe.dir_size(3);
  exc_off = -1;
  if (exc_rva != 0 && exc_size != 0) {
    exc_off = pe.rva_to_off(exc_rva);
    if (exc_off < 0) {
      std::printf("error: cannot parse exception directory (rva %#x)\n", exc_rva);
      return 1;
    }
    if (exc_size % 12 != 0) {
      std::printf("error: exception directory size is not a multiple of 12 (%u)\n", exc_size);
      return 1;
    }
    const uint8_t* pd = &pe.data[exc_off];
    for (uint32_t i = 0; i + 12 <= exc_size; i += 12) {
      UnwindEntry e;
      e.begin = rd32(pd + i);
      e.end = rd32(pd + i + 4);
      e.unwind = rd32(pd + i + 8);

      if (e.unwind & 1u) {
        std::printf("error: chained unwind info is not supported "
                    " (rva %#x)\n", e.begin);
        return 1;
      }
      if (in_protected(e.begin)) continue;
      old_pdata.push_back(e);
    }
  }

  return 0;
}


int Protector::plan_layout() {

  for (Protected& p : prot) {
    p.tramp_rva = new_va + cursor;
    const std::vector<uint8_t> tb = build_trampoline(0, p.preserve, 0, syms);
    p.tramp_code_size = static_cast<uint32_t>(tb.size());
    p.tramp_frame = tramp_frame(p.preserve);
    if (p.tramp_frame > kTrampMaxFrame || p.tramp_frame % 8 != 0) {
      std::printf("error: trampoline frame cannot be expressed in unwind info "
                  "(%u)\n", p.tramp_frame);
      return 1;
    }
    p.tramp_size =
        static_cast<uint32_t>(align_up(p.tramp_code_size, kTrampAlign));
    cursor += p.tramp_size;
  }
  for (Protected& p : prot) {
    cursor = align_up(cursor, 16);
    p.blob_rva = new_va + cursor;
    cursor += static_cast<uint32_t>(sizeof(hyda::BlobHeader)) +
              align_up(static_cast<uint32_t>(p.code.size()), 16);
  }
  for (Protected& p : prot) {
    if (p.islands.empty()) continue;
    cursor = align_up(cursor, 16);
    p.islands_rva = new_va + cursor;
    cursor += hyda::islands_span(p.islands, p.islands_rva);
  }

  if (!imp_entries.empty()) {
    cursor = align_up(cursor, 16);
    import_tab_rva = new_va + cursor;
    cursor += 24u + static_cast<uint32_t>(imp_entries.size()) * 24u +
              static_cast<uint32_t>(imp_names.size());
    cursor = align_up(cursor, 16);
  }

  if (!integrity_chunks.empty()) {
    integrity_chunk_count = static_cast<uint32_t>(integrity_chunks.size());
    cursor = align_up(cursor, 16);
    integrity_rva = new_va + cursor;

    cursor += static_cast<uint32_t>(sizeof(hyda::IntegrityManifest));
    cursor = align_up(cursor, 16);
  }

  cursor = align_up(cursor, 8);
  pdata_rva = new_va + cursor;
  pdata_count = static_cast<uint32_t>(old_pdata.size() + prot.size());
  cursor += pdata_count * 12;
  cursor = align_up(cursor, 8);
  xdata_rva = new_va + cursor;
  cursor += static_cast<uint32_t>(prot.size()) * 8;
  virt_size = align_up(cursor, 16);

  raw_off =
      align_up(static_cast<uint32_t>(pe.data.size()), pe.file_align);
  raw_size = align_up(virt_size, pe.file_align);
  hydak_first_rva = align_up(new_va + virt_size, pe.section_align);
  hydak_first_raw = align_up(raw_off + raw_size, pe.file_align);

  return 0;
}


int Protector::plan_handler_layout() {

  {

    const unsigned ndat_hdr = (integrity_chunk_count != 0) ? 1u : 0u;
    const uint32_t need_off = pe.sect_off + pe.num_sections * 40u;
    unsigned want = hydak_containers;
    for (;;) {
      if (!plan_handler_parts(hset, hydak_seed, hydak_parts, hydak_decoys, want,
                              hydak_first_rva, pe.section_align, pe.file_align,
                              hydak_first_raw, &partset, &herr)) {
        std::printf("error: cannot plan handler layout (%s)\n", herr.c_str());
        return 1;
      }
      ncont = static_cast<unsigned>(partset.containers.size());
      if (need_off + (1u + ncont + ndat_hdr) * 40u <= pe.size_of_headers) break;
      if (want <= 1u) {
        std::printf("error: no room for %u new sections in headers "
                    " (SizeOfHeaders %#x)\n", 1u + ncont + ndat_hdr,
                    pe.size_of_headers);
        return 1;
      }
      --want;
    }
    if (want != hydak_containers) {
      std::printf("  note: header space full; containers %u -> %u\n", hydak_containers, want);
    }
    hydak_containers = want;
  }

  ndat = integrity_chunk_count != 0 ? 1u : 0u;
  if (ndat != 0) {
    const uint32_t payload =
        integrity_chunk_count * static_cast<uint32_t>(sizeof(hyda::IntegrityChunk));
    dat_total = align_up(static_cast<uint32_t>(sizeof(hyda::DatHeader)) + payload,
                         pe.section_align ? pe.section_align : 16u);
    dat_rva = align_up(partset.virt_end, pe.section_align ? pe.section_align : 16u);
    const ContainerPlan& last = partset.containers.back();
    dat_raw = align_up(last.raw_addr + last.raw_size, pe.file_align);
    dat_raw_size = align_up(dat_total, pe.file_align ? pe.file_align : 16u);
  }

  return 0;
}


int Protector::build_shards() {

  part_bytes.assign(partset.parts.size(), {});
  for (size_t k = 0; k < partset.parts.size(); ++k) {
    if (!fill_part(pe, hset, partset, k, &part_bytes[k], &herr)) {
      std::printf("error: cannot build handler part %zu (%s)\n", k,
                  herr.c_str());
      return 1;
    }
    hydak_code_total += partset.parts[k].code_size;
    hydak_part_total += partset.parts[k].total;
  }
  cont_bytes.assign(ncont, {});
  for (unsigned c = 0; c < ncont; ++c) {
    if (!build_container(partset, part_bytes, c, &cont_bytes[c], &herr)) {
      std::printf("error: cannot build container %u (%s)\n", c, herr.c_str());
      return 1;
    }
    hydak_size_total += partset.containers[c].total;
    for (const Block& b : partset.containers[c].blocks) {
      if (b.real) continue;
      decoy_total += b.total;
      ++decoy_blocks;
    }
  }
  std::printf("  handler parts: %zu parts (%u bytes total, %u bytes code); "
              "each part encrypted + CRC\n",
              partset.parts.size(), hydak_part_total, hydak_code_total);
  std::printf("  containers   : %u sections, %u decoy blocks (%u bytes), "
              "%u bytes total; random content, signature-only discovery\n",
              ncont, decoy_blocks, decoy_total, hydak_size_total);
  for (unsigned c = 0; c < ncont; ++c) {
    const ContainerPlan& cp = partset.containers[c];
    unsigned nr = 0;
    for (const Block& b : cp.blocks) {
      if (b.real) ++nr;
    }
    std::printf("    %-8s va=%#x size=%u blocks=%zu (real %u / decoy %zu)\n",
                cp.name.c_str(), cp.rva, cp.total, cp.blocks.size(), nr,
                cp.blocks.size() - nr);
  }

  return 0;
}


int Protector::build_blob() {

  blob.assign(virt_size, 0);

  for (Protected& p : prot) {
    if (p.islands.empty()) continue;
    std::string ierr;
    const std::vector<hyda::PlacedIsland> placed = hyda::place_islands(
        p.islands, p.islands_rva, leave_rvas, pe.image_base, &ierr);
    if (placed.size() != p.islands.size()) {
      std::printf("error: cannot place native islands for %s: %s\n", p.name.c_str(),
                  ierr.c_str());
      return 1;
    }

    for (const hyda::NativeRef& ref : p.native_refs) {
      if (ref.island >= placed.size()) {
        std::printf("error: %s invalid island reference (%u)\n", p.name.c_str(),
                    ref.island);
        return 1;
      }
      if (static_cast<size_t>(ref.rva_offset) + 4 > p.code.size()) {
        std::printf("error: %s island reference outside bytecode\n", p.name.c_str());
        return 1;
      }
      wr32(&p.code[ref.rva_offset], placed[ref.island].rva);
    }

    for (const hyda::PlacedIsland& pl : placed) {
      std::memcpy(&blob[pl.rva - new_va], pl.bytes.data(), pl.bytes.size());

      if (!pl.header.empty()) {
        std::memcpy(&blob[pl.rva - new_va - hyda::HYDA_ISLAND_SIZE],
                    pl.header.data(), pl.header.size());
      }

      if (pl.decoy_rva != 0 && !pl.decoy.empty()) {
        std::memcpy(&blob[pl.decoy_rva - new_va], pl.decoy.data(),
                    pl.decoy.size());
      }
    }

    if (import_tab_rva != 0) {
      const uint32_t tab_off = import_tab_rva - new_va;
      const uint32_t count = static_cast<uint32_t>(imp_entries.size());
      wr32(&blob[tab_off + 0], hyda::HYDA_RIMPTAB_MAGIC);
      wr32(&blob[tab_off + 4], count);
      wr32(&blob[tab_off + 8], orig_entry_rva);
      wr32(&blob[tab_off + 12], imp_name_key);

      wr32(&blob[tab_off + 16], integrity_rva);
      wr32(&blob[tab_off + 20], 0);
      for (size_t i = 0; i < imp_entries.size(); ++i) {
        const uint8_t* e = reinterpret_cast<const uint8_t*>(&imp_entries[i]);
        std::memcpy(&blob[tab_off + 24 + i * 24], e, 24);
      }
      if (!imp_names.empty()) {
        std::memcpy(&blob[tab_off + 24 + count * 24], imp_names.data(),
                    imp_names.size());
      }
    }
  }

  {
    std::vector<int> part_shard(partset.parts.size(), -1);
    int sh = 0;
    for (const ContainerPlan& cp : partset.containers) {
      for (const Block& b : cp.blocks) {
        if (!b.real) continue;
        if (b.part < part_shard.size()) part_shard[b.part] = sh;
        ++sh;
      }
    }
    std::vector<int> chunk_shard(hset.chunks.size(), -1);
    for (size_t k = 0; k < partset.parts.size(); ++k) {
      if (part_shard[k] < 0) continue;
      for (uint32_t c : partset.parts[k].chunk) {
        if (c < chunk_shard.size()) chunk_shard[c] = part_shard[k];
      }
    }
    for (Protected& p : prot) {
      uint64_t m = 0;
      bool ok = true;
      for (size_t op = 0; op < hyda::OP_COUNT && ok; ++op) {
        if (!p.op_used[op]) continue;
        const uint16_t c = hset.op_chunk[op];
        if (c >= chunk_shard.size() || chunk_shard[c] < 0 ||
            chunk_shard[c] >= 64) {
          ok = false;
          break;
        }
        m |= (1ull << chunk_shard[c]);
      }
      const uint16_t bc = hset.op_chunk[hyda::OP_COUNT];
      if (ok && bc < chunk_shard.size() && chunk_shard[bc] >= 0 &&
          chunk_shard[bc] < 64) {
        m |= (1ull << chunk_shard[bc]);
      } else {
        ok = false;
      }

      p.shard_mask = ok ? m : 0;
    }
    unsigned avg = 0;
    for (const Protected& p : prot) {
      uint64_t m = p.shard_mask;
      while (m) { avg += static_cast<unsigned>(m & 1u); m >>= 1; }
    }
    if (!prot.empty()) {
      std::printf("  shard mask   : %zu parts / %zu containers; avg %u "
                  "parts per blob\n",
                  partset.parts.size(), partset.containers.size(),
                  avg / static_cast<unsigned>(prot.size()));
    }
  }

  return 0;
}


int Protector::apply_crypt() {

  {
    std::vector<bool> exempt(prot.size(), false);
    for (const std::string& want : no_crypt_names) {
      bool found = false;
      for (size_t i = 0; i < prot.size(); ++i) {
        if (prot[i].name == want) {
          exempt[i] = true;
          found = true;
        }
      }
      if (!found) {
        std::printf("error: --no-crypt '%s' matches no protected function\n", want.c_str());
        return 1;
      }
    }
    size_t nplain = 0;
    for (size_t i = 0; i < prot.size(); ++i) {
      Protected& p = prot[i];
      p.no_crypt = exempt[i];
      if (p.no_crypt) {
        ++nplain;
        continue;
      }

      const std::vector<uint8_t> plain = p.code;
      hyda::crypt_operands_encrypt_v(p.code.data(), p.code.size(),
                                     hyda::crypt_key_for(p.blob_rva),
                                     prof_crypt);
      std::vector<uint8_t> check = p.code;
      hyda::crypt_operands_decrypt_v(check.data(), check.size(),
                                     hyda::crypt_key_for(p.blob_rva),
                                     prof_crypt);
      if (check != plain) {
        std::printf("error: %s codec self-check failed (blob rva %#x): "
                    "encrypt/decrypt mismatch\n",
                    p.name.c_str(), p.blob_rva);
        return 1;
      }
    }
    if (nplain == 0) {
      std::printf("  encryption   : opcode codec v2 (2 bytes, position-bound) + "
                  "operand encryption ON + chained "
                  "(%zu blobs; per-blob key, per-insn stream)\n",
                  prot.size());
    } else {
      std::printf("  encryption   : opcode codec v2 + operand encryption "
                  "on %zu/%zu blobs; %zu plaintext "
                  "(--no-crypt)\n",
                  prot.size() - nplain, prot.size(), nplain);
      for (const Protected& p : prot) {
        if (!p.no_crypt) continue;
        std::printf("  %-22s operand encryption OFF (plaintext, "
                    "HYDA_BLOB_NO_CRYPT; blob rva %#x)\n",
                    p.name.c_str(), p.blob_rva);
      }
    }
  }

  return 0;
}


int Protector::build_tramp_blob() {

  for (Protected& p : prot) {
    const std::vector<uint8_t> tb =
        build_trampoline(p.blob_rva, p.preserve, p.tramp_rva, syms);
    std::memcpy(&blob[p.tramp_rva - new_va], tb.data(), tb.size());

    if (p.tramp_size > tb.size()) {
      uint64_t rs = mutate_seed_for(p.name) ^ 0x9E3779B97F4A7C15ull;
      for (uint32_t k = static_cast<uint32_t>(tb.size()); k < p.tramp_size; ++k) {
        blob[p.tramp_rva - new_va + k] =
            static_cast<uint8_t>(hyda::splitmix64(rs) & 0xFFu);
      }
    }

    hyda::BlobHeader h;
    h.magic = hyda::blob_magic();
    h.code_size = static_cast<uint32_t>(p.code.size());
    h.entry_offset = static_cast<uint32_t>(p.entry);
    h.code_crc32 = hyda::crc32(p.code.data(), static_cast<uint32_t>(p.code.size()));
    h.version = hyda::HYDA_BLOB_VERSION;
    h.flags = 0;
    if (p.no_crypt) h.flags |= hyda::HYDA_BLOB_NO_CRYPT;

    h.import_tab_rva = import_tab_rva;
    h.islands_rva = p.islands_rva;
    h.island_count = static_cast<uint32_t>(p.islands.size());
    h.island_span =
        p.islands.empty() ? 0u : hyda::islands_span(p.islands, p.islands_rva);
    h.shard_mask = p.shard_mask;

    if (!hyda::blob_header_check(h)) {
      std::printf("error: invalid blob header for %s\n",
                  p.name.c_str());
      return 1;
    }

    uint8_t* dst = &blob[static_cast<size_t>(p.blob_rva - new_va)];
    std::memcpy(dst, &h, sizeof(h));
    std::memcpy(dst + sizeof(h), p.code.data(), p.code.size());
  }

  return 0;
}


int Protector::build_unwind() {

  {
    std::vector<UnwindEntry> table = old_pdata;
    for (size_t i = 0; i < prot.size(); ++i) {
      const Protected& p = prot[i];
      const uint32_t ui = xdata_rva + static_cast<uint32_t>(i) * 8;
      build_tramp_unwind(&blob[ui - new_va], p.tramp_frame);
      UnwindEntry e;
      e.begin = p.tramp_rva;
      e.end = p.tramp_rva + p.tramp_code_size;
      e.unwind = ui;
      table.push_back(e);
    }
    std::stable_sort(table.begin(), table.end(),
                     [](const UnwindEntry& a, const UnwindEntry& b) {
                       return a.begin < b.begin;
                     });
    for (size_t i = 0; i < table.size(); ++i) {
      uint8_t* w = &blob[pdata_rva - new_va + i * 12];
      wr32(w, table[i].begin);
      wr32(w + 4, table[i].end);
      wr32(w + 8, table[i].unwind);
    }

    wr32(&pe.data[pe.opt_off + 112 + 3 * 8], pdata_rva);
    wr32(&pe.data[pe.opt_off + 112 + 3 * 8 + 4],
         static_cast<uint32_t>(table.size() * 12));
    if (exc_off >= 0) {
      std::memset(&pe.data[exc_off], 0, exc_size);
    }
    std::printf("  unwind table : %zu entries (%zu copied + %zu trampolines) "
                "va=%#x unwind=%#x\n",
                table.size(), old_pdata.size(), prot.size(), pdata_rva, xdata_rva);
  }

  return 0;
}


int Protector::patch_entry_imports() {

  {

    if (pe.dir_rva(13) != 0) {
      std::printf("error: delay imports are not supported\n");
      return 1;
    }
    const uint32_t imp_rva = pe.dir_rva(1);
    if (imp_rva != 0) {
      const int64_t imp_off = pe.rva_to_off(imp_rva);
      if (imp_off < 0) {
        std::printf("error: cannot parse import directory (cannot encrypt)\n");
        return 1;
      }

      std::memset(&pe.data[imp_off], 0, 20);

      for (const ImportInfo& im : imports) {
        if (im.name_off >= 0) {

          const int64_t hint_len = 2;
          const int64_t n = im.func.empty()
                                ? 2
                                : static_cast<int64_t>(im.func.size()) + 1;
          for (int64_t k = 0; k < n; ++k) {
            const int64_t off = im.name_off + (k < hint_len ? k : k);
            if (off < 0 || off >= static_cast<int64_t>(pe.data.size())) break;
            pe.data[off] = static_cast<uint8_t>(0xA5 + (k * 31u) & 0xFF);
          }
        }
        if (im.dll_name_off >= 0 && im.dll_name_len > 0) {
          for (int64_t k = 0; k < im.dll_name_len; ++k) {
            const int64_t off = im.dll_name_off + k;
            if (off < 0 || off >= static_cast<int64_t>(pe.data.size())) break;
            pe.data[off] = static_cast<uint8_t>(0x5A + (k * 17u) & 0xFF);
          }
        }

        if (im.thunk_off >= 0) {
          uint64_t zero = 0;
          if (im.thunk_off + 8 <= static_cast<int64_t>(pe.data.size())) {
            std::memcpy(&pe.data[im.thunk_off], &zero, 8);
          }
        }
        if (im.int_off >= 0) {
          uint64_t zero = 0;
          if (im.int_off + 8 <= static_cast<int64_t>(pe.data.size())) {
            std::memcpy(&pe.data[im.int_off], &zero, 8);
          }
        }
      }

      const uint32_t bound_rva = pe.dir_rva(11);
      if (bound_rva != 0) {
        const int64_t bound_off = pe.rva_to_off(bound_rva);
        const uint32_t bound_sz = pe.dir_size(11);
        if (bound_off >= 0 && bound_sz > 0) {
          std::memset(&pe.data[bound_off], 0,
                      std::min<size_t>(bound_sz, pe.data.size() - bound_off));
        }
        wr32(&pe.data[pe.opt_off + 112 + 11 * 8], 0);
        wr32(&pe.data[pe.opt_off + 112 + 11 * 8 + 4], 0);
      }

      wr32(&pe.data[pe.opt_off + 112 + 1 * 8 + 4], 0);
    }

    wr32(&pe.data[pe.opt_off + 16], entry_stub_rva);
    const int64_t stub_off = pe.rva_to_off(entry_stub_rva);
    if (stub_off < 0) {
      std::printf("error: cannot parse entry-point stub\n");
      return 1;
    }

    int64_t stub_imm = -1;
    for (int64_t k = 0; k + 5 <= 32 && stub_off + k + 5 <= (int64_t)pe.data.size();
         ++k) {
      if (pe.data[stub_off + k] == 0xB9) {
        stub_imm = stub_off + k + 1;
        break;
      }
    }
    if (stub_imm < 0 || stub_imm + 4 > (int64_t)pe.data.size()) {
      std::printf("error: 'mov ecx, imm32' not found in entry-point stub\n");
      return 1;
    }
    wr32(&pe.data[stub_imm], import_tab_rva);
    std::printf("  imports      : %zu imports handed to runtime ("
                "names removed from file)\n",
                imp_entries.size());
    std::printf("  entry point  : %#x -> stub %#x (original %#x)\n",
                orig_entry_rva, entry_stub_rva, orig_entry_rva);
  }

  std::printf("  new section  : .hydavm va=%#x size=%u\n", new_va, virt_size);

  return 0;
}


int Protector::patch_bodies() {

  for (const Protected& p : prot) {
    const int64_t off = pe.rva_to_off(p.func_rva);
    if (off < 0) {
      std::printf("error: cannot parse body of %s\n", p.name.c_str());
      return 1;
    }
    uint8_t* body = &pe.data[off];
    body[0] = 0xE9;

    wr32(body + 1, static_cast<uint32_t>(
                       static_cast<int64_t>(p.tramp_rva) -
                       (static_cast<int64_t>(p.func_rva) + 5)));

    std::memset(body + 5, 0xCC, p.func_size - 5);
    std::printf("  patched      : %-22s @rva %#x -> trampoline %#x (blob %#x)\n",
                p.name.c_str(), p.func_rva, p.tramp_rva, p.blob_rva);
  }

  return 0;
}


int Protector::wipe_handlers() {

  {
    uint32_t wiped = 0;
    for (const HandlerSet::Chunk& c : hset.chunks) {
      const int64_t off = pe.rva_to_off(c.rva);
      if (off < 0 ||
          static_cast<uint64_t>(off) + c.erase > pe.data.size()) {
        std::printf("error: cannot parse handler body (rva %#x)\n", c.rva);
        return 1;
      }
      std::memset(&pe.data[static_cast<size_t>(off)], 0xCC, c.erase);
      wiped += c.erase;
    }
    std::printf("  handler wipe : %u bytes set to 0xCC (%zu bodies, "
                "range [%#x,%#x))\n", wiped, hset.chunks.size(),
                hset.region_lo, hset.region_hi);
  }

  return 0;
}


int Protector::neutralize_list() {

  {
    bool lfound = false, nfound = false;
    const uint32_t list_rva = coff_symbol_rva(pe, "hyda_handler_list", &lfound);
    const uint32_t neutral_rva =
        coff_symbol_rva(pe, "hyda_handler_neutral", &nfound);
    if (!lfound || !nfound) {
      std::printf("error: neutralization symbols not found (list:%d neutral:%d)\n",
                  static_cast<int>(lfound), static_cast<int>(nfound));
      return 1;
    }
    if (neutral_rva >= hset.region_lo && neutral_rva < hset.region_hi) {
      std::printf("error: neutral target (%#x) is inside the handler wipe "
                  "range\n", neutral_rva);
      return 1;
    }
    const int64_t lo = pe.rva_to_off(list_rva);
    const uint64_t want = (static_cast<uint64_t>(hyda::OP_COUNT) + 1) * 8;
    if (lo < 0 || static_cast<uint64_t>(lo) + want > pe.data.size()) {
      std::printf("error: cannot parse handler list (rva %#x)\n", list_rva);
      return 1;
    }
    for (size_t i = 0; i <= hyda::OP_COUNT; ++i) {
      wr64(&pe.data[static_cast<size_t>(lo) + i * 8],
           pe.image_base + neutral_rva);
    }
    std::printf("  handler list : `hyda_handler_list` neutralized (%u entries -> "
                "rva %#x)\n", static_cast<unsigned>(hyda::OP_COUNT + 1),
                neutral_rva);
  }

  return 0;
}


int Protector::rewrite_sections() {

  uint8_t* cof = &pe.data[pe.cof_off];
  const uint16_t old_n = rd16(cof + 2);
  wr16(cof + 2, static_cast<uint16_t>(old_n + 1 + ncont + ndat));

  const uint32_t new_sect_off = pe.sect_off + static_cast<uint32_t>(old_n) * 40;

  if (new_sect_off + (1 + ncont + ndat) * 40 > pe.size_of_headers) {
    std::printf("error: no room for %u new sections in headers\n",
                1 + ncont + ndat);
    return 1;
  }
  uint8_t* sh = &pe.data[new_sect_off];
  std::memset(sh, 0, 40);
  std::memcpy(sh, ".hydavm", 7);
  wr32(sh + 8, virt_size);
  wr32(sh + 12, new_va);
  wr32(sh + 16, raw_size);
  wr32(sh + 20, raw_off);
  wr32(sh + 36, 0x60000020u);

  std::vector<uint8_t> cont_strtab(4, 0);
  for (unsigned c = 0; c < ncont; ++c) {
    const ContainerPlan& cp = partset.containers[c];
    uint8_t* sc = &pe.data[new_sect_off + 40 + static_cast<size_t>(c) * 40];
    std::memset(sc, 0, 40);
    set_section_name(sc, cp.name, &cont_strtab);
    wr32(sc + 8, cp.total);
    wr32(sc + 12, cp.rva);
    wr32(sc + 16, cp.raw_size);
    wr32(sc + 20, cp.raw_addr);
    wr32(sc + 36, 0x40000040u);
  }

  if (ndat != 0) {
    uint8_t* sd = &pe.data[new_sect_off + 40 + static_cast<size_t>(ncont) * 40];
    std::memset(sd, 0, 40);
    std::memcpy(sd, ".hdat3", 6);
    wr32(sd + 8, dat_total);
    wr32(sd + 12, dat_rva);
    wr32(sd + 16, dat_raw_size);
    wr32(sd + 20, dat_raw);
    wr32(sd + 36, 0x40000040u);
  }

  wr32(&pe.data[pe.opt_off + 56], ndat != 0 ? dat_rva + dat_total
                                            : partset.virt_end);

  {
    const uint16_t total = rd16(cof + 2);
    if (pe.sect_off + static_cast<uint32_t>(total) * 40 > pe.data.size()) {
      std::printf("error: section table outside file\n");
      return 1;
    }

    struct Hdr {
      std::array<uint8_t, 40> bytes{};
      std::string name;
    };
    std::vector<Hdr> kept;
    std::vector<uint32_t> zero_ranges;
    unsigned fn_index = 0;
    unsigned dropped = 0;
    for (uint16_t i = 0; i < total; ++i) {
      uint8_t* h = &pe.data[pe.sect_off + static_cast<uint32_t>(i) * 40];
      const std::string name = pe.resolve_name(h);
      const uint32_t rs = rd32(h + 16), ra = rd32(h + 20);
      if (name.compare(0, 7, ".debug_") == 0) {

        if (rs != 0) {
          zero_ranges.push_back(ra);
          zero_ranges.push_back(rs);
        }
        ++dropped;
        continue;
      }
      Hdr hd;
      std::memcpy(hd.bytes.data(), h, 40);
      hd.name = name;
      if (name.compare(0, 7, "hydafn_") == 0) {

        static const char* const kNeutral[] = {
            ".rdata", ".rodata", ".data", ".text", ".bss",
            ".idata", ".edata", ".tls",   ".data1", ".rdata1"};
        const unsigned h =
            ((fn_index++) * 2654435761u) ^ static_cast<unsigned>(vm_seed_val);
        hd.name = kNeutral[(h >> 8) % (sizeof(kNeutral) / sizeof(kNeutral[0]))];
      }
      kept.push_back(std::move(hd));
    }

    std::vector<uint8_t> strtab(4, 0);
    for (Hdr& hd : kept) {
      set_section_name(hd.bytes.data(), hd.name, &strtab);
    }

    if (pe.ptr_symtab != 0) {
      const uint32_t sym_bytes = pe.num_symbols * 18u;
      const uint32_t str_off = pe.ptr_symtab + sym_bytes;
      uint32_t str_size = 4;
      if (str_off + 4 <= pe.data.size()) {
        str_size = rd32(&pe.data[str_off]);
        if (str_size < 4 || str_off + str_size > pe.data.size()) str_size = 4;
      }
      if (str_off + str_size > pe.data.size()) {
        std::printf("error: string table outside file\n");
        return 1;
      }

      std::memset(&pe.data[pe.ptr_symtab], 0, sym_bytes);

      if (strtab.size() > str_size) {
        std::printf("error: new string table does not fit (%zu > %u)\n",
                    strtab.size(), str_size);
        return 1;
      }
      wr32(&strtab[0], static_cast<uint32_t>(strtab.size()));
      std::memset(&pe.data[str_off], 0, str_size);
      std::memcpy(&pe.data[str_off], strtab.data(), strtab.size());

      wr32(cof + 8, str_off);
      wr32(cof + 12, 0);
    } else if (strtab.size() > 4) {
      std::printf("error: long section name without a COFF string table\n");
      return 1;
    }

    for (size_t i = 0; i + 1 < zero_ranges.size(); i += 2) {
      const uint32_t ra = zero_ranges[i], rs = zero_ranges[i + 1];
      if (static_cast<uint64_t>(ra) + rs > pe.data.size()) {
        std::printf("error: erased section outside file (offset %#x)\n", ra);
        return 1;
      }
      std::memset(&pe.data[ra], 0, rs);
    }

    for (size_t i = 0; i < kept.size(); ++i) {
      std::memcpy(&pe.data[pe.sect_off + static_cast<uint32_t>(i) * 40],
                  kept[i].bytes.data(), 40);
    }

    for (uint32_t i = static_cast<uint32_t>(kept.size()); i < total; ++i) {
      std::memset(&pe.data[pe.sect_off + i * 40], 0, 40);
    }
    wr16(cof + 2, static_cast<uint16_t>(kept.size()));

    wr16(cof + 18, static_cast<uint16_t>(rd16(cof + 18) | 0x0200u));

    std::printf("  stripping    : %u debug sections removed, %u section names "
                "neutralized, symbol table cleared\n",
                dropped, fn_index);
  }

  return 0;
}


int Protector::apply_rebase() {

  if (do_rebase) {
    const uint32_t rel_rva = rd32(&pe.data[pe.opt_off + 112 + 5 * 8]);
    const uint32_t rel_size = rd32(&pe.data[pe.opt_off + 112 + 5 * 8 + 4]);
    if (rel_rva == 0 || rel_size == 0) {
      std::printf("error: no .reloc (BASERELOC) directory for --rebase\n");
      return 1;
    }
    if (rebase_to % 0x10000 != 0) {
      std::printf("error: --rebase address must be 64K aligned (%#llx)\n",
                  static_cast<unsigned long long>(rebase_to));
      return 1;
    }

    const int64_t delta = static_cast<int64_t>(rebase_to) -
                          static_cast<int64_t>(pe.image_base);
    uint32_t pos = 0;
    size_t fixed = 0;
    while (pos + 8 <= rel_size) {
      const int64_t off = pe.rva_to_off(rel_rva + pos);
      if (off < 0) {
        std::printf("error: cannot parse relocation block (rva %#x)\n", rel_rva + pos);
        return 1;
      }
      uint8_t* blk = &pe.data[off];
      const uint32_t page = rd32(blk);
      const uint32_t bsize = rd32(blk + 4);
      if (bsize < 8 || pos + bsize > rel_size) break;
      const uint32_t n = (bsize - 8) / 2;
      for (uint32_t i = 0; i < n; ++i) {
        const uint16_t e = rd16(blk + 8 + i * 2);
        const uint32_t type = e >> 12;
        const uint32_t o = e & 0xFFFu;
        if (type == 0) continue;
        if (type != 10) {
          std::printf("error: unsupported relocation type %u\n", type);
          return 1;
        }
        const int64_t fo = pe.rva_to_off(page + o);
        if (fo < 0) {
          std::printf("error: cannot parse relocation target (rva %#x)\n", page + o);
          return 1;
        }
        wr64(&pe.data[fo], rd64(&pe.data[fo]) + static_cast<uint64_t>(delta));
        ++fixed;
      }
      pos += bsize;
    }

    wr64(&pe.data[pe.opt_off + 24], rebase_to);
    std::printf("  rebase       : %#llx -> %#llx (%zu relocations)\n",
                static_cast<unsigned long long>(pe.image_base),
                static_cast<unsigned long long>(rebase_to), fixed);
  }

  return 0;
}


int Protector::build_integrity_data() {

  if (integrity_rva != 0 && !integrity_chunks.empty()) {

    const auto chunk_file_off = [&](uint32_t rva) -> int64_t {
      for (const hyda::IntegrityRegion& reg : integrity_regions) {
        if (rva >= reg.rva && rva < reg.rva + reg.size) {
          return static_cast<int64_t>(reg.raw) +
                 static_cast<int64_t>(rva - reg.rva);
        }
      }
      return -1;
    };
    for (hyda::IntegrityChunk& c : integrity_chunks) {
      const int64_t off = chunk_file_off(c.rva);
      if (off < 0 ||
          static_cast<uint64_t>(off) + c.size > pe.data.size()) {
        std::printf("error: cannot parse integrity chunk (rva %#x)\n", c.rva);
        return 1;
      }
      c.crc32 = hyda::integrity_crc32(&pe.data[static_cast<size_t>(off)],
                                      c.size);
    }

    const uint32_t man_off = integrity_rva - new_va;
    const uint32_t chunk_bytes =
        static_cast<uint32_t>(integrity_chunks.size()) *
        static_cast<uint32_t>(sizeof(hyda::IntegrityChunk));

    const uint32_t salt = static_cast<uint32_t>(
        hyda::integrity_key_for(0x1BEEu, pe.image_base) & 0xFFFFFFFFu);
    hyda::IntegrityManifest man;
    man.magic = hyda::integrity_magic();
    man.version = hyda::HYDA_INTEGRITY_VERSION;
    man.count = static_cast<uint32_t>(integrity_chunks.size());
    man.chunks_rva = dat_rva;
    man.salt = salt;
    man.reserved[0] = 0;
    man.reserved[1] = 0;

    std::vector<uint8_t> plain(chunk_bytes);
    for (size_t i = 0; i < integrity_chunks.size(); ++i) {
      std::memcpy(&plain[i * sizeof(hyda::IntegrityChunk)],
                  &integrity_chunks[i], sizeof(hyda::IntegrityChunk));
    }
    man.self_crc32 = hyda::integrity_crc32(plain.data(), plain.size());

    const uint64_t key = hyda::integrity_key_for(salt, integrity_rva);
    hyda::integrity_crypt(plain.data(), chunk_bytes, key, true);
    std::memcpy(&blob[man_off], &man, sizeof(man));

    std::vector<uint8_t>& dat = dat_bytes;
    dat.assign(dat_total, 0);
    bool dat_ok = false;
    const uint32_t dat_payload_total =
        static_cast<uint32_t>(sizeof(hyda::DatHeader)) + chunk_bytes;
    for (unsigned attempt = 0; attempt < 8 && !dat_ok; ++attempt) {
      uint64_t ds = 0xD6E8FEB86659FD93ull ^ (0x9E3779B97F4A7C15ull * (attempt + 1))
                    ^ static_cast<uint64_t>(dat_rva);
      for (uint32_t i = dat_payload_total; i < dat_total; ++i) {
        dat[i] = static_cast<uint8_t>(hyda::splitmix64(ds) & 0xFFu);
      }
      hyda::DatHeader dh;
      std::memset(&dh, 0, sizeof(dh));
      dh.magic = hyda::dat_magic();
      dh.version = hyda::HYDA_DAT_VERSION;
      dh.total_size = dat_payload_total;
      dh.count = static_cast<uint32_t>(integrity_chunks.size());
      dh.salt = salt;
      dh.self_crc32 = man.self_crc32;
      std::memcpy(dat.data(), &dh, sizeof(dh));
      std::memcpy(dat.data() + sizeof(dh), plain.data(), chunk_bytes);

      hyda::hydak_xor(dat.data(), dat_payload_total,
                      hyda::dat_key_for(dat_rva));

      dat_ok = true;
      for (uint32_t off = 0; off + 16u <= dat_total; off += 16u) {
        uint32_t t = 0;
        if (hyda::hydak_probe(dat.data() + off, dat_total - off,
                              hyda::hydak_key_for(dat_rva + off), &t)) {
          dat_ok = false;
          break;
        }
      }
      hyda::DatHeader chk;
      if (dat_ok &&
          !hyda::dat_open(dat.data(), dat_total, hyda::dat_key_for(dat_rva),
                          &chk)) {
        dat_ok = false;
      }
      if (dat_ok) hyda::dat_close(dat.data(), chk.total_size,
                                  hyda::dat_key_for(dat_rva));
    }
    if (!dat_ok) {
      std::printf("error: cannot build audit data container (padding signature "
                  "collision)\n");
      return 1;
    }

    std::printf("  integrity    : %zu chunks, %zu sections, manifest rva %#x, "
                "data container rva %#x (%u bytes, RVA-bound encryption)\n",
                integrity_chunks.size(), integrity_regions.size(),
                integrity_rva, dat_rva, dat_total);

  }

  return 0;
}


void Protector::build_report() {
  report.input = in_path != nullptr ? in_path : "";
  report.output = out_path != nullptr ? out_path : "";
  report.dry_run = dry_run;
  report.strict = strict_opt;
  report.image_base = pe.image_base;
  report.vm_seed = vm_seed_val;
  report.hydak_seed = hydak_seed;
  report.prof_mask = prof_mask;
  report.prof_key = prof_key;
  report.prof_base = prof_base;
  report.prof_shift = prof_shift;
  report.prof_call = prof_call;
  report.prof_crypt = prof_crypt;
  report.skipped = skipped;

  for (const Protected& p : prot) {
    ReportFn fn;
    fn.name = p.name;
    fn.rva = p.func_rva;
    fn.x86_bytes = p.func_size;
    fn.bytecode_bytes = static_cast<uint32_t>(p.code.size());
    fn.islands = p.st_islands;
    fn.fused = p.st_fused;
    fn.variants = p.st_variants;
    fn.dead_flags = p.st_dead_flags;
    fn.opcodes = p.st_opcodes;
    fn.encrypted = !p.no_crypt;
    report.functions.push_back(std::move(fn));
  }
}


int Protector::emit_report() {
  if (report_path.empty()) return 0;
  std::string err;
  if (!write_report(report, report_path, &err)) {
    std::printf("error: %s\n", err.c_str());
    return 1;
  }
  std::printf("  report       : %s (%zu protected, %zu skipped)\n",
              report_path.c_str(), report.functions.size(),
              report.skipped.size());
  return 0;
}


int Protector::write_output() {

  pe.data.resize(raw_off, 0);
  pe.data.insert(pe.data.end(), blob.begin(), blob.end());
  pe.data.resize(static_cast<size_t>(raw_off) + raw_size, 0);
  for (unsigned c = 0; c < ncont; ++c) {
    const ContainerPlan& cp = partset.containers[c];
    pe.data.resize(cp.raw_addr, 0);
    pe.data.insert(pe.data.end(), cont_bytes[c].begin(), cont_bytes[c].end());
    pe.data.resize(static_cast<size_t>(cp.raw_addr) + cp.raw_size, 0);
  }

  if (ndat != 0 && !dat_bytes.empty()) {
    pe.data.resize(dat_raw, 0);
    pe.data.insert(pe.data.end(), dat_bytes.begin(), dat_bytes.end());
    pe.data.resize(static_cast<size_t>(dat_raw) + dat_raw_size, 0);
  }

  scrub_signatures(pe, vm_seed_val);

  if (!write_file(out_path, pe.data)) {
    std::printf("error: cannot write %s\n", out_path);
    return 1;
  }
  std::printf("  output       : %s (%zu bytes)\n", out_path, pe.data.size());
  return 0;

  return 0;
}


}  // namespace hyda::prot
