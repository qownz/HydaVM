#include "handlers.hpp"

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstring>
#include <map>
#include <utility>

namespace hyda::prot {

void read_pdata(const PeFile& pe, std::vector<PdataRange>* out) {
  const uint32_t rva = pe.dir_rva(3);
  const uint32_t size = pe.dir_size(3);
  if (rva == 0 || size < 12) return;
  const int64_t off = pe.rva_to_off(rva);
  if (off < 0) return;
  const uint32_t n = size / 12;
  out->reserve(n);
  for (uint32_t i = 0; i < n; ++i) {
    const uint64_t at = static_cast<uint64_t>(off) + i * 12ull;
    if (at + 12 > pe.data.size()) break;
    PdataRange r;
    r.begin = rd32(&pe.data[static_cast<size_t>(at)]);
    r.end = rd32(&pe.data[static_cast<size_t>(at) + 4]);
    if (r.end > r.begin) out->push_back(r);
  }
  std::sort(out->begin(), out->end(),
            [](const PdataRange& a, const PdataRange& b) { return a.begin < b.begin; });
}

int chunk_of_rva(const HandlerSet& hs, int64_t rva) {
  auto it = std::upper_bound(
      hs.by_rva.begin(), hs.by_rva.end(), rva,
      [&](int64_t v, uint32_t i) {
        return v < static_cast<int64_t>(hs.chunks[i].rva);
      });
  if (it == hs.by_rva.begin()) return -1;
  --it;
  const uint32_t i = *it;
  if (rva >= hs.chunks[i].rva &&
      rva < static_cast<int64_t>(hs.chunks[i].rva) + hs.chunks[i].size) {
    return static_cast<int>(i);
  }
  return -1;
}

int section_of_rva(const PeFile& pe, uint32_t rva) {
  for (size_t i = 0; i < pe.sections.size(); ++i) {
    const Section& s = pe.sections[i];
    const uint32_t vs = s.virt_size ? s.virt_size : s.raw_size;
    if (rva >= s.virt_addr && rva < s.virt_addr + vs) return static_cast<int>(i);
  }
  return -1;
}

uint32_t coff_symbol_rva(const PeFile& pe, const std::string& want, bool* found) {
  *found = false;
  if (pe.ptr_symtab == 0 || pe.num_symbols == 0) return 0;
  const uint64_t str_at = static_cast<uint64_t>(pe.ptr_symtab) +
                          static_cast<uint64_t>(pe.num_symbols) * 18ull;
  if (str_at + 4 > pe.data.size()) return 0;
  for (uint32_t i = 0; i < pe.num_symbols; ++i) {
    const uint64_t at = static_cast<uint64_t>(pe.ptr_symtab) + i * 18ull;
    if (at + 18 > pe.data.size()) break;
    const uint8_t* rec = &pe.data[static_cast<size_t>(at)];
    const uint8_t naux = rec[17];
    std::string name;
    if (rec[0] == 0 && rec[1] == 0 && rec[2] == 0 && rec[3] == 0) {
      const uint32_t so = rd32(rec + 4);
      const uint64_t na = str_at + so;
      if (na < pe.data.size())
        name = reinterpret_cast<const char*>(&pe.data[static_cast<size_t>(na)]);
    } else {
      char b[9];
      std::memcpy(b, rec, 8);
      b[8] = 0;
      name = b;
    }
    const int16_t sec = static_cast<int16_t>(rd16(rec + 12));
    if (name == want && sec >= 1 &&
        static_cast<size_t>(sec) <= pe.sections.size()) {
      *found = true;
      return pe.sections[sec - 1].virt_addr + rd32(rec + 8);
    }
    i += naux;
  }
  return 0;
}

void coff_symbol_rvas_in_section(const PeFile& pe, int sec_idx,
                                 std::vector<uint32_t>* out) {
  if (pe.ptr_symtab == 0 || pe.num_symbols == 0) return;
  for (uint32_t i = 0; i < pe.num_symbols; ++i) {
    const uint64_t at = static_cast<uint64_t>(pe.ptr_symtab) + i * 18ull;
    if (at + 18 > pe.data.size()) break;
    const uint8_t* rec = &pe.data[static_cast<size_t>(at)];
    const uint8_t naux = rec[17];
    const int16_t sec = static_cast<int16_t>(rd16(rec + 12));
    if (sec == sec_idx + 1) {
      out->push_back(pe.sections[sec_idx].virt_addr + rd32(rec + 8));
    }
    i += naux;
  }
}

uint32_t coff_function_symbols_in_section(const PeFile& pe, int sec_idx) {
  if (pe.ptr_symtab == 0 || pe.num_symbols == 0) return 0;
  uint32_t n = 0;
  for (uint32_t i = 0; i < pe.num_symbols; ++i) {
    const uint64_t at = static_cast<uint64_t>(pe.ptr_symtab) + i * 18ull;
    if (at + 18 > pe.data.size()) break;
    const uint8_t* rec = &pe.data[static_cast<size_t>(at)];
    const uint8_t naux = rec[17];
    const int16_t sec = static_cast<int16_t>(rd16(rec + 12));

    const uint16_t type = rd16(rec + 14);
    if (sec == sec_idx + 1 && (type & 0xF0u) == 0x20u) ++n;
    i += naux;
  }
  return n;
}

bool discover_handlers(const PeFile& pe, HandlerSet* out, std::string* err) {
  bool found = false;
  const uint32_t list_rva = coff_symbol_rva(pe, "hyda_handler_list", &found);
  if (!found) {
    *err = "`hyda_handler_list` symbol not found (target must not be stripped)";
    return false;
  }
  const int64_t list_off = pe.rva_to_off(list_rva);
  const uint64_t want = (static_cast<uint64_t>(hyda::OP_COUNT) + 1) * 8;
  if (list_off < 0 ||
      static_cast<uint64_t>(list_off) + want > pe.data.size()) {
    *err = "cannot read handler list from file";
    return false;
  }

  std::vector<uint32_t> hrva;
  hrva.reserve(hyda::OP_COUNT + 1);
  for (size_t i = 0; i <= hyda::OP_COUNT; ++i) {
    const uint64_t v = rd64(&pe.data[static_cast<size_t>(list_off) + i * 8]);
    if (v < pe.image_base || v - pe.image_base >= pe.size_of_image) {
      *err = "handler list points outside the image";
      return false;
    }
    hrva.push_back(static_cast<uint32_t>(v - pe.image_base));
  }

  std::map<uint32_t, uint16_t> uniq;
  out->op_chunk.assign(hyda::OP_COUNT + 1, 0);
  for (size_t i = 0; i <= hyda::OP_COUNT; ++i) {
    auto it = uniq.find(hrva[i]);
    if (it == uniq.end()) {
      if (out->chunks.size() >= 0xFFFFu) {
        *err = "too many unique handlers";
        return false;
      }
      const uint16_t idx = static_cast<uint16_t>(out->chunks.size());
      uniq[hrva[i]] = idx;
      HandlerSet::Chunk c;
      c.rva = hrva[i];
      out->chunks.push_back(c);
      out->op_chunk[i] = idx;
    } else {
      out->op_chunk[i] = it->second;
    }
  }

  const int sec_idx = section_of_rva(pe, out->chunks[0].rva);
  if (sec_idx < 0) {
    *err = "cannot parse handler section";
    return false;
  }
  std::vector<uint32_t> syms;
  coff_symbol_rvas_in_section(pe, sec_idx, &syms);
  if (syms.empty()) {
    *err = "handler section has no symbols";
    return false;
  }
  std::sort(syms.begin(), syms.end());
  syms.erase(std::unique(syms.begin(), syms.end()), syms.end());

  std::vector<PdataRange> pd;
  read_pdata(pe, &pd);

  for (HandlerSet::Chunk& c : out->chunks) {

    auto it = std::upper_bound(syms.begin(), syms.end(), c.rva);
    if (it == syms.end()) {
      *err = "handler extent boundary (next symbol) not found";
      return false;
    }
    const uint32_t sym_end = *it;
    c.erase = sym_end - c.rva;
    if (c.erase == 0 || c.erase > kHydakMaxChunk) {
      *err = "unreasonable handler size";
      return false;
    }
    c.size = c.erase;

    auto p = std::lower_bound(
        pd.begin(), pd.end(), c.rva,
        [](const PdataRange& r, uint32_t v) { return r.begin < v; });
    if (p != pd.end() && p->begin == c.rva) {
      if (p->end > sym_end) {
        *err = "`.pdata` function end exceeds symbol boundary";
        return false;
      }
      c.size = p->end - c.rva;
      ++out->pdata_used;
    }
    const int64_t fo = pe.rva_to_off(c.rva);
    if (fo < 0 || static_cast<uint64_t>(fo) + c.erase > pe.data.size()) {
      *err = "handler body outside file";
      return false;
    }

  }

  std::vector<std::pair<uint32_t, uint32_t>> iv;
  iv.reserve(out->chunks.size());
  out->region_lo = UINT32_MAX;
  out->region_hi = 0;
  for (const HandlerSet::Chunk& c : out->chunks) {
    iv.push_back({c.rva, c.rva + c.erase});
    out->region_lo = std::min(out->region_lo, c.rva);
    out->region_hi = std::max(out->region_hi, c.rva + c.erase);
  }
  std::sort(iv.begin(), iv.end());
  for (size_t i = 1; i < iv.size(); ++i) {
    if (iv[i].first < iv[i - 1].second) {
      *err = "handler bodies overlap";
      return false;
    }
  }

  out->by_rva.resize(out->chunks.size());
  for (size_t i = 0; i < out->chunks.size(); ++i) {
    out->by_rva[i] = static_cast<uint32_t>(i);
  }
  std::sort(out->by_rva.begin(), out->by_rva.end(),
            [&](uint32_t a, uint32_t b) {
              return out->chunks[a].rva < out->chunks[b].rva;
            });
  return true;
}

bool branch_rel(const cs_x86& x, BranchRel* out) {
  *out = BranchRel{};
  if (x.op_count < 1 || x.operands[0].type != X86_OP_IMM) return false;
  out->direct = true;
  out->size = x.encoding.imm_size;
  out->off = x.encoding.imm_offset;
  out->target = static_cast<int64_t>(x.operands[0].imm);
  return out->size == 1 || out->size == 2 || out->size == 4;
}

bool relocate_chunk(csh h, const HandlerSet& hs,
                    const std::vector<uint32_t>& new_rva, const uint8_t* src,
                    uint32_t len, uint32_t orig_rva, uint8_t* shard,
                    uint32_t dst_off, uint32_t shard_rva, std::string* err) {
  cs_insn* insn = nullptr;
  const size_t n = cs_disasm(h, src, len, orig_rva, 0, &insn);
  if (n == 0) {
    *err = "disassembly failed";
    return false;
  }
  size_t consumed = 0;
  bool ok = true;
  for (size_t i = 0; i < n && ok; ++i) {
    const cs_insn& in = insn[i];
    consumed += in.size;
    const cs_x86& x = in.detail->x86;
    const bool is_branch = cs_insn_group(h, &in, CS_GRP_JUMP) ||
                           cs_insn_group(h, &in, CS_GRP_CALL);
    int rip_op = -1;
    bool is_abs = false;
    for (int k = 0; k < x.op_count; ++k) {
      if (x.operands[k].type != X86_OP_MEM) continue;
      if (x.operands[k].mem.base == X86_REG_RIP) {
        rip_op = k;
      } else if (x.operands[k].mem.base == X86_REG_INVALID &&
                 x.operands[k].mem.index == X86_REG_INVALID) {
        is_abs = true;
      }
    }

    if (rip_op >= 0) {
      const size_t fo = static_cast<size_t>(in.address - orig_rva) +
                        x.encoding.disp_offset;
      if (x.encoding.disp_offset == 0 || fo + 4 > static_cast<size_t>(len) ||
          static_cast<int32_t>(rd32(src + fo)) !=
              static_cast<int32_t>(x.operands[rip_op].mem.disp)) {
        *err = "cannot verify RIP-relative displacement field";
        ok = false;
        continue;
      }
      const int64_t t = static_cast<int64_t>(in.address) +
                        static_cast<int64_t>(in.size) +
                        static_cast<int32_t>(rd32(src + fo));
      uint64_t ta = static_cast<uint64_t>(t);
      const int tc = chunk_of_rva(hs, t);
      if (tc >= 0) {
        ta = static_cast<uint64_t>(new_rva[static_cast<size_t>(tc)]) +
             static_cast<uint64_t>(t - hs.chunks[static_cast<size_t>(tc)].rva);
      }
      const uint64_t fa = static_cast<uint64_t>(shard_rva) + dst_off + fo;
      const int64_t nd = static_cast<int64_t>(ta) - static_cast<int64_t>(fa + 4);
      if (nd < INT32_MIN || nd > INT32_MAX) {
        *err = "new RIP-relative displacement does not fit in 32 bits";
        ok = false;
      } else {
        wr32(shard + dst_off + fo, static_cast<uint32_t>(nd));
      }
      continue;
    }

    BranchRel br;
    if (is_branch && branch_rel(x, &br)) {
      const int64_t t = br.target;
      const size_t fo =
          static_cast<size_t>(in.address - orig_rva) + br.off;
      if (br.size == 1) {

        if (t < static_cast<int64_t>(orig_rva) ||
            t >= static_cast<int64_t>(orig_rva) + len) {
          *err = "rel8 branch leaves the body (cannot relocate)";
          ok = false;
        }
        continue;
      }
      uint64_t ta = static_cast<uint64_t>(t);
      const int tc = chunk_of_rva(hs, t);
      if (tc >= 0) {
        ta = static_cast<uint64_t>(new_rva[static_cast<size_t>(tc)]) +
             static_cast<uint64_t>(t - hs.chunks[static_cast<size_t>(tc)].rva);
      }
      const uint64_t fa = static_cast<uint64_t>(shard_rva) + dst_off + fo;
      if (br.size == 2) {
        const int64_t nd =
            static_cast<int64_t>(ta) - static_cast<int64_t>(fa + 2);
        if (nd < INT16_MIN || nd > INT16_MAX) {
          *err = "new rel16 displacement does not fit in 16 bits";
          ok = false;
        } else {
          const uint16_t v = static_cast<uint16_t>(nd);
          shard[dst_off + fo] = static_cast<uint8_t>(v);
          shard[dst_off + fo + 1] = static_cast<uint8_t>(v >> 8);
        }
      } else {
        const int64_t nd =
            static_cast<int64_t>(ta) - static_cast<int64_t>(fa + 4);
        if (nd < INT32_MIN || nd > INT32_MAX) {
          *err = "new rel32 displacement does not fit in 32 bits";
          ok = false;
        } else {
          wr32(shard + dst_off + fo, static_cast<uint32_t>(nd));
        }
      }
      continue;
    }

    if (is_abs) {
      *err = "absolute addressing (cannot relocate)";
      ok = false;
    }
  }
  cs_free(insn, n);
  if (!ok) return false;
  if (consumed != len) {

    for (size_t i = consumed; i < len; ++i) {
      const uint8_t b = src[i];
      if (b != 0x00 && b != 0x90 && b != 0xCC) {
        *err = "disassembly did not cover the whole body";
        return false;
      }
    }
  }
  return true;
}

bool check_erased_tails(const PeFile& pe, const HandlerSet& hs,
                        std::string* err) {
  csh h = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
    *err = "cannot initialize capstone";
    return false;
  }
  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  bool ok = true;
  for (const HandlerSet::Chunk& c : hs.chunks) {
    if (c.erase <= c.size) continue;
    const int64_t fo = pe.rva_to_off(c.rva);
    if (fo < 0 || static_cast<uint64_t>(fo) + c.erase > pe.data.size()) {
      *err = "body/padding outside file";
      ok = false;
      break;
    }
    const uint8_t* tail = &pe.data[static_cast<size_t>(fo) + c.size];
    const uint32_t len = c.erase - c.size;
    cs_insn* insn = nullptr;
    const size_t n = cs_disasm(h, tail, len, c.rva + c.size, 0, &insn);
    size_t cov = 0;
    for (size_t i = 0; i < n; ++i) {
      cov += insn[i].size;
      const unsigned id = insn[i].id;
      if (id != X86_INS_NOP && id != X86_INS_INT3 && id != X86_INS_UD2 &&
          id != X86_INS_HLT) {
        char buf[176];
        std::snprintf(buf, sizeof(buf),
                      "bytes after body are not padding (%#x: %s) - `.pdata` "
                      "boundary may be wrong",
                      static_cast<uint32_t>(insn[i].address), insn[i].mnemonic);
        *err = buf;
        ok = false;
        break;
      }
    }
    cs_free(insn, n);
    if (ok && cov != len) {
      char buf[144];
      std::snprintf(buf, sizeof(buf),
                    "cannot parse padding after body (%#x, %u/%u bytes)", c.rva,
                    static_cast<unsigned>(cov), len);
      *err = buf;
      ok = false;
    }
    if (!ok) break;
  }
  cs_close(&h);
  return ok;
}

bool check_no_inbound_refs(const PeFile& pe, const HandlerSet& hs,
                           std::string* err) {
  const int sec_idx = section_of_rva(pe, hs.chunks[0].rva);
  if (sec_idx < 0) {
    *err = "cannot parse handler section";
    return false;
  }
  const Section& s = pe.sections[sec_idx];
  const uint32_t size = s.virt_size ? s.virt_size : s.raw_size;
  if (static_cast<uint64_t>(s.raw_addr) + size > pe.data.size()) {
    *err = "code section outside file";
    return false;
  }

  auto in_handler = [&](uint32_t rva) -> bool {
    for (const HandlerSet::Chunk& c : hs.chunks) {
      if (rva >= c.rva && rva < c.rva + c.size) return true;
    }
    return false;
  };

  csh h = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
    *err = "cannot initialize capstone";
    return false;
  }
  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  cs_insn* insn = nullptr;
  const size_t n = cs_disasm(h, &pe.data[s.raw_addr], size, s.virt_addr, 0, &insn);
  unsigned bad = 0;
  uint32_t bad_at = 0, bad_to = 0;
  for (size_t i = 0; i < n; ++i) {
    const cs_insn& in = insn[i];
    const bool is_branch = cs_insn_group(h, &in, CS_GRP_JUMP) ||
                           cs_insn_group(h, &in, CS_GRP_CALL);
    if (!is_branch) continue;

    BranchRel br;
    if (!branch_rel(in.detail->x86, &br)) continue;
    const int64_t t = br.target;
    if (t < 0) continue;
    const uint32_t target = static_cast<uint32_t>(t);
    if (!in_handler(target)) continue;
    if (in_handler(static_cast<uint32_t>(in.address))) continue;
    ++bad;
    bad_at = static_cast<uint32_t>(in.address);
    bad_to = target;
  }
  cs_free(insn, n);
  cs_close(&h);
  if (bad) {
    char buf[160];
    std::snprintf(buf, sizeof(buf),
                  "%u branch outside body enters a handler (first: %#x -> %#x)",
                  bad, bad_at, bad_to);
    *err = buf;
    return false;
  }
  return true;
}

bool check_no_rel_tables(const PeFile& pe, const HandlerSet& hs,
                         std::string* err) {
  auto in_handler = [&](int64_t t) -> bool {
    for (const HandlerSet::Chunk& c : hs.chunks) {
      if (t >= static_cast<int64_t>(c.rva) &&
          t < static_cast<int64_t>(c.rva) + c.size) {
        return true;
      }
    }
    return false;
  };

  csh h = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
    *err = "cannot initialize capstone";
    return false;
  }
  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  bool ok = true;
  for (const HandlerSet::Chunk& c : hs.chunks) {
    const int64_t fo = pe.rva_to_off(c.rva);
    if (fo < 0) {
      *err = "cannot parse body";
      ok = false;
      break;
    }
    const uint8_t* body = &pe.data[static_cast<size_t>(fo)];
    cs_insn* insn = nullptr;
    const size_t n = cs_disasm(h, body, c.size, c.rva, 0, &insn);
    for (size_t i = 0; i < n && ok; ++i) {
      const cs_insn& in = insn[i];
      const cs_x86& x = in.detail->x86;

      for (int k = 0; k < x.op_count; ++k) {
        if (x.operands[k].type != X86_OP_IMM ||
            x.operands[k].size != 8) {
          continue;
        }
        const int64_t v = static_cast<int64_t>(x.operands[k].imm);
        if (v < 0 || static_cast<uint64_t>(v) < pe.image_base) continue;
        const int64_t rva = v - static_cast<int64_t>(pe.image_base);
        if (in_handler(rva)) {
          char buf[160];
          std::snprintf(buf, sizeof(buf),
                        "absolute address immediate (%#llx) in a relocated body",
                        static_cast<unsigned long long>(v));
          *err = buf;
          ok = false;
        }
      }

      if (ok && in.id == X86_INS_LEA && x.encoding.disp_size == 4) {
        for (int k = 0; k < x.op_count; ++k) {
          if (x.operands[k].type != X86_OP_MEM ||
              x.operands[k].mem.base != X86_REG_RIP) {
            continue;
          }
          const size_t dfo = static_cast<size_t>(in.address - c.rva) +
                             x.encoding.disp_offset;
          const int64_t t = static_cast<int64_t>(in.address) +
                            static_cast<int64_t>(in.size) +
                            static_cast<int32_t>(rd32(body + dfo));
          if (t < 0 || static_cast<uint64_t>(t) >= pe.size_of_image) continue;
          const int ts = section_of_rva(pe, static_cast<uint32_t>(t));
          if (ts < 0) continue;

          if ((pe.sections[static_cast<size_t>(ts)].characteristics &
               0x80000000u) != 0) {
            continue;
          }
          const int64_t tab_off = pe.rva_to_off(static_cast<uint32_t>(t));
          if (tab_off < 0) continue;
          for (unsigned e = 0; e < 64; ++e) {
            const uint64_t at = static_cast<uint64_t>(tab_off) + e * 4ull;
            if (at + 4 > pe.data.size()) break;
            const int32_t v =
                static_cast<int32_t>(rd32(&pe.data[static_cast<size_t>(at)]));
            if (in_handler(t + v)) {
              char buf[200];
              std::snprintf(buf, sizeof(buf),
                            "relative jump table (%#x, entry %u) points into a relocated "
                            "handler; compile handlers with "
                            "-fno-jump-tables",
                            static_cast<uint32_t>(t), e);
              *err = buf;
              ok = false;
              break;
            }
          }
        }
      }
    }
    cs_free(insn, n);
    if (!ok) break;
  }
  cs_close(&h);
  return ok;
}

}  // namespace hyda::prot
