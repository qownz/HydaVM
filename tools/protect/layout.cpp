#include "layout.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

#include "hyda/codec/crypt.hpp"
#include "hyda/core/opcodes.hpp"

namespace hyda::prot {

namespace {
constexpr int kVolatile[] = {0 , 1 , 2 , 8, 9, 10, 11};
constexpr uint8_t kUwopAllocSmall = 2;
}  // namespace

uint32_t tramp_frame(uint16_t preserve) {
  unsigned n = 0;
  for (int v : kVolatile) {
    if (preserve & (1u << v)) ++n;
  }
  const unsigned slots = n + (n & 1);
  return 0x28 + 8 * slots;
}

inline uint8_t x86_code(int vreg) { return static_cast<uint8_t>(vreg); }

void emit_mem_reg(std::vector<uint8_t>* t, uint8_t disp, int reg, bool store) {
  const bool hi = reg >= 8;
  t->push_back(static_cast<uint8_t>(0x48 | (hi ? 0x04 : 0x00)));
  t->push_back(static_cast<uint8_t>(store ? 0x89 : 0x8B));
  t->push_back(static_cast<uint8_t>(0x44 | ((reg & 7) << 3)));
  t->push_back(0x24);
  t->push_back(disp);
}

std::vector<uint8_t> build_trampoline(uint32_t blob_rva, uint16_t preserve,
                                      uint32_t tramp_va, const TrampSyms& syms) {
  std::vector<int> regs;
  for (int v : kVolatile) {
    if (preserve & (1u << v)) regs.push_back(v);
  }
  const unsigned n = static_cast<unsigned>(regs.size());
  const uint32_t frame = tramp_frame(preserve);

  std::vector<uint8_t> t;
  auto emit_call = [&](uint32_t target_va) {
    t.push_back(0xE8);
    const uint32_t rel = static_cast<uint32_t>(
        static_cast<int64_t>(target_va) -
        (static_cast<int64_t>(tramp_va) + static_cast<int64_t>(t.size()) + 4));
    for (int i = 0; i < 4; ++i) t.push_back(static_cast<uint8_t>(rel >> (8 * i)));
  };

  t.push_back(0x48); t.push_back(0x83); t.push_back(0xEC);
  t.push_back(static_cast<uint8_t>(frame));

  emit_call(syms.save_simd);

  for (unsigned i = 0; i < n; ++i) {
    emit_mem_reg(&t, static_cast<uint8_t>(0x28 + 8 * i), x86_code(regs[i]), true);
  }

  t.push_back(0xB8);
  for (int i = 0; i < 4; ++i) t.push_back(static_cast<uint8_t>(blob_rva >> (8 * i)));
  const uint8_t store[] = {0x48, 0x89, 0x44, 0x24, 0x20};
  t.insert(t.end(), store, store + sizeof(store));

  emit_call(syms.dispatch);

  for (unsigned i = n; i-- > 0;) {
    emit_mem_reg(&t, static_cast<uint8_t>(0x28 + 8 * i), x86_code(regs[i]), false);
  }

  emit_call(syms.restore_simd);

  t.push_back(0x48); t.push_back(0x83); t.push_back(0xC4);
  t.push_back(static_cast<uint8_t>(frame));
  t.push_back(0xC3);
  return t;
}

void build_tramp_unwind(uint8_t* w, uint32_t frame) {
  std::memset(w, 0, 8);
  w[0] = 1;
  w[1] = 4;
  w[2] = 1;
  w[3] = 0;
  w[4] = 4;
  w[5] = static_cast<uint8_t>((frame / 8 - 1) << 4) | kUwopAllocSmall;
}

void set_section_name(uint8_t* h, const std::string& name,
                      std::vector<uint8_t>* strtab) {
  std::memset(h, 0, 8);
  if (name.size() <= 8) {
    std::memcpy(h, name.data(), name.size());
    return;
  }
  const uint32_t off = static_cast<uint32_t>(strtab->size());
  strtab->insert(strtab->end(), name.begin(), name.end());
  strtab->push_back(0);
  char buf[16];
  std::snprintf(buf, sizeof(buf), "/%u", off);
  std::memcpy(h, buf, std::strlen(buf));
}

const char* const kContainerNames[] = {".rdata",  ".rodata", ".hdata0",
                                       ".hdat1",  ".gccdat", ".ehdata",
                                       ".hvmdat"};

bool plan_handler_parts(const HandlerSet& hs, uint64_t seed, unsigned want_parts,
                        unsigned want_decoys, unsigned want_containers,
                        uint32_t first_rva, uint32_t section_align,
                        uint32_t file_align, uint32_t file_start, PartSet* out,
                        std::string* err) {
  const size_t n = hs.chunks.size();
  if (n == 0) {
    *err = "no handler body";
    return false;
  }
  unsigned nparts = want_parts ? want_parts : 1;
  if (nparts > hyda::HYDA_HYDAK_MAX_PARTS) nparts = hyda::HYDA_HYDAK_MAX_PARTS;
  if (nparts > n) nparts = static_cast<unsigned>(n);

  uint64_t s = seed ? seed : 1;

  std::vector<uint32_t> order(n);
  for (size_t i = 0; i < n; ++i) order[i] = static_cast<uint32_t>(i);
  for (size_t i = n; i > 1; --i) {
    const size_t k = static_cast<size_t>(hyda::splitmix64(s) % i);
    std::swap(order[i - 1], order[k]);
  }

  out->parts.assign(nparts, PartPlan{});
  std::vector<uint64_t> load(nparts, 0);
  for (uint32_t idx : order) {
    unsigned best = 0;
    for (unsigned k = 1; k < nparts; ++k) {
      if (load[k] < load[best] ||
          (load[k] == load[best] && (hyda::splitmix64(s) & 1u) != 0)) {
        best = k;
      }
    }
    out->parts[best].chunk.push_back(idx);
    load[best] += hs.chunks[idx].size + 16u;
  }

  uint32_t pmin = 0xFFFFFFFFu, pmax = 0;
  for (unsigned k = 0; k < nparts; ++k) {
    PartPlan& p = out->parts[k];
    p.seed = s ^ (0xA24BAED4963EE407ull * (k + 1));
    uint64_t ps = p.seed;
    uint32_t cursor = hyda::HYDA_HYDAK_CODE_OFF;
    p.off.reserve(p.chunk.size());
    for (uint32_t g : p.chunk) {
      p.off.push_back(cursor);
      cursor += hs.chunks[g].size;
      cursor = align_up(cursor, 16);
      const uint32_t gap =
          16u * static_cast<uint32_t>(hyda::splitmix64(ps) % 8u);
      cursor = align_up(cursor + gap, 16);
    }
    p.code_size = align_up(cursor, 16) - hyda::HYDA_HYDAK_CODE_OFF;
    p.chunks_off = align_up(cursor, 16);
    p.opmap_off =
        align_up(p.chunks_off + static_cast<uint32_t>(p.chunk.size()) * 12, 8);

    p.total = align_up(p.opmap_off + static_cast<uint32_t>(hyda::OP_COUNT) * 2,
                       16);
    if (p.total < pmin) pmin = p.total;
    if (p.total > pmax) pmax = p.total;
  }

  struct Item {
    bool real;
    uint32_t part;
    uint32_t total;
    uint64_t seed;
  };
  std::vector<Item> items;
  for (unsigned k = 0; k < nparts; ++k) {
    items.push_back({true, k, out->parts[k].total, 0});
  }
  unsigned ndeco = want_decoys;
  const unsigned deco_cap = 3u * nparts + 8u;
  if (ndeco > deco_cap) ndeco = deco_cap;
  for (unsigned d = 0; d < ndeco; ++d) {
    const uint32_t span = (pmax > pmin) ? (pmax - pmin) : 0;
    uint32_t t = pmin;
    if (span != 0) {
      t = pmin + static_cast<uint32_t>(hyda::splitmix64(s) % (span + 1u));
    }
    t = align_up(t, 16);
    if (t < hyda::HYDA_HYDAK_CODE_OFF + 32u) {
      t = align_up(hyda::HYDA_HYDAK_CODE_OFF + 32u, 16);
    }
    items.push_back({false, 0, t, s ^ (0x94D049BB133111EBull * (d + 1))});
  }

  for (size_t i = items.size(); i > 1; --i) {
    const size_t k = static_cast<size_t>(hyda::splitmix64(s) % i);
    std::swap(items[i - 1], items[k]);
  }

  const unsigned name_n =
      static_cast<unsigned>(sizeof(kContainerNames) / sizeof(kContainerNames[0]));
  unsigned ncont = want_containers ? want_containers : 1;
  if (ncont > name_n) ncont = name_n;
  if (ncont > items.size()) ncont = static_cast<unsigned>(items.size());
  out->containers.assign(ncont, ContainerPlan{});

  std::vector<Item> reals, fakes;
  for (const Item& it : items) {
    (it.real ? reals : fakes).push_back(it);
  }
  for (int pass = 0; pass < 2; ++pass) {
    const std::vector<Item>& list = (pass == 0) ? reals : fakes;
    for (size_t i = 0; i < list.size(); ++i) {
      ContainerPlan& cp = out->containers[i % ncont];
      Block b;
      b.real = list[i].real;
      b.part = list[i].part;
      b.total = list[i].total;
      b.seed = list[i].seed;
      cp.blocks.push_back(b);
    }
  }
  uint32_t rva = first_rva;
  uint32_t raw = file_start;
  for (unsigned c = 0; c < ncont; ++c) {
    ContainerPlan& cp = out->containers[c];
    cp.name = kContainerNames[c % name_n];

    const uint64_t cs_seed = s ^ (0xD1B54A32D192ED03ull * (c + 1));
    uint64_t cs = cs_seed;
    for (size_t i = cp.blocks.size(); i > 1; --i) {
      const size_t k = static_cast<size_t>(hyda::splitmix64(cs) % i);
      std::swap(cp.blocks[i - 1], cp.blocks[k]);
    }
    uint32_t off = 0;
    for (Block& b : cp.blocks) {
      b.off = off;
      off = align_up(off + b.total, 16);
    }
    cp.total = align_up(off, section_align ? section_align : 16u);
    cp.rva = rva;
    cp.raw_addr = raw;
    cp.raw_size = align_up(cp.total, file_align ? file_align : 16u);
    rva += cp.total;
    raw += cp.raw_size;
  }
  out->virt_end = rva;

  for (const ContainerPlan& cp : out->containers) {
    for (const Block& b : cp.blocks) {
      if (b.real) out->parts[b.part].rva = cp.rva + b.off;
    }
  }
  out->new_rva.assign(n, 0);
  for (unsigned k = 0; k < nparts; ++k) {
    const PartPlan& p = out->parts[k];
    for (size_t i = 0; i < p.chunk.size(); ++i) {
      out->new_rva[p.chunk[i]] = p.rva + p.off[i];
    }
  }
  unsigned bad_found = 0;
  for (unsigned k = 0; k < nparts; ++k) {
    PartPlan& p = out->parts[k];
    for (size_t i = 0; i < p.chunk.size(); ++i) {
      if (p.chunk[i] == hs.op_chunk[hyda::OP_COUNT]) {
        p.bad_local = static_cast<uint16_t>(i);
        ++bad_found;
      }
    }
  }
  if (bad_found != 1) {
    *err = "invalid-slot handler is not in exactly one part";
    return false;
  }
  return true;
}

bool fill_part(const PeFile& pe, const HandlerSet& hs, const PartSet& ps,
               unsigned k, std::vector<uint8_t>* out, std::string* err) {
  const PartPlan& p = ps.parts[k];
  std::vector<uint8_t> part(p.total, 0);

  {
    uint64_t r = p.seed ^ 0x123456789ABCDEFull;
    for (size_t i = 0; i < part.size(); ++i) {
      part[i] = static_cast<uint8_t>(hyda::splitmix64(r) & 0xFFu);
    }
  }

  std::vector<int32_t> local(hs.chunks.size(), -1);
  for (size_t i = 0; i < p.chunk.size(); ++i) {
    local[p.chunk[i]] = static_cast<int32_t>(i);
  }

  csh h = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
    *err = "cannot initialize capstone";
    return false;
  }
  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  for (size_t i = 0; i < p.chunk.size(); ++i) {
    const HandlerSet::Chunk& c = hs.chunks[p.chunk[i]];
    const int64_t fo = pe.rva_to_off(c.rva);
    if (fo < 0) {
      cs_close(&h);
      *err = "cannot parse body";
      return false;
    }
    std::memcpy(part.data() + p.off[i], &pe.data[static_cast<size_t>(fo)],
                c.size);
    std::string cerr;
    if (!relocate_chunk(h, hs, ps.new_rva, &pe.data[static_cast<size_t>(fo)],
                        c.size, c.rva, part.data(), p.off[i], p.rva, &cerr)) {
      cs_close(&h);
      char buf[64];
      std::snprintf(buf, sizeof(buf), "%#x: ", c.rva);
      *err = std::string(buf) + cerr;
      return false;
    }
  }
  cs_close(&h);

  uint8_t* hp = part.data();
  wr32(hp + 0, hyda::hydak_magic());
  wr32(hp + 4, p.total);
  wr32(hp + 8, p.code_size);
  wr32(hp + 12, static_cast<uint32_t>(p.chunk.size()));
  wr32(hp + 16, p.chunks_off);
  wr32(hp + 20, p.opmap_off);
  wr16(hp + 24, p.bad_local);
  wr16(hp + 26, static_cast<uint16_t>(hyda::HYDA_HYDAK_VERSION));
  wr32(hp + 28, 0);
  for (size_t i = 0; i < p.chunk.size(); ++i) {
    const HandlerSet::Chunk& c = hs.chunks[p.chunk[i]];
    uint8_t* w = part.data() + p.chunks_off + i * 12;
    wr32(w, p.off[i]);
    wr32(w + 4, c.size);
    wr32(w + 8, c.rva);
  }
  for (size_t op = 0; op < hyda::OP_COUNT; ++op) {
    const int32_t li = local[hs.op_chunk[op]];
    wr16(part.data() + p.opmap_off + op * 2,
         li < 0 ? hyda::HYDA_HYDAK_NO_CHUNK : static_cast<uint16_t>(li));
  }

  if (const char* dump = std::getenv("HYDA_HYDAK_DUMP")) {
    std::string path = dump;
    if (ps.parts.size() > 1) path += "." + std::to_string(k);
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(part.data()),
            static_cast<std::streamsize>(p.total));
  }
  if (const char* map = std::getenv("HYDA_HYDAK_MAP")) {
    std::string path = map;
    if (ps.parts.size() > 1) path += "." + std::to_string(k);
    std::ofstream f(path);
    f << "part " << k << " part_rva " << std::hex << p.rva << "\n";
    f << "total " << p.total << " code_size " << p.code_size << " chunks_off "
      << p.chunks_off << " opmap_off " << p.opmap_off << "\n";
    for (size_t i = 0; i < p.chunk.size(); ++i) {
      const HandlerSet::Chunk& c = hs.chunks[p.chunk[i]];
      f << p.chunk[i] << " local " << i << " off " << p.off[i] << " rva "
        << c.rva << " size " << c.size << "\n";
    }
  }

  const uint32_t crc =
      hyda::crc32(part.data() + sizeof(hyda::HydakHeader),
                  p.total - static_cast<uint32_t>(sizeof(hyda::HydakHeader)));
  wr32(hp + 28, crc);
  hyda::hydak_xor(part.data(), p.total, hyda::hydak_key_for(p.rva));

  *out = std::move(part);
  return true;
}

bool build_container(const PartSet& ps,
                     const std::vector<std::vector<uint8_t>>& parts_bytes,
                     unsigned c, std::vector<uint8_t>* out, std::string* err) {
  const ContainerPlan& cp = ps.containers[c];
  std::vector<uint32_t> want_off;
  for (const Block& b : cp.blocks) {
    if (b.real) want_off.push_back(b.off);
  }

  for (unsigned attempt = 0; attempt < 16; ++attempt) {
    out->assign(cp.total, 0);

    uint64_t cseed = 0x9E3779B97F4A7C15ull ^ (0xD1B54A32D192ED03ull * (c + 1)) ^
                     (0xC2B2AE3D27D4EB4Full * (attempt + 1));
    for (size_t i = 0; i < out->size(); ++i) {
      (*out)[i] = static_cast<uint8_t>(hyda::splitmix64(cseed) & 0xFFu);
    }

    for (const Block& b : cp.blocks) {
      if (b.real) continue;
      uint64_t r = b.seed ^ (0xBB67AE8584CAA73Bull * (attempt + 1));
      for (uint32_t i = 0; i < b.total && b.off + i < out->size(); ++i) {
        (*out)[b.off + i] =
            static_cast<uint8_t>(hyda::splitmix64(r) & 0xFFu);
      }
    }

    for (const Block& b : cp.blocks) {
      if (!b.real) continue;
      const std::vector<uint8_t>& pb = parts_bytes[b.part];
      if (b.off + pb.size() > out->size()) {
        *err = "part exceeds container limit";
        return false;
      }
      std::memcpy(out->data() + b.off, pb.data(), pb.size());
    }

    hyda::HandlerShardDesc got[hyda::HYDA_HYDAK_MAX_PARTS];
    uint32_t verr = hyda::HYDAK_OK;
    const unsigned gn = hyda::hydak_scan_parts(
        out->data(), cp.total, cp.rva, got, hyda::HYDA_HYDAK_MAX_PARTS, &verr);
    bool ok = (verr == hyda::HYDAK_OK) && (gn == want_off.size());
    if (ok) {
      for (unsigned i = 0; i < gn; ++i) {
        if (got[i].rva - cp.rva != want_off[i]) {
          ok = false;
          break;
        }
      }
    }
    if (ok) return true;
  }
  *err = "container scan does not match plan (decoy signature collision)";
  return false;
}

}  // namespace hyda::prot
