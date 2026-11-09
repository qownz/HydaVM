#include "native_island.hpp"

#include "hyda/native/island.hpp"
#include "hyda/native/island_mut.hpp"

#include <cstring>

namespace hyda {
namespace {

uint32_t align16(uint32_t v) { return (v + 15u) / 16u * 16u; }

constexpr uint32_t kTailHead = 12;

constexpr uint32_t kIslandHeaderSize = HYDA_ISLAND_SIZE;

constexpr uint32_t kIslandSlotSize = 8u;

constexpr uint32_t kMaxIslandPad = 16;
constexpr uint32_t kMaxIslandJunk = 3;

void emit_decoy(std::vector<uint8_t>& out, uint32_t rva, uint64_t& seed,
                 uint32_t size) {

  static const uint8_t kPieces[][3] = {
      {0x90, 0x00, 0x00},
      {0x66, 0x90, 0x00},
      {0x0F, 0x1F, 0x00},
      {0x48, 0x89, 0xC0},
      {0x31, 0xC0, 0x00},
  };

  const size_t n = size;
  std::vector<uint8_t> code;
  while (code.size() < n) {
    const size_t pi = static_cast<size_t>(splitmix64(seed) % 5);
    const size_t len = (pi == 2) ? 3 : (pi == 0 ? 1 : 2);
    for (size_t k = 0; k < len && code.size() < n; ++k) {
      code.push_back(kPieces[pi][k]);
    }
  }
  IslandHeader ih;
  ih.magic = island_magic();
  ih.size = static_cast<uint32_t>(code.size());
  ih.salt = static_cast<uint32_t>(splitmix64(seed));
  ih.flags = 0;
  ih.refs = 0;
  ih.import_index = 0;
  ih.reserved2 = 0;

  island_encrypt(code.data(), ih.size, island_key_for(ih.salt, rva + 32));
  out.insert(out.end(), reinterpret_cast<const uint8_t*>(&ih),
             reinterpret_cast<const uint8_t*>(&ih) + sizeof(ih));
  out.insert(out.end(), code.begin(), code.end());

  const size_t total = sizeof(ih) + code.size();
  const size_t pad = (16 - (total % 16)) % 16;
  for (size_t k = 0; k < pad; ++k) {
    out.push_back(static_cast<uint8_t>(splitmix64(seed)));
  }
}

}

std::vector<IslandPlan> plan_islands(const std::vector<NativeIsland>& islands,
                                     uint32_t first_rva) {
  std::vector<IslandPlan> plan(islands.size());
  if (islands.empty()) return plan;

  uint64_t st = 0x51ED2701B3F4A9C7ull ^ static_cast<uint64_t>(first_rva) ^
                (static_cast<uint64_t>(islands.size()) << 32);

  std::vector<uint32_t> order(islands.size());
  for (size_t i = 0; i < order.size(); ++i) order[i] = static_cast<uint32_t>(i);
  for (size_t i = order.size(); i > 1; --i) {
    const size_t j = static_cast<size_t>(splitmix64(st) % i);
    const uint32_t tmp = order[i - 1];
    order[i - 1] = order[j];
    order[j] = tmp;
  }

  const uint32_t leave_base =
      static_cast<uint32_t>(splitmix64(st) % kIslandLeaveAliasCount);

  for (size_t k = 0; k < order.size(); ++k) {
    const size_t idx = order[k];
    IslandPlan p;
    p.order = static_cast<uint32_t>(k);
    p.pad = static_cast<uint32_t>(splitmix64(st) % (kMaxIslandPad + 1));
    p.junk = static_cast<uint32_t>(splitmix64(st) % (kMaxIslandJunk + 1));

    p.decoy_size = (splitmix64(st) & 1u)
                       ? 0u
                       : (8u + static_cast<uint32_t>(splitmix64(st) % 17u));

    p.leave_sel = static_cast<uint32_t>((leave_base + k) % kIslandLeaveAliasCount);
    plan[idx] = p;
  }

  bool any_decoy = false;
  for (const IslandPlan& p : plan) {
    if (p.decoy_size != 0) { any_decoy = true; break; }
  }
  if (!any_decoy) {
    const size_t r = static_cast<size_t>(splitmix64(st) % plan.size());
    plan[r].decoy_size = 8u + static_cast<uint32_t>(splitmix64(st) % 17u);
  }
  return plan;
}

uint32_t island_stride(const NativeIsland& isl, const IslandPlan& plan) {

  const uint32_t head = isl.tail_call ? kTailHead : 0u;

  const uint32_t mut =
      HYDA_MUT_SLACK + static_cast<uint32_t>(sizeof(IslandMutPlan));
  const uint32_t own =
      align16(kIslandHeaderSize + head +
              static_cast<uint32_t>(isl.bytes.size()) + plan.junk + 5u +
              plan.pad + mut +
              (isl.import_index != 0 ? kIslandSlotSize : 0u));
  const uint32_t decoy =
      plan.decoy_size ? align16(kIslandHeaderSize + plan.decoy_size) : 0u;
  return own + decoy;
}

uint32_t islands_span(const std::vector<NativeIsland>& islands,
                      uint32_t first_rva) {

  const std::vector<IslandPlan> plan = plan_islands(islands, first_rva);
  uint32_t span = kIslandHeaderSize;
  for (size_t i = 0; i < islands.size(); ++i) {
    span += island_stride(islands[i], plan[i]);
  }
  return span;
}

std::vector<PlacedIsland> place_islands(const std::vector<NativeIsland>& islands,
                                        uint32_t first_rva,
                                        const std::vector<uint32_t>& leave_rvas,
                                        uint64_t image_base, std::string* err) {
  std::vector<PlacedIsland> out;
  out.resize(islands.size());
  if (islands.empty()) return out;
  if (leave_rvas.empty()) {
    *err = "gate-leave address not provided";
    return {};
  }

  const std::vector<IslandPlan> plan = plan_islands(islands, first_rva);

  uint32_t cur = first_rva + kIslandHeaderSize;
  for (size_t k = 0; k < islands.size(); ++k) {

    size_t idx = 0;
    for (size_t q = 0; q < islands.size(); ++q) {
      if (plan[q].order == k) { idx = q; break; }
    }
    const NativeIsland& isl = islands[idx];
    const IslandPlan& pl = plan[idx];
    PlacedIsland p;
    p.rva = cur;
    p.bytes.clear();

    const uint32_t head = isl.tail_call ? kTailHead : 0u;
    if (head != 0) {

      const int64_t lea_end = static_cast<int64_t>(p.rva) + 4 + 7;
      const int64_t d = static_cast<int64_t>(leave_rvas[0]) - lea_end;
      if (d < INT32_MIN || d > INT32_MAX) {
        *err = "tail-call exit target out of range (±2 GB)";
        return {};
      }
      const int32_t d32 = static_cast<int32_t>(d);
      uint8_t db[4];
      std::memcpy(db, &d32, 4);
      p.bytes.push_back(0x48);
      p.bytes.push_back(0x83);
      p.bytes.push_back(0xEC);
      p.bytes.push_back(0x08);
      p.bytes.push_back(0x48);
      p.bytes.push_back(0x8D);
      p.bytes.push_back(0x05);
      p.bytes.insert(p.bytes.end(), db, db + 4);
      p.bytes.push_back(0x50);
    }
    p.bytes.insert(p.bytes.end(), isl.bytes.begin(), isl.bytes.end());

    const bool import_ref = (isl.import_index != 0);
    if (isl.disp_off >= 0 && !import_ref) {
      const size_t off = static_cast<size_t>(isl.disp_off) + head;
      if (off + 4 > p.bytes.size()) {
        *err = "island-relative field outside instruction";
        return {};
      }
      const int64_t target_rva = static_cast<int64_t>(isl.disp_target) -
                                 static_cast<int64_t>(image_base);

      const int64_t insn_end = static_cast<int64_t>(p.rva) +
                               static_cast<int64_t>(head) +
                               static_cast<int64_t>(isl.bytes.size());
      const int64_t disp = target_rva - insn_end;
      if (disp < INT32_MIN || disp > INT32_MAX) {
        *err = "island-relative target out of range (±2 GB)";
        return {};
      }
      const int32_t d = static_cast<int32_t>(disp);
      std::memcpy(p.bytes.data() + off, &d, 4);
    }

    for (uint32_t j = 0; j < pl.junk; ++j) p.bytes.push_back(0x90);

    const uint32_t leave_rva = leave_rvas[pl.leave_sel % leave_rvas.size()];
    p.bytes.push_back(0xE9);
    const int64_t next = static_cast<int64_t>(p.rva) +
                         static_cast<int64_t>(p.bytes.size()) + 4;
    const int64_t rel = static_cast<int64_t>(leave_rva) - next;
    if (rel < INT32_MIN || rel > INT32_MAX) {
      *err = "island tail target out of range";
      return {};
    }
    const int32_t r32 = static_cast<int32_t>(rel);
    uint8_t rb[4];
    std::memcpy(rb, &r32, 4);
    p.bytes.insert(p.bytes.end(), rb, rb + 4);

    uint64_t pst = static_cast<uint64_t>(cur) ^
                   (static_cast<uint64_t>(idx) << 32) ^
                   static_cast<uint64_t>(0x8A5E1D3Bull);
    const uint32_t pad_seed = static_cast<uint32_t>(splitmix64(pst));
    const uint32_t dead = pl.pad + HYDA_MUT_SLACK;
    for (uint32_t j = 0; j < dead; ++j) {
      p.bytes.push_back(island_mut_fill(pad_seed, j));
    }

    {
      const uint32_t insn_len = static_cast<uint32_t>(isl.bytes.size());
      if (insn_len == 0u || insn_len > 255u || head > 255u ||
          head + insn_len > 65535u) {
        *err = "island mutation plan: instruction length out of range";
        return {};
      }
      if (isl.disp_off >= 0 && static_cast<uint32_t>(isl.disp_off) + head > 254u) {
        *err = "island mutation plan: relative field offset out of range";
        return {};
      }
      IslandMutPlan mp;
      mp.magic = island_mut_magic();
      mp.version = 1;
      mp.insn_off = static_cast<uint8_t>(head);
      mp.insn_len = static_cast<uint8_t>(insn_len);
      mp.flip = isl.flip_kind;
      mp.flip_off = isl.flip_off;
      mp.disp_off = (isl.disp_off >= 0)
                        ? static_cast<uint8_t>(head + isl.disp_off)
                        : HYDA_MUT_NO_DISP;
      mp.tail_off = static_cast<uint16_t>(head + insn_len + pl.junk);
      mp.pad_seed = pad_seed;
      mp.rsv0 = 0;
      mp.rsv1 = 0;
      const uint8_t* mb = reinterpret_cast<const uint8_t*>(&mp);
      p.bytes.insert(p.bytes.end(), mb, mb + sizeof(mp));
    }

    IslandHeader ih;
    ih.magic = island_magic();
    ih.size = static_cast<uint32_t>(p.bytes.size());
    ih.salt = island_salt_for(static_cast<uint32_t>(idx), cur);
    ih.flags = 0;
    ih.refs = 0;
    ih.import_index = 0;
    ih.reserved2 = 0;
    island_encrypt(p.bytes.data(), ih.size, island_key_for(ih.salt, cur));
    p.header.assign(reinterpret_cast<const uint8_t*>(&ih),
                    reinterpret_cast<const uint8_t*>(&ih) + sizeof(ih));

    if (import_ref) {

      const uint32_t slot_rva = cur + static_cast<uint32_t>(p.bytes.size());

      const size_t off = static_cast<size_t>(isl.disp_off) + head;
      if (off + 4 > p.bytes.size()) {
        *err = "import island: relative field outside instruction";
        return {};
      }
      const int64_t insn_end = static_cast<int64_t>(p.rva) +
                               static_cast<int64_t>(head) +
                               static_cast<int64_t>(isl.bytes.size());
      const int64_t disp = static_cast<int64_t>(slot_rva) - insn_end;
      if (disp < INT32_MIN || disp > INT32_MAX) {
        *err = "import island: hidden slot target out of range (±2 GB)";
        return {};
      }
      const int32_t d = static_cast<int32_t>(disp);

      std::vector<uint8_t> plain = p.bytes;
      island_decrypt(plain.data(), ih.size, island_key_for(ih.salt, cur));
      std::memcpy(plain.data() + off, &d, 4);
      island_encrypt(plain.data(), ih.size, island_key_for(ih.salt, cur));
      p.bytes = plain;

      for (int k = 0; k < 8; ++k) p.bytes.push_back(0);
      ih.import_index = isl.import_index;
      ih.flags |= HYDA_ISLAND_IMPORT;
      p.header.assign(reinterpret_cast<const uint8_t*>(&ih),
                      reinterpret_cast<const uint8_t*>(&ih) + sizeof(ih));
    }

    if (pl.decoy_size > 0) {

      const uint32_t block =
          align16(kIslandHeaderSize + static_cast<uint32_t>(p.bytes.size()));
      const uint32_t decoy_rva = cur - kIslandHeaderSize + block;
      uint64_t dseed = 0x243F6A8885A308D3ull ^
                       (static_cast<uint64_t>(idx) << 32) ^ cur;
      emit_decoy(p.decoy, decoy_rva, dseed, pl.decoy_size);
      p.decoy_rva = decoy_rva;
    }

    cur += island_stride(isl, pl);
    out[idx] = std::move(p);
  }
  return out;
}

}
