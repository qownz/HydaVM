#pragma once
// Minimal PE32+ reader used by the protector.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "common.hpp"

namespace hyda::prot {

struct Section {
  std::string name;
  uint32_t virt_size = 0;
  uint32_t virt_addr = 0;
  uint32_t raw_size = 0;
  uint32_t raw_addr = 0;
  uint32_t characteristics = 0;
};

struct ImportInfo {
  uint32_t iat_rva = 0;
  std::string dll;
  std::string func;
  uint16_t ordinal = 0;
  bool by_ordinal = false;
  int64_t first_thunk_off = -1;
  int64_t int_off = -1;
  int64_t name_off = -1;
  int64_t dll_name_off = -1;
  int64_t dll_name_len = 0;
  int64_t thunk_off = -1;
};

struct PeFile {
  std::vector<uint8_t> data;
  uint32_t pe_off = 0;
  uint32_t cof_off = 0;
  uint32_t opt_off = 0;
  uint32_t sect_off = 0;
  uint16_t num_sections = 0;
  uint16_t opt_size = 0;
  uint32_t ptr_symtab = 0;
  uint32_t num_symbols = 0;
  uint64_t image_base = 0;
  uint32_t section_align = 0;
  uint32_t file_align = 0;
  uint32_t size_of_image = 0;
  uint32_t size_of_headers = 0;
  uint32_t num_dirs = 0;
  uint32_t export_rva = 0, export_size = 0;
  std::vector<Section> sections;

  std::string resolve_name(const uint8_t* raw8) const {
    char buf[9];
    std::memcpy(buf, raw8, 8);
    buf[8] = 0;
    if (buf[0] != '/') return std::string(buf);
    const uint32_t off = static_cast<uint32_t>(std::strtoul(buf + 1, nullptr, 10));
    const uint64_t at = static_cast<uint64_t>(ptr_symtab) + num_symbols * 18ull + off;
    if (at >= data.size()) return std::string(buf);
    return std::string(reinterpret_cast<const char*>(&data[at]));
  }

  bool parse(std::string* err) {
    if (data.size() < 0x40) { *err = "file too small"; return false; }
    if (data[0] != 'M' || data[1] != 'Z') { *err = "missing MZ signature"; return false; }
    pe_off = rd32(&data[0x3C]);
    if (pe_off + 24 > data.size()) { *err = "invalid PE offset"; return false; }
    if (data[pe_off] != 'P' || data[pe_off + 1] != 'E' || data[pe_off + 2] != 0) {
      *err = "missing PE signature";
      return false;
    }
    cof_off = pe_off + 4;
    num_sections = rd16(&data[cof_off + 2]);
    ptr_symtab = rd32(&data[cof_off + 8]);
    num_symbols = rd32(&data[cof_off + 12]);
    opt_size = rd16(&data[cof_off + 16]);
    opt_off = cof_off + 20;
    sect_off = opt_off + opt_size;

    const uint16_t magic = rd16(&data[opt_off]);
    if (magic != 0x20B) { *err = "only PE32+ (x86-64) is supported"; return false; }

    image_base = rd64(&data[opt_off + 24]);
    section_align = rd32(&data[opt_off + 32]);
    file_align = rd32(&data[opt_off + 36]);
    size_of_image = rd32(&data[opt_off + 56]);
    size_of_headers = rd32(&data[opt_off + 60]);
    num_dirs = rd32(&data[opt_off + 108]);
    if (num_dirs > 0) {
      export_rva = rd32(&data[opt_off + 112]);
      export_size = rd32(&data[opt_off + 116]);
    }

    if (sect_off + static_cast<uint32_t>(num_sections) * 40 > data.size()) {
      *err = "section table outside file";
      return false;
    }
    sections.clear();
    for (uint16_t i = 0; i < num_sections; ++i) {
      const uint8_t* s = &data[sect_off + static_cast<uint32_t>(i) * 40];
      Section sec;
      sec.name = resolve_name(s);
      sec.virt_size = rd32(s + 8);
      sec.virt_addr = rd32(s + 12);
      sec.raw_size = rd32(s + 16);
      sec.raw_addr = rd32(s + 20);
      sec.characteristics = rd32(s + 36);
      sections.push_back(sec);
    }
    return true;
  }

  int rva_to_section(uint32_t rva) const {
    for (size_t i = 0; i < sections.size(); ++i) {
      const Section& s = sections[i];
      const uint32_t sz = s.virt_size ? s.virt_size : s.raw_size;
      if (rva >= s.virt_addr && rva < s.virt_addr + sz) return static_cast<int>(i);
    }
    return -1;
  }

  int64_t rva_to_off(uint32_t rva) const {
    const int i = rva_to_section(rva);
    if (i < 0) return -1;
    const Section& s = sections[i];
    const int64_t off = static_cast<int64_t>(rva - s.virt_addr) + s.raw_addr;
    if (off < 0 || static_cast<size_t>(off) >= data.size()) return -1;
    return off;
  }

  uint32_t dir_rva(unsigned i) const {
    if (i >= num_dirs) return 0;
    return rd32(&data[opt_off + 112 + i * 8]);
  }
  uint32_t dir_size(unsigned i) const {
    if (i >= num_dirs) return 0;
    return rd32(&data[opt_off + 112 + i * 8 + 4]);
  }

  std::vector<ImportInfo> parse_imports(std::string* err) const {
    std::vector<ImportInfo> out;
    const uint32_t imp_rva = dir_rva(1);
    if (imp_rva == 0) { *err = "no import directory"; return out; }
    const int64_t imp_off = rva_to_off(imp_rva);
    if (imp_off < 0) { *err = "cannot parse import directory"; return out; }
    for (uint32_t d = 0;; ++d) {
      const int64_t desc = imp_off + static_cast<int64_t>(d) * 20;
      if (desc + 20 > static_cast<int64_t>(data.size())) break;
      const uint32_t oft = rd32(&data[desc + 0]);
      const uint32_t name_rva = rd32(&data[desc + 12]);
      const uint32_t ft = rd32(&data[desc + 16]);
      if (oft == 0 && name_rva == 0 && ft == 0) break;
      if (name_rva == 0 || ft == 0) continue;
      const int64_t noff = rva_to_off(name_rva);
      std::string dll;
      size_t dll_len = 0;
      if (noff >= 0) {
        const char* s = reinterpret_cast<const char*>(&data[noff]);
        size_t len = 0;
        while (len < 128 && s[len] != '\0') ++len;
        dll.assign(s, len);
        dll_len = len + 1;
      }
      if (dll.empty()) continue;
      const int64_t ftoff = rva_to_off(ft);
      if (ftoff < 0) continue;
      for (uint32_t t = 0;; ++t) {
        const int64_t e = ftoff + static_cast<int64_t>(t) * 8;
        if (e + 8 > static_cast<int64_t>(data.size())) break;
        const uint64_t thunk = rd64(&data[e]);
        if (thunk == 0) break;
        ImportInfo info;
        info.iat_rva = ft + t * 8u;
        info.dll = dll;
        info.first_thunk_off = e;
        info.dll_name_off = noff;
        info.dll_name_len = static_cast<int64_t>(dll_len);
        info.thunk_off = e;
        if (oft != 0) {
          const int64_t io = rva_to_off(oft + t * 8u);
          if (io >= 0 && io + 8 <= static_cast<int64_t>(data.size())) {
            info.int_off = io;
          }
        }
        if (thunk & 0x8000000000000000ull) {
          info.by_ordinal = true;
          info.ordinal = static_cast<uint16_t>(thunk & 0xFFFFu);
        } else {

          uint32_t fname_rva = static_cast<uint32_t>(thunk);
          if (info.int_off >= 0) {
            const uint64_t v = rd64(&data[info.int_off]);
            if (v != 0 && (v & 0x8000000000000000ull) == 0) {
              fname_rva = static_cast<uint32_t>(v);
            }
          }
          const int64_t hn = rva_to_off(fname_rva);
          if (hn < 0 || hn + 2 >= static_cast<int64_t>(data.size())) continue;
          info.name_off = hn;
          const char* s = reinterpret_cast<const char*>(&data[hn + 2]);
          size_t len = 0;
          while (len < 256 && s[len] != '\0') ++len;
          if (len == 0) continue;
          info.func.assign(s, len);
        }
        out.push_back(info);
      }
    }
    return out;
  }

  uint32_t find_export(const char* name, std::string* err) const {
    if (export_rva == 0) { *err = "no export directory"; return 0; }
    const int64_t d = rva_to_off(export_rva);
    if (d < 0) { *err = "cannot parse export directory"; return 0; }
    const uint8_t* dir = &data[d];
    const uint32_t num_names = rd32(dir + 24);
    const uint32_t eat_rva = rd32(dir + 28);
    const uint32_t names_rva = rd32(dir + 32);
    const uint32_t ords_rva = rd32(dir + 36);
    const int64_t eat = rva_to_off(eat_rva);
    const int64_t names = rva_to_off(names_rva);
    const int64_t ords = rva_to_off(ords_rva);
    if (eat < 0 || names < 0 || ords < 0) { *err = "cannot parse export tables"; return 0; }

    for (uint32_t i = 0; i < num_names; ++i) {
      const uint32_t nrva = rd32(&data[names + i * 4]);
      const int64_t noff = rva_to_off(nrva);
      if (noff < 0) continue;
      if (std::strcmp(reinterpret_cast<const char*>(&data[noff]), name) != 0) continue;
      const uint16_t ord = rd16(&data[ords + i * 2]);
      return rd32(&data[eat + static_cast<uint32_t>(ord) * 4]);
    }
    *err = std::string("export not found: ") + name;
    return 0;
  }
};

}  // namespace hyda::prot
