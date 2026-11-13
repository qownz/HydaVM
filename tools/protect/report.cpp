#include "report.hpp"

#include <cstdio>
#include <string>

namespace hyda::prot {
namespace {

std::string quote(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c & 0xFF);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  out += '"';
  return out;
}

std::string hex(uint64_t v) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "\"0x%llx\"", static_cast<unsigned long long>(v));
  return buf;
}

}  // namespace

bool write_report(const Report& r, const std::string& path, std::string* err) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) {
    if (err != nullptr) *err = "cannot write " + path;
    return false;
  }

  std::fprintf(f, "{\n");
  std::fprintf(f, "  \"tool\": \"hyda_protect\",\n");
  std::fprintf(f, "  \"input\": %s,\n", quote(r.input).c_str());
  std::fprintf(f, "  \"output\": %s,\n", quote(r.output).c_str());
  std::fprintf(f, "  \"dry_run\": %s,\n", r.dry_run ? "true" : "false");
  std::fprintf(f, "  \"strict\": %s,\n", r.strict ? "true" : "false");
  std::fprintf(f, "  \"image_base\": %s,\n", hex(r.image_base).c_str());
  std::fprintf(f, "  \"vm_seed\": %s,\n", hex(r.vm_seed).c_str());
  std::fprintf(f, "  \"hydak_seed\": %s,\n", hex(r.hydak_seed).c_str());
  std::fprintf(f,
               "  \"dispatch_profile\": {\"mask\": %u, \"key\": %u, \"base\": %u, "
               "\"shift\": %u, \"call\": %u, \"crypt\": %u},\n",
               r.prof_mask, r.prof_key, r.prof_base, r.prof_shift, r.prof_call,
               r.prof_crypt);
  std::fprintf(f, "  \"identities\": %u,\n", r.identities);

  std::fprintf(f, "  \"functions\": [\n");
  for (size_t i = 0; i < r.functions.size(); ++i) {
    const ReportFn& fn = r.functions[i];
    std::fprintf(f,
                 "    {\"name\": %s, \"rva\": %s, \"x86_bytes\": %u, "
                 "\"bytecode_bytes\": %u, \"islands\": %u, \"fused\": %u, "
                 "\"variants\": %u, \"dead_flags\": %u, \"opcodes\": %u, "
                 "\"encrypted\": %s}%s\n",
                 quote(fn.name).c_str(), hex(fn.rva).c_str(), fn.x86_bytes,
                 fn.bytecode_bytes, fn.islands, fn.fused, fn.variants,
                 fn.dead_flags, fn.opcodes, fn.encrypted ? "true" : "false",
                 i + 1 == r.functions.size() ? "" : ",");
  }
  std::fprintf(f, "  ],\n");

  std::fprintf(f, "  \"skipped\": [\n");
  for (size_t i = 0; i < r.skipped.size(); ++i) {
    std::fprintf(f, "    {\"name\": %s, \"reason\": %s}%s\n",
                 quote(r.skipped[i].name).c_str(),
                 quote(r.skipped[i].reason).c_str(),
                 i + 1 == r.skipped.size() ? "" : ",");
  }
  std::fprintf(f, "  ],\n");

  uint64_t x86_total = 0;
  uint64_t bc_total = 0;
  uint64_t island_total = 0;
  for (const ReportFn& fn : r.functions) {
    x86_total += fn.x86_bytes;
    bc_total += fn.bytecode_bytes;
    island_total += fn.islands;
  }
  std::fprintf(f,
               "  \"totals\": {\"protected\": %zu, \"skipped\": %zu, "
               "\"x86_bytes\": %llu, \"bytecode_bytes\": %llu, \"islands\": %llu}\n",
               r.functions.size(), r.skipped.size(),
               static_cast<unsigned long long>(x86_total),
               static_cast<unsigned long long>(bc_total),
               static_cast<unsigned long long>(island_total));
  std::fprintf(f, "}\n");

  const bool ok = std::ferror(f) == 0;
  if (std::fclose(f) != 0 || !ok) {
    if (err != nullptr) *err = "short write to " + path;
    return false;
  }
  return true;
}

}  // namespace hyda::prot