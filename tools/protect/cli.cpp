#include "cli.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "hyda/codec/hydak.hpp"
#include "hyda/guard/audit.hpp"

namespace hyda::prot {
namespace {

bool is(const char* a, const char* b) { return std::strcmp(a, b) == 0; }

unsigned parse_u(const char* s, bool* ok) {
  char* end = nullptr;
  const unsigned long v = std::strtoul(s, &end, 0);
  *ok = (end != nullptr && *end == '\0');
  return static_cast<unsigned>(v);
}

uint64_t parse_u64(const char* s, bool* ok) {
  char* end = nullptr;
  const unsigned long long v = std::strtoull(s, &end, 0);
  *ok = (end != nullptr && *end == '\0');
  return static_cast<uint64_t>(v);
}

const char* kPosUsage =
    "error: expected an input file%s\n"
    "       run '%s --help' for usage\n";

}  // namespace

int parse_options(int argc, char** argv, Options* out) {
  *out = Options{};
  if (argc <= 1) {
    out->show_help = true;
    return 0;
  }

  // Optional subcommand. Falls back to the legacy "hyda_protect in out" form.
  int i = 1;
  const char* first = argv[1];
  if (is(first, "help")) {
    out->show_help = true;
    return 0;
  }
  if (is(first, "version")) {
    out->show_version = true;
    return 0;
  }
  if (is(first, "protect")) {
    out->mode = Options::Mode::Protect;
    i = 2;
  } else if (is(first, "list")) {
    out->mode = Options::Mode::ListSections;
    i = 2;
  } else if (is(first, "inspect") || is(first, "list-handlers")) {
    out->mode = Options::Mode::ListHandlers;
    i = 2;
  }

  std::vector<std::string> pos;
  bool end_of_options = false;
  for (; i < argc; ++i) {
    const char* a = argv[i];

    if (!end_of_options && is(a, "--")) {
      end_of_options = true;
      continue;
    }

    if (!end_of_options && a[0] == '-' && a[1] != '\0') {
      auto value = [&](const char* name) -> const char* {
        if (i + 1 >= argc) {
          std::printf("error: %s requires a value\n", name);
          return nullptr;
        }
        return argv[++i];
      };

      if (is(a, "--help") || is(a, "-h")) { out->show_help = true; return 0; }
      if (is(a, "--version") || is(a, "-V")) { out->show_version = true; return 0; }
      if (is(a, "--list")) { out->mode = Options::Mode::ListSections; continue; }
      if (is(a, "--list-handlers")) {
        out->mode = Options::Mode::ListHandlers;
        continue;
      }
      if (is(a, "--no-mutate")) { out->do_mutate = false; continue; }
      if (is(a, "--strict")) { out->strict = true; continue; }
      if (is(a, "--dry-run")) { out->dry_run = true; continue; }

      bool ok = false;
      if (is(a, "--report")) {
        const char* v = value(a); if (!v) return 2;
        out->report_path = v;
        continue;
      }
      if (is(a, "--vm-seed")) {
        const char* v = value(a); if (!v) return 2;
        out->vm_seed = v;
        continue;
      }
      if (is(a, "--dispatch-profile")) {
        const char* v = value(a); if (!v) return 2;
        out->dispatch_profile = v;
        continue;
      }
      if (is(a, "--no-crypt")) {
        const char* v = value(a); if (!v) return 2;
        out->no_crypt.emplace_back(v);
        continue;
      }
      if (is(a, "--rebase")) {
        const char* v = value(a); if (!v) return 2;
        out->rebase_to = parse_u64(v, &ok);
        if (!ok) { std::printf("error: invalid --rebase value\n"); return 2; }
        out->do_rebase = true;
        continue;
      }
      if (is(a, "--hydak-seed")) {
        const char* v = value(a); if (!v) return 2;
        out->hydak_seed = parse_u64(v, &ok);
        if (!ok) { std::printf("error: invalid --hydak-seed value\n"); return 2; }
        out->has_hydak_seed = true;
        continue;
      }
      if (is(a, "--hydak-parts") || is(a, "--hydak-shards")) {
        const char* v = value(a); if (!v) return 2;
        unsigned n = parse_u(v, &ok);
        if (!ok || n < 1) { std::printf("error: --hydak-parts must be >= 1\n"); return 2; }
        if (n > hyda::HYDA_HYDAK_MAX_PARTS) n = hyda::HYDA_HYDAK_MAX_PARTS;
        out->hydak_parts = n;
        continue;
      }
      if (is(a, "--hydak-decoys")) {
        const char* v = value(a); if (!v) return 2;
        out->hydak_decoys = parse_u(v, &ok);
        if (!ok) { std::printf("error: invalid --hydak-decoys value\n"); return 2; }
        continue;
      }
      if (is(a, "--hydak-containers")) {
        const char* v = value(a); if (!v) return 2;
        unsigned n = parse_u(v, &ok);
        if (!ok || n < 1) { std::printf("error: --hydak-containers must be >= 1\n"); return 2; }
        out->hydak_containers = n;
        continue;
      }
      if (is(a, "--audit-period")) {
        const char* v = value(a); if (!v) return 2;
        out->audit_period = parse_u(v, &ok);
        if (!ok || out->audit_period < 1 ||
            out->audit_period > hyda::HYDA_AUDIT_PERIOD_MAX) {
          std::printf("error: --audit-period must be 1..%u\n",
                      hyda::HYDA_AUDIT_PERIOD_MAX);
          return 2;
        }
        continue;
      }
      if (is(a, "--audit-chunks")) {
        const char* v = value(a); if (!v) return 2;
        out->audit_chunks = parse_u(v, &ok);
        if (!ok || out->audit_chunks < 1 ||
            out->audit_chunks > hyda::HYDA_AUDIT_CHUNKS_MAX) {
          std::printf("error: --audit-chunks must be 1..%u\n",
                      hyda::HYDA_AUDIT_CHUNKS_MAX);
          return 2;
        }
        continue;
      }
      if (is(a, "--audit-refs")) {
        const char* v = value(a); if (!v) return 2;
        out->audit_refs = parse_u(v, &ok);
        if (!ok || out->audit_refs > hyda::HYDA_AUDIT_REFS_MAX) {
          std::printf("error: --audit-refs must be 0..%u\n",
                      hyda::HYDA_AUDIT_REFS_MAX);
          return 2;
        }
        out->has_audit_refs = true;
        continue;
      }

      std::printf("error: unknown option '%s'\n"
                  "       run '%s --help' for usage\n", a, argv[0]);
      return 2;
    }

    pos.emplace_back(a);
  }

  if (out->mode == Options::Mode::Protect) {
    if (out->dry_run && pos.size() == 1) {
      out->input = pos[0];
      return 0;
    }
    if (pos.size() != 2) {
      std::printf(kPosUsage, " and an output file", argv[0]);
      return 2;
    }
    out->input = pos[0];
    out->output = pos[1];
  } else {
    if (pos.size() != 1) {
      std::printf(kPosUsage, "", argv[0]);
      return 2;
    }
    out->input = pos[0];
  }
  return 0;
}

void print_version() {
  std::printf("hyda_protect (HydaVM) - x86-64 VM-based code protector\n");
}

void print_help(const char* argv0) {
  std::printf(
      "HydaVM protector\n"
      "\n"
      "Usage:\n"
      "  %s <input.exe> <output.exe> [options]   protect a PE file\n"
      "  %s list <input.exe>                     list sections\n"
      "  %s inspect <input.exe>                  list handler bodies\n"
      "  %s help                                 show this help\n"
      "\n"
      "Aliases: 'list' = --list, 'inspect' = --list-handlers.\n"
      "\n"
      "General options:\n"
      "  -h, --help              show this help\n"
      "  -V, --version           show version\n"
      "  --vm-seed <hex>         VM seed (random when omitted)\n"
      "  --rebase <hex>          output image base (64K aligned)\n"
      "  --no-mutate             disable the mutation engine (debug)\n"
      "  --strict                fail on the first unprotected function\n"
      "  --dry-run               analyze and report without writing output\n"
      "  --report <file>         write a JSON protection report\n"
      "  --no-crypt <fn>         disable operand encryption for one blob\n"
      "\n"
      "Handler sharding:\n"
      "  --hydak-parts <n>       number of handler parts (default 6)\n"
      "  --hydak-decoys <n>      number of decoy blocks (default 4)\n"
      "  --hydak-containers <n>  data sections for parts (default 3)\n"
      "  --hydak-seed <hex>      fixed layout seed (random when omitted)\n"
      "\n"
      "Integrity / audit:\n"
      "  --audit-period <n>      audit every N VM calls (1..%u)\n"
      "  --audit-chunks <n>      parts per audit (1..%u)\n"
      "  --audit-refs <n>        IAT slots per audit (0..%u)\n"
      "  --dispatch-profile <m,k,b,s,c,x>\n"
      "                          fixed dispatch profile (hex); call and crypt\n"
      "                          are defaults for blobs without an identity\n"
      "\n"
      "Examples:\n"
      "  %s app.exe app_protected.exe --vm-seed 0x1122334455667788\n"
      "  %s list app.exe\n"
      "  %s inspect app.exe\n"
      "  %s app.exe out.exe --report out.json\n"
      "  %s app.exe --dry-run --report out.json\n",
      argv0, argv0, argv0, argv0,
      hyda::HYDA_AUDIT_PERIOD_MAX, hyda::HYDA_AUDIT_CHUNKS_MAX,
      hyda::HYDA_AUDIT_REFS_MAX, argv0, argv0, argv0, argv0, argv0);
}

}  // namespace hyda::prot