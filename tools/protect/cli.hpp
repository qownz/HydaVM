#pragma once
// Command-line parsing for hyda_protect.

#include <cstdint>
#include <string>
#include <vector>

namespace hyda::prot {

struct Options {
  enum class Mode { Protect, ListSections, ListHandlers };

  Mode mode = Mode::Protect;
  std::string input;
  std::string output;

  bool do_mutate = true;
  bool do_rebase = false;
  uint64_t rebase_to = 0;

  unsigned hydak_parts = 6;
  unsigned hydak_decoys = 4;
  unsigned hydak_containers = 3;
  bool has_hydak_seed = false;
  uint64_t hydak_seed = 0;

  uint32_t audit_period = 1;
  uint32_t audit_chunks = 1;
  bool has_audit_refs = false;
  uint32_t audit_refs = 0;

  std::string vm_seed;
  std::string dispatch_profile;
  std::vector<std::string> no_crypt;

  bool show_help = false;
  bool show_version = false;
};

// Parses argv into `out`. Returns 0 on success, 2 on a usage error (a message
// has already been printed). Help/version requests are reported via flags.
int parse_options(int argc, char** argv, Options* out);

void print_help(const char* argv0);
void print_version();

}  // namespace hyda::prot