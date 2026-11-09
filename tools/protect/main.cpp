#include "cli.hpp"
#include "protector.hpp"

int main(int argc, char** argv) {
  using namespace hyda::prot;

  Options opt;
  const int rc = parse_options(argc, argv, &opt);
  if (rc != 0) return rc;
  if (opt.show_help) {
    print_help(argv[0]);
    return 0;
  }
  if (opt.show_version) {
    print_version();
    return 0;
  }

  Protector protector;
  return protector.run(opt);
}