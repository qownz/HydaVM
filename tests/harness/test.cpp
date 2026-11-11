#include "harness/test.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace hyda::test {
namespace {

struct Options {
  bool list = false;
  bool quiet = false;
  bool verbose = false;
  const char* filter = nullptr;
  int repeat = 1;
};

bool matches(const char* filter, const char* suite, const char* name) {
  if (filter == nullptr || *filter == '\0') return true;
  const size_t n = std::strlen(filter);
  const std::string full = std::string(suite) + "." + name;
  return full.compare(0, n, filter) == 0 || std::strncmp(filter, suite, n) == 0 ||
         std::strstr(name, filter) != nullptr ||
         std::strstr(suite, filter) != nullptr;
}

Options parse(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    const char* a = argv[i];
    if (std::strcmp(a, "--list") == 0) {
      o.list = true;
    } else if (std::strcmp(a, "--quiet") == 0) {
      o.quiet = true;
    } else if (std::strcmp(a, "--verbose") == 0) {
      o.verbose = true;
    } else if (std::strncmp(a, "--filter=", 9) == 0) {
      o.filter = a + 9;
    } else if (std::strncmp(a, "--repeat=", 9) == 0) {
      o.repeat = std::atoi(a + 9);
      if (o.repeat < 1) o.repeat = 1;
    }
  }
  return o;
}

}  // namespace

void Reporter::check(bool ok, const char* what, const char* file, int line) {
  check(ok, std::string(what == nullptr ? "" : what), file, line);
}

void Reporter::check(bool ok, const std::string& what, const char* file, int line) {
  ++checks_;
  if (ok) return;
  ++fails_;
  std::printf("    %s:%d: %s\n", file, line, what.c_str());
}

void Reporter::eq_hex(uint64_t a, uint64_t b, const char* what, const char* file,
                      int line) {
  if (a == b) {
    check(true, what, file, line);
    return;
  }
  char buf[160];
  std::snprintf(buf, sizeof(buf), "%s (got %#llx, want %#llx)", what,
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b));
  check(false, buf, file, line);
}

Registry& Registry::instance() {
  static Registry r;
  return r;
}

void Registry::add(std::unique_ptr<Test> test) { tests_.push_back(std::move(test)); }

int Registry::run(int argc, char** argv) {
  const Options opt = parse(argc, argv);

  if (opt.list) {
    for (const std::unique_ptr<Test>& t : tests_) {
      std::printf("%-10s %-22s %s\n", t->suite(), t->name(), t->desc());
    }
    return 0;
  }

  int total_checks = 0;
  int total_fails = 0;
  int run = 0;
  int failed = 0;

  for (int rep = 0; rep < opt.repeat; ++rep) {
    for (const std::unique_ptr<Test>& t : tests_) {
      if (!matches(opt.filter, t->suite(), t->name())) continue;

      Reporter r;
      const auto t0 = std::chrono::steady_clock::now();
      t->run(r);
      const auto t1 = std::chrono::steady_clock::now();
      const long long ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

      ++run;
      total_checks += r.checks();
      total_fails += r.failures();
      if (r.failures() != 0) ++failed;

      std::printf("%s %-10s %-22s %4lld ms %5d checks\n",
                  r.failures() == 0 ? "ok  " : "FAIL", t->suite(), t->name(), ms,
                  r.checks());
      if (opt.verbose) std::printf("     %s\n", t->desc());
    }
  }

  std::printf("\n%d tests, %d checks, %d failed\n", run, total_checks, total_fails);
  return failed == 0 ? 0 : 1;
}

}  // namespace hyda::test