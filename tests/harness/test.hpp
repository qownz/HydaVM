#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hyda::test {

class Reporter {
 public:
  void check(bool ok, const char* what, const char* file, int line);
  void check(bool ok, const std::string& what, const char* file, int line);

  template <class A, class B>
  void eq(const A& a, const B& b, const char* what, const char* file, int line) {
    if (a == b) {
      check(true, what, file, line);
      return;
    }
    check(false, std::string(what) + " (" + std::to_string(a) + " != " +
                     std::to_string(b) + ")",
          file, line);
  }

  void eq_hex(uint64_t a, uint64_t b, const char* what, const char* file, int line);

  int checks() const { return checks_; }
  int failures() const { return fails_; }
  void reset() {
    checks_ = 0;
    fails_ = 0;
  }

 private:
  int checks_ = 0;
  int fails_ = 0;
};

class Test {
 public:
  virtual ~Test() = default;
  virtual const char* suite() const = 0;
  virtual const char* name() const = 0;
  virtual const char* desc() const = 0;
  virtual void run(Reporter& r) = 0;
};

class Registry {
 public:
  static Registry& instance();
  void add(std::unique_ptr<Test> test);
  int run(int argc, char** argv);

 private:
  std::vector<std::unique_ptr<Test>> tests_;
};

struct Registrar {
  Registrar(std::unique_ptr<Test> test) { Registry::instance().add(std::move(test)); }
};

}  // namespace hyda::test

#define HYDA_CHECK(REP, COND) \
  (REP).check(static_cast<bool>(COND), #COND, __FILE__, __LINE__)
#define HYDA_CHECK_MSG(REP, COND, MSG) (REP).check(static_cast<bool>(COND), (MSG), __FILE__, __LINE__)
#define HYDA_EQ(REP, A, B) (REP).eq((A), (B), #A " == " #B, __FILE__, __LINE__)

#define HYDA_TEST_STR2(X) #X
#define HYDA_TEST_STR(X) HYDA_TEST_STR2(X)

#define HYDA_TEST(SUITE_NAME, CLASS_NAME, DESC)                   \
  class CLASS_NAME : public ::hyda::test::Test {                  \
   public:                                                        \
    const char* suite() const override { return HYDA_TEST_STR(SUITE_NAME); } \
    const char* name() const override { return #CLASS_NAME; }     \
    const char* desc() const override { return DESC; }            \
    void run(::hyda::test::Reporter& r) override;                 \
  };                                                              \
  static ::hyda::test::Registrar g_reg_##CLASS_NAME(              \
      std::make_unique<CLASS_NAME>());                            \
  void CLASS_NAME::run(::hyda::test::Reporter& r)
