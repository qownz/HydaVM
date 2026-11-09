#include "hyda/vm/fpstate.hpp"
#include "hyda/core/thread.hpp"

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#endif

namespace hyda {
namespace {
alignas(64) HydaFpState g_fp[kMaxThreads];
}

HydaFpState* fp_state() {
  unsigned i = thread_index();
  if (i >= kMaxThreads) i = 0;
  return &g_fp[i];
}

bool fp_supports_avx() {
#if defined(__x86_64__) || defined(_M_X64)
  unsigned a = 0, b = 0, c = 0, d = 0;
  if (!__get_cpuid(1, &a, &b, &c, &d)) return false;
  const bool xsave = (c & (1u << 26)) != 0;
  const bool osxsave = (c & (1u << 27)) != 0;
  const bool avx = (c & (1u << 28)) != 0;
  if (!xsave || !osxsave || !avx) return false;
  unsigned lo = 0, hi = 0;
  __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
  return (lo & 0x6u) == 0x6u;
#else
  return false;
#endif
}

}
