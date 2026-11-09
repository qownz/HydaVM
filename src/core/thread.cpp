#include "hyda/core/thread.hpp"

#include <atomic>

namespace hyda {
namespace {

struct ThreadSlot {
  uint64_t key;
};
ThreadSlot g_slots[kMaxThreads];
std::atomic<uint32_t> g_lock{0};

void spin_pause() {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#endif
}

}

uint64_t thread_key() {
#if defined(_WIN32)
  uint64_t k = 0;
  __asm__ volatile("movq %%gs:0x30, %0" : "=r"(k));
  return k;
#else
  return reinterpret_cast<uint64_t>(__builtin_thread_pointer());
#endif
}

unsigned thread_index() {
  const uint64_t key = thread_key();
  if (key == 0) return kThreadIndexNone;
  for (unsigned i = 0; i < kMaxThreads; ++i) {
    if (g_slots[i].key == key) return i;
  }
  while (g_lock.exchange(1, std::memory_order_acquire) != 0) spin_pause();
  unsigned idx = kThreadIndexNone;
  for (unsigned i = 0; i < kMaxThreads; ++i) {
    if (g_slots[i].key == key) {
      idx = i;
      break;
    }
  }
  if (idx == kThreadIndexNone) {
    for (unsigned i = 0; i < kMaxThreads; ++i) {
      if (g_slots[i].key != 0) continue;
      g_slots[i].key = key;
      idx = i;
      break;
    }
  }
  g_lock.store(0, std::memory_order_release);
  return idx;
}

}
