#pragma once

#include <cstdint>

namespace hyda {

constexpr unsigned kMaxThreads = 64;
constexpr unsigned kThreadIndexNone = 0xFFFFu;

uint64_t thread_key();
unsigned thread_index();

}
