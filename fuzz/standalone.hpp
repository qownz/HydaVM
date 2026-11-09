#pragma once
// Optional driver so a fuzz target can be built and run without libFuzzer:
//   g++ -DHYDA_FUZZ_STANDALONE -fsanitize=address,undefined ...
//   ./fuzz_pe <file>...   (each file is fed to LLVMFuzzerTestOneInput)

#if defined(HYDA_FUZZ_STANDALONE)

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    std::FILE* f = std::fopen(argv[i], "rb");
    if (f == nullptr) continue;
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(n > 0 ? static_cast<size_t>(n) : 0u);
    if (!buf.empty() && std::fread(buf.data(), 1, buf.size(), f) != buf.size()) {
      buf.clear();
    }
    std::fclose(f);
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  return 0;
}

#endif