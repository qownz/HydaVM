// Fuzz the per-function blob header validation.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "hyda/codec/blob.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < sizeof(hyda::BlobHeader)) return 0;
  hyda::BlobHeader h;
  std::memcpy(&h, data, sizeof(h));
  (void)hyda::blob_header_check(h);
  return 0;
}

#include "standalone.hpp"