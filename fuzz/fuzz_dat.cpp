// Fuzz the audit-data container parser (dat_probe / dat_open).
#include <cstddef>
#include <cstdint>
#include <vector>

#include "hyda/codec/datblob.hpp"

namespace {
constexpr uint64_t kKey = 0x1122334455667788ull;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > (1u << 20)) return 0;
  const uint32_t n = static_cast<uint32_t>(size);

  std::vector<uint8_t> buf(data, data + size);
  uint32_t total = 0;
  (void)hyda::dat_probe(buf.data(), n, kKey, &total);

  hyda::DatHeader hdr{};
  if (hyda::dat_open(buf.data(), n, kKey, &hdr)) {
    hyda::dat_close(buf.data(), hdr.total_size, kKey);
  }
  return 0;
}

#include "standalone.hpp"