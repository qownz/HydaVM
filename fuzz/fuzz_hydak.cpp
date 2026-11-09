// Fuzz the shard-container parser (hydak_open + catalog + scan).
// key = 0 disables the XOR layer so the raw structure is reachable.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "hyda/codec/hydak.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > (1u << 20)) return 0;
  const uint32_t n = static_cast<uint32_t>(size);

  std::vector<uint8_t> buf(data, data + size);
  hyda::HydakView view{};
  uint32_t err = 0;
  if (hyda::hydak_open(buf.data(), n, 0, &view, &err)) {
    hyda::HydakCatalog cat;
    (void)hyda::hydak_catalog_add(&cat, view, &err);
    (void)hyda::hydak_catalog_finish(&cat, &err);
  }

  uint32_t total = 0;
  (void)hyda::hydak_probe(data, n, 0, &total);

  hyda::HandlerShardDesc descs[hyda::HYDA_HYDAK_MAX_PARTS];
  (void)hyda::hydak_scan_parts(data, n, 0x1000, descs,
                               hyda::HYDA_HYDAK_MAX_PARTS, &err);
  return 0;
}

#include "standalone.hpp"