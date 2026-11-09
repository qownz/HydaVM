// Fuzz the protector's PE reader. The protector parses untrusted input files,
// so malformed PEs must not read out of bounds.
#include <cstddef>
#include <cstdint>
#include <string>

#include "pe.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > (1u << 24)) return 0;  // keep a single run bounded (16 MB)

  hyda::prot::PeFile pe;
  pe.data.assign(data, data + size);

  std::string err;
  if (!pe.parse(&err)) return 0;

  const uint32_t dirs = pe.num_dirs < 16u ? pe.num_dirs : 16u;
  for (uint32_t i = 0; i < dirs; ++i) {
    (void)pe.dir_rva(i);
    (void)pe.dir_size(i);
  }
  for (const hyda::prot::Section& s : pe.sections) {
    (void)pe.rva_to_off(s.virt_addr);
  }
  (void)pe.parse_imports(&err);
  (void)pe.find_export("hyda_vm_dispatch", &err);
  return 0;
}

#include "standalone.hpp"