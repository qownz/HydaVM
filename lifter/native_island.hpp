#pragma once

#include "hyda/ir/ir.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace hyda {

struct PlacedIsland {
  uint32_t rva = 0;
  std::vector<uint8_t> bytes;

  std::vector<uint8_t> header;

  uint32_t decoy_rva = 0;
  std::vector<uint8_t> decoy;
};

struct IslandPlan {
  uint32_t order = 0;
  uint32_t pad = 0;
  uint32_t decoy_size = 0;

  uint32_t junk = 0;
  uint32_t leave_sel = 0;
};

std::vector<IslandPlan> plan_islands(const std::vector<NativeIsland>& islands,
                                     uint32_t first_rva);

uint32_t island_stride(const NativeIsland& isl, const IslandPlan& plan);

uint32_t islands_span(const std::vector<NativeIsland>& islands,
                      uint32_t first_rva);

std::vector<PlacedIsland> place_islands(const std::vector<NativeIsland>& islands,
                                        uint32_t first_rva,
                                        const std::vector<uint32_t>& leave_rvas,
                                        uint64_t image_base, std::string* err);

}
