#pragma once

#include "elf.hpp"
#include <vector>

namespace build {

// Combine a host ET_EXEC with a PIE payload into a single ET_EXEC image.
std::vector<elf::u8> combine(const elf::Image &host,
                             const elf::Image &payload);

} // namespace build
