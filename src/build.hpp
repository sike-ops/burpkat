#pragma once

#include "elf.hpp"
#include <vector>

namespace build {

// Combine a host (ET_EXEC or PIE) with a PIE payload into a single ET_EXEC.
std::vector<elf::u8> combine(const elf::Image &host,
                             const elf::Image &payload);

} // namespace build
