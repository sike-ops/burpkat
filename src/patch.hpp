#pragma once

#include "elf.hpp"
#include <vector>

namespace patch {

using elf::u64;

// Recompute the SHA1 build-id note in `out` for the host image.
void build_id(std::vector<elf::u8> &out, const elf::Image &host);

// Patch the host .dynamic in place to point at the merged tables.
void dynamic(std::vector<elf::u8> &out, const elf::Image &host, u64 dynsym_va,
             u64 dynstr_va, u64 versym_va, u64 gnuhash_va, u64 rela_va,
             u64 rela_size, u64 jmprel_va, u64 pltrelsz, u64 str_size);

} // namespace patch
