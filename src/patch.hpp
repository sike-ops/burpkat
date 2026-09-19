#pragma once

#include "elf.hpp"
#include <vector>

namespace patch {

using elf::u64;

// Recompute the SHA1 build-id note in `out` for the host image.
void build_id(std::vector<elf::u8> &out, const elf::Image &host);

// Build the output's merged .dynamic table from the host's, rewriting the
// pointer tags to the merged tables and adding eager-binding flags plus the
// DT_NEEDED entries named by `needed_offsets` (offsets into the merged
// `.dynstr`). The table is relocated into the tool's extra segment, so the
// caller must repoint PT_DYNAMIC (and the `.dynamic` section header) at the
// returned bytes.
//
// `bias` is the host load bias: for a PIE host its address-valued tags (INIT,
// FINI, PLTGOT, VERNEED, ...) carry 0-based values and are shifted by `bias`
// so the output is fully absolute. When `verneed_va` is non-zero (payload-only
// version needs were appended), DT_VERNEED/DT_VERNEEDNUM are repointed at the
// merged version-needs table.
std::vector<elf::u8> dynamic(const elf::Image &host, u64 dynsym_va,
                             u64 dynstr_va, u64 versym_va, u64 gnuhash_va,
                             u64 rela_va, u64 rela_size, u64 jmprel_va,
                             u64 pltrelsz, u64 str_size, u64 bias,
                             u64 verneed_va, u64 verneed_num,
                             const std::vector<u64> &needed_offsets);

} // namespace patch
