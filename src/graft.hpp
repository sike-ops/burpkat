#pragma once

#include "elf.hpp"
#include "imports.hpp"
#include <elf.h>
#include <format>
#include <vector>

namespace graft {

using elf::u64;

struct PayloadReloc {
  std::vector<Elf64_Rela> rela_dyn; // runtime (64-undef, GLOB_DAT, COPY)
  std::vector<Elf64_Rela> rela_plt; // runtime JUMP_SLOT
};

// Graft + relocate the PIE payload into a flat image at load bias B.
std::vector<elf::u8> graft_payload(const elf::Image &host,
                                   const elf::Image &payload,
                                   const imports::Imports &im,
                                   const std::vector<imports::NewSym> &new_syms,
                                   u64 B, PayloadReloc &pr);

// Build the entry shellcode: call the payload, then jump back to the host.
std::vector<elf::u8> make_shellcode(u64 payload_entry, u64 host_entry,
                                    u64 got_slot);

} // namespace graft

template <> struct std::formatter<graft::PayloadReloc> {
  template <class ParseContext>
  constexpr ParseContext::iterator parse(ParseContext &ctx) const {
    return ctx.begin();
  }

  template <class FormatContext>
  FormatContext::iterator format(const graft::PayloadReloc &pr,
                                 FormatContext &ctx) const {
    return std::format_to(ctx.out(), "PayloadReloc{{rela_dyn={}, rela_plt={}}}",
                          pr.rela_dyn.size(), pr.rela_plt.size());
  }
};
