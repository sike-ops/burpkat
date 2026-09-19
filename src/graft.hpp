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
//
// `im` is mutated in one place: a payload COPY relocation against a host symbol
// whose st_size is smaller (typically 0 for a GLOB_DAT import) bumps the merged
// symbol's size up to the payload's, so the loader copies the full object and
// does not warn about the size mismatch.
// `launcher_va` is the runtime address of the payload launcher (see
// make_launcher). A payload PIE's `_start` calls `__libc_start_main`; that
// libc entry point runs the *process main map's* constructors, i.e. it would
// run the host's `.init_array` a second time. The payload's
// `__libc_start_main` GOT slot is redirected to the launcher instead.
std::vector<elf::u8> graft_payload(const elf::Image &host,
                                   const elf::Image &payload,
                                   imports::Imports &im,
                                   const std::vector<imports::NewSym> &new_syms,
                                   u64 B, u64 launcher_va, PayloadReloc &pr);

// Build the entry shellcode: call the payload, then jump back to the host.
std::vector<elf::u8> make_shellcode(u64 payload_entry, u64 host_entry,
                                    u64 got_slot);

// Build the payload launcher: entered with rdi = payload main (as passed to
// __libc_start_main), rsi = argc, rdx = argv. Runs the payload's DT_INIT and
// each `.init_array` function, then calls main. Never returns (glibc's
// __libc_start_main would have called exit(); this thread must not).
std::vector<elf::u8> make_launcher(u64 dt_init, const std::vector<u64> &init_slots);

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
