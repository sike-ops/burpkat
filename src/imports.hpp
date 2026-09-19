#pragma once

#include "elf.hpp"
#include <elf.h>
#include <format>
#include <optional>
#include <string>
#include <vector>

namespace imports {

using elf::u8;
using elf::u16;
using elf::u32;
using elf::u64;

struct NewSym {
  std::string name;
  Elf64_Sym sym;
  u16 version;
};

struct Imports {
  std::vector<Elf64_Sym> dynsym;
  std::vector<u8> dynstr;
  std::vector<u16> versym;
  std::vector<u8> gnuhash;
  std::vector<Elf64_Rela> rela; // host rela.dyn (remapped) + pthread GLOB_DAT
  u32 pthread_index = 0;
  u32 symoffset = 0; // original symoffset
  u32 count = 0;     // number of new symbols inserted
  u64 got_slot = 0;
};

// merged symbol index for a host original index, given new symbols shifted
// every host symbol >= symoffset by +count
u32 merge_index(u32 host_idx, u32 symoffset, u32 count);

// Build the merged dynamic tables: append any payload imports the host lacks,
// plus a pthread_create symbol when the host has none.
//
// `host_pthread_index` is the host's existing pthread_create dynsym index when
// the host already imports it; the merged GOT slot then resolves against that
// host symbol (with the host's own version) instead of introducing a duplicate
// with a guessed version index.
//
// `bias` is the host's load bias: 0 for an ET_EXEC host (all addresses are
// already absolute), or the relocation base chosen for a PIE (ET_DYN) host,
// whose link-time addresses are 0-based. Every host absolute value emitted
// into the merged tables (symbol st_value, relocation r_offset/r_addend) is
// shifted by `bias`.
//
// `got_slot` is a caller-provided, writable 8-byte address owned by the tool
// (in its extra segment) used to hold the resolved pthread_create pointer. It
// must NOT be carved out of the host's .bss: doing so clobbers the host's
// globals (thunderbird's uptime guard lives in the last 8 bytes of .bss). The
// pthread_create GLOB_DAT relocation is only emitted when `got_slot != 0`.
Imports build_imports(const elf::Image &host,
                      const std::vector<NewSym> &new_syms,
                      std::optional<u32> host_pthread_index = std::nullopt,
                      u64 bias = 0, u64 got_slot = 0);

} // namespace imports

template <> struct std::formatter<imports::NewSym> {
  template <class ParseContext>
  constexpr ParseContext::iterator parse(ParseContext &ctx) const {
    return ctx.begin();
  }

  template <class FormatContext>
  FormatContext::iterator format(const imports::NewSym &ns,
                                 FormatContext &ctx) const {
    return std::format_to(ctx.out(), "NewSym{{name={}, version={}}}", ns.name,
                          ns.version);
  }
};

template <> struct std::formatter<imports::Imports> {
  template <class ParseContext>
  constexpr ParseContext::iterator parse(ParseContext &ctx) const {
    return ctx.begin();
  }

  template <class FormatContext>
  FormatContext::iterator format(const imports::Imports &im,
                                 FormatContext &ctx) const {
    return std::format_to(
        ctx.out(),
        "Imports{{symbols={}, dynstr={}B, versym={}, gnuhash={}B, rela={}, "
        "pthread_index={}, symoffset={}, count={}, got_slot=0x{:x}}}",
        im.dynsym.size(), im.dynstr.size(), im.versym.size(), im.gnuhash.size(),
        im.rela.size(), im.pthread_index, im.symoffset, im.count, im.got_slot);
  }
};
