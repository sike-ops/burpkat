#pragma once

#include "types.h"
#include "utils.hpp"
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace elf {

constexpr std::size_t ehsize = sizeof(Elf64_Ehdr);

// ---------------------------------------------------------------------------
// Image: a parsed ELF file.
// ---------------------------------------------------------------------------
class Image {
public:
  utils::VirtualBuffer file;
  Elf64_Ehdr eh{};
  std::vector<Elf64_Phdr> phdrs;
  std::vector<Elf64_Shdr> shdrs;
  std::vector<std::string> names;

  u64 base = 0; // lowest p_vaddr among PT_LOAD segments
  u64 span = 0; // page-aligned virtual footprint
  utils::VirtualBuffer vmem;

  const u8 *fdata() const { return file.data<u8>(); }
  std::size_t fsize() const { return file.size(); }

  std::span<const u8> sh_bytes(std::size_t i) const {
    const auto &sh = shdrs[i];
    return {fdata() + sh.sh_offset, static_cast<std::size_t>(sh.sh_size)};
  }

  std::string_view name(std::size_t i) const { return names[i]; }

  std::int64_t find(std::string_view wanted) const {
    for (std::size_t i = 0; i < shdrs.size(); ++i) {
      if (names[i] == wanted) {
        return static_cast<std::int64_t>(i);
      }
    }
    return -1;
  }
};

[[noreturn]] void fail(const std::string &msg);
void check(bool cond, const std::string &msg);

u32 rd32(const u8 *p);
void wr32(u8 *p, u32 v);

bool is_elf64(const u8 *data, std::size_t size);
Image load_image(std::string_view filename);

// ---------------------------------------------------------------------------
// Dynamic symbol helpers
// ---------------------------------------------------------------------------
const Elf64_Sym *dynsym(const Image &img, std::size_t idx);
std::size_t dynsym_count(const Image &img);
std::string_view dynsym_name(const Image &img, std::size_t idx);

// find a symbol index in `img` by base name (stripping @version)
std::int64_t sym_index_by_name(const Image &img, std::string_view base);

// ---------------------------------------------------------------------------
// Dynamic table helpers
// ---------------------------------------------------------------------------
// Value of a DT_* tag in `img`'s .dynamic, or nullopt if absent.
std::optional<u64> dynamic_tag(const Image &img, s64 tag);

// Names of every DT_NEEDED entry in `img`'s .dynamic, in order.
std::vector<std::string> needed_libraries(const Image &img);

// Decode DT_RELR packed relative relocations into a list of 0-based target
// virtual addresses (the addresses whose 8-byte value the loader would add the
// load bias to). Returns empty when the image has no DT_RELR.
std::vector<u64> relr_targets(const Image &img);

// ---------------------------------------------------------------------------
// Version needs helpers
// ---------------------------------------------------------------------------
struct VersionNeed {
  std::string file; // owning library (vn_file), e.g. "libstdc++.so.6"
  std::string name; // version name (vna_name), e.g. "GLIBCXX_3.4.36"
  u16 index;        // vna_other (the value stored in .gnu.version entries)
};

struct VersionNeeds {
  std::vector<VersionNeed> list;
};

VersionNeeds version_needs(const Image &img);

// lookup a version index by name, or 0 if the image does not need that version
u16 version_index(const VersionNeeds &vn, std::string_view name);

// Serialize the host's .gnu.version_r with `added` extra (library, version,
// index) needs appended as new Verneed/Vernaux records. `added` must carry the
// freshly assigned vna_other indices, grouped by library. Library/version
// names are appended to `dynstr` and referenced by offset. Returns the merged
// .gnu.version_r bytes (or an empty vector if neither the host nor `added`
// contributes any records).
std::vector<u8> merge_verneed(const Image &host,
                              const std::vector<VersionNeed> &added,
                              std::vector<u8> &dynstr);

} // namespace elf

template <> struct std::formatter<elf::Image> {
  template <class ParseContext>
  constexpr ParseContext::iterator parse(ParseContext &ctx) const {
    return ctx.begin();
  }

  template <class FormatContext>
  FormatContext::iterator format(const elf::Image &img,
                                 FormatContext &ctx) const {
    return std::format_to(
        ctx.out(),
        "Image{{type={}, entry=0x{:x}, base=0x{:x}, span=0x{:x}, "
        "sections={}, segments={}}}",
        img.eh.e_type, img.eh.e_entry, img.base, img.span, img.shdrs.size(),
        img.phdrs.size());
  }
};

template <> struct std::formatter<elf::VersionNeeds> {
  template <class ParseContext>
  constexpr ParseContext::iterator parse(ParseContext &ctx) const {
    return ctx.begin();
  }

  template <class FormatContext>
  FormatContext::iterator format(const elf::VersionNeeds &vn,
                                 FormatContext &ctx) const {
    auto out = std::format_to(ctx.out(), "VersionNeeds{{");
    bool first = true;
    for (const auto &v : vn.list) {
      if (!first) {
        out = std::format_to(out, ", ");
      }
      first = false;
      out = std::format_to(out, "{}:{}={}", v.file, v.name, v.index);
    }
    return std::format_to(out, "}}");
  }
};
