#include "patch.hpp"
#include "log.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <cstring>

namespace patch {

using elf::u8;
using elf::u32;
using elf::s64;
using elf::check;
using elf::fail;
using elf::rd32;

void build_id(std::vector<u8> &out, const elf::Image &host) {
  const auto idx = host.find(".note.gnu.build-id");
  if (idx < 0) {
    logging::debug("host has no .note.gnu.build-id, skipping");
    return;
  }
  const auto &sh = host.shdrs[idx];
  const u8 *base = out.data() + sh.sh_offset;
  std::size_t off = 0;
  while (off + 12 <= sh.sh_size) {
    const u32 namesz = rd32(base + off);
    const u32 descsz = rd32(base + off + 4);
    const u32 type = rd32(base + off + 8);
    const std::size_t name_off = off + 12;
    const std::size_t name_pad = ((namesz + 3) & ~3u) - namesz;
    const std::size_t desc_off = name_off + namesz + name_pad;
    const std::size_t desc_pad = ((descsz + 3) & ~3u) - descsz;
    const std::size_t next = desc_off + descsz + desc_pad;
    if (next > sh.sh_size) {
      break;
    }
    if (type == NT_GNU_BUILD_ID && descsz == 20) {
      std::fill(out.begin() + (sh.sh_offset + desc_off),
                out.begin() + (sh.sh_offset + desc_off + descsz), 0);
      std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
      unsigned int digest_len = 0;
      check(EVP_Digest(out.data(), out.size(), digest.data(), &digest_len,
                       EVP_sha1(), nullptr) == 1,
            "SHA1 digest failed");
      std::memcpy(out.data() + sh.sh_offset + desc_off, digest.data(),
                  digest_len);
      return;
    }
    off = next;
  }
  fail("no NT_GNU_BUILD_ID note found");
}

void dynamic(std::vector<u8> &out, const elf::Image &host, u64 dynsym_va,
             u64 dynstr_va, u64 versym_va, u64 gnuhash_va, u64 rela_va,
             u64 rela_size, u64 jmprel_va, u64 pltrelsz, u64 str_size) {
  const auto di = host.find(".dynamic");
  check(di >= 0, "no .dynamic");
  const u64 off = host.shdrs[di].sh_offset;
  const u64 end = off + host.shdrs[di].sh_size;

  // first pass: rewrite the pointer entries
  for (u64 o = off; o + 16 <= end; o += 16) {
    s64 tag;
    u64 val;
    std::memcpy(&tag, out.data() + o, 8);
    std::memcpy(&val, out.data() + o + 8, 8);
    if (tag == DT_NULL) {
      break;
    }
    switch (tag) {
    case DT_STRTAB:
      val = dynstr_va;
      break;
    case DT_SYMTAB:
      val = dynsym_va;
      break;
    case DT_RELA:
      val = rela_va;
      break;
    case DT_RELASZ:
      val = rela_size;
      break;
    case DT_STRSZ:
      val = str_size;
      break;
    case DT_GNU_HASH:
      val = gnuhash_va;
      break;
    case DT_VERSYM:
      val = versym_va;
      break;
    case DT_JMPREL:
      val = jmprel_va;
      break;
    case DT_PLTRELSZ:
      val = pltrelsz;
      break;
    default:
      break;
    }
    std::memcpy(out.data() + o + 8, &val, 8);
  }

  // second pass: turn the terminating DT_NULL into DT_FLAGS|DF_BIND_NOW (the
  // payload's JUMP_SLOT relocations must be resolved eagerly), then append a
  // fresh DT_NULL.
  for (u64 o = off; o + 16 <= end; o += 16) {
    s64 tag;
    std::memcpy(&tag, out.data() + o, 8);
    if (tag == DT_NULL) {
      const u64 flags_tag = DT_FLAGS;
      const u64 bind_now = DF_BIND_NOW;
      std::memcpy(out.data() + o, &flags_tag, 8);
      std::memcpy(out.data() + o + 8, &bind_now, 8);
      if (o + 16 < end) {
        const u64 zero = 0;
        std::memcpy(out.data() + o + 16, &zero, 8);
        std::memcpy(out.data() + o + 24, &zero, 8);
      }
      break;
    }
  }
}

} // namespace patch
