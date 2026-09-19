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

std::vector<u8> dynamic(const elf::Image &host, u64 dynsym_va, u64 dynstr_va,
                        u64 versym_va, u64 gnuhash_va, u64 rela_va,
                        u64 rela_size, u64 jmprel_va, u64 pltrelsz,
                        u64 str_size, u64 bias, u64 verneed_va,
                        u64 verneed_num,
                        const std::vector<u64> &needed_offsets) {
  const auto di = host.find(".dynamic");
  check(di >= 0, "no .dynamic");
  const auto &dsh = host.shdrs[di];
  const u8 *p = host.fdata() + dsh.sh_offset;
  const u8 *end = p + dsh.sh_size;

  // Dynamic tags whose d_un.d_ptr is an address and which are not repointed at
  // the merged tables below. A PIE host stores these 0-based, so they must be
  // shifted by `bias` to become absolute in the ET_EXEC output.
  const auto is_addr_tag = [](s64 tag) {
    switch (tag) {
    case DT_PLTGOT:
    case DT_HASH:
    case DT_REL:
    case DT_INIT:
    case DT_FINI:
    case DT_INIT_ARRAY:
    case DT_FINI_ARRAY:
    case DT_PREINIT_ARRAY:
    case DT_VERDEF:
    case DT_SYMTAB_SHNDX:
      return true;
    default:
      return false;
    }
  };

  std::vector<Elf64_Dyn> entries;
  const auto emit = [&](s64 tag, u64 val) {
    Elf64_Dyn d{};
    d.d_tag = tag;
    d.d_un.d_val = val;
    entries.push_back(d);
  };

  // Rewrite each host entry: repoint the merged tables, force eager binding by
  // OR-ing DF_BIND_NOW / DF_1_NOW into the flags, and drop DT_RELR. The
  // terminating DT_NULL is not copied; a fresh one is emitted at the end.
  bool saw_flags = false;
  bool saw_flags_1 = false;
  for (;; p += 16) {
    if (p + 16 > end) {
      fail("unterminated .dynamic");
    }
    s64 tag;
    u64 val;
    std::memcpy(&tag, p, 8);
    std::memcpy(&val, p + 8, 8);
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
    case DT_RELR:
    case DT_RELRSZ:
      // packed relative relocations were expanded into the merged .rela.dyn;
      // drop them so the loader does not try to apply them with l_addr == 0
      val = 0;
      break;
    case DT_FLAGS:
      // bind the payload's JUMP_SLOT relocations eagerly
      val |= DF_BIND_NOW;
      saw_flags = true;
      break;
    case DT_FLAGS_1:
      // the output is a fixed-address ET_EXEC, so it is no longer a PIE
      val &= ~static_cast<u64>(DF_1_PIE);
      // bind the payload's JUMP_SLOT relocations eagerly
      val |= DF_1_NOW;
      saw_flags_1 = true;
      break;
    case DT_VERNEED:
      if (verneed_va != 0) {
        val = verneed_va;
      } else {
        val += bias;
      }
      break;
    case DT_VERNEEDNUM:
      if (verneed_va != 0) {
        val = verneed_num;
      }
      break;
    default:
      if (is_addr_tag(tag)) {
        val += bias;
      }
      break;
    }
    emit(tag, val);
  }

  // A host with neither DT_FLAGS nor DT_FLAGS_1 still needs eager binding so the
  // payload's JUMP_SLOT relocations are applied before the shellcode runs.
  if (!saw_flags && !saw_flags_1) {
    emit(DT_FLAGS, DF_BIND_NOW);
  }

  // DT_NEEDED injection: libraries the payload needs that the host does not
  // already depend on. Without these the loader would neither load the library
  // nor be able to bind the appended version needs.
  for (u64 off : needed_offsets) {
    logging::debug("injecting DT_NEEDED at dynstr offset {}", off);
    emit(DT_NEEDED, off);
  }

  emit(DT_NULL, 0);

  std::vector<u8> out(entries.size() * sizeof(Elf64_Dyn));
  std::memcpy(out.data(), entries.data(), out.size());
  return out;
}

} // namespace patch
