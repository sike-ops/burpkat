#include "elf.hpp"
#include <algorithm>
#include <fstream>
#include <stdexcept>

namespace elf {

[[noreturn]] void fail(const std::string &msg) {
  throw std::runtime_error(msg);
}

void check(bool cond, const std::string &msg) {
  if (!cond) {
    fail(msg);
  }
}

u32 rd32(const u8 *p) {
  u32 v;
  std::memcpy(&v, p, 4);
  return v;
}

void wr32(u8 *p, u32 v) { std::memcpy(p, &v, 4); }

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------
bool is_elf64(const u8 *data, std::size_t size) {
  if (size < ehsize) {
    return false;
  }
  const auto *hdr = reinterpret_cast<const Elf64_Ehdr *>(data);
  if (std::memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0) {
    return false;
  }
  if (hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
      hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
    return false;
  }
  if (hdr->e_ehsize != ehsize) {
    return false;
  }
  if (hdr->e_type != ET_EXEC && hdr->e_type != ET_DYN) {
    return false;
  }
  return true;
}

Image load_image(std::string_view filename) {
  std::ifstream f(filename.data(), std::ios::binary);
  if (!f) {
    throw SystemErrorMessage{};
  }
  f.seekg(0, std::ios::end);
  const auto size = static_cast<std::size_t>(f.tellg());
  f.seekg(0, std::ios::beg);

  Image img;
  img.file = std::move(utils::VirtualBuffer(size));
  f.read(img.file.data<char>(), static_cast<std::streamsize>(size));
  f.close();

  check(is_elf64(img.fdata(), size), "input is not a valid 64-bit ELF");

  std::memcpy(&img.eh, img.fdata(), ehsize);
  check(img.eh.e_phnum != 0 && img.eh.e_phoff != 0, "no program headers");
  check(img.eh.e_shnum != 0 && img.eh.e_shoff != 0, "no section headers");

  img.phdrs.resize(img.eh.e_phnum);
  const auto phbytes = img.eh.e_phnum * img.eh.e_phentsize;
  check(img.eh.e_phoff + phbytes <= size, "program header table out of range");
  std::memcpy(img.phdrs.data(), img.fdata() + img.eh.e_phoff, phbytes);

  img.shdrs.resize(img.eh.e_shnum);
  const auto shbytes = img.eh.e_shnum * img.eh.e_shentsize;
  check(img.eh.e_shoff + shbytes <= size, "section header table out of range");
  std::memcpy(img.shdrs.data(), img.fdata() + img.eh.e_shoff, shbytes);

  check(img.eh.e_shstrndx < img.eh.e_shnum, "bad e_shstrndx");
  const auto &strtab = img.shdrs[img.eh.e_shstrndx];
  check(strtab.sh_offset + strtab.sh_size <= size, "shstrtab out of range");
  const char *strdata =
      reinterpret_cast<const char *>(img.fdata() + strtab.sh_offset);

  img.names.resize(img.eh.e_shnum);
  for (std::size_t i = 0; i < img.shdrs.size(); ++i) {
    const auto off = img.shdrs[i].sh_name;
    check(off < strtab.sh_size, "section name out of range");
    img.names[i] = std::string(strdata + off);
  }

  bool any_load = false;
  u64 lo = ~u64{0}, hi = 0;
  for (const auto &ph : img.phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0) {
      continue;
    }
    any_load = true;
    lo = std::min(lo, ph.p_vaddr);
    hi = std::max(hi, ph.p_vaddr + ph.p_memsz);
  }
  check(any_load, "no loadable segments");

  img.base = lo;
  img.span = utils::page_align(hi - lo);
  img.vmem = std::move(utils::VirtualBuffer(img.span));

  for (const auto &ph : img.phdrs) {
    if (ph.p_type != PT_LOAD) {
      continue;
    }
    check(ph.p_offset + ph.p_filesz <= size, "segment out of range");
    const u8 *src = img.fdata() + ph.p_offset;
    u8 *dst = img.vmem.data<u8>() + (ph.p_vaddr - img.base);
    std::memcpy(dst, src, ph.p_filesz);
  }

  return img;
}

// ---------------------------------------------------------------------------
// Dynamic symbol helpers
// ---------------------------------------------------------------------------
const Elf64_Sym *dynsym(const Image &img, std::size_t idx) {
  const auto di = img.find(".dynsym");
  check(di >= 0, "no .dynsym");
  const auto &sh = img.shdrs[di];
  return reinterpret_cast<const Elf64_Sym *>(img.fdata() + sh.sh_offset) + idx;
}

std::size_t dynsym_count(const Image &img) {
  const auto di = img.find(".dynsym");
  check(di >= 0, "no .dynsym");
  const auto &sh = img.shdrs[di];
  return sh.sh_size / sh.sh_entsize;
}

std::string_view dynsym_name(const Image &img, std::size_t idx) {
  const auto di = img.find(".dynsym");
  const auto si = img.find(".dynstr");
  check(di >= 0 && si >= 0, "no dynsym/dynstr");
  const auto &dsh = img.shdrs[di];
  const auto &ssh = img.shdrs[si];
  const char *strtab =
      reinterpret_cast<const char *>(img.fdata() + ssh.sh_offset);
  const auto *s =
      reinterpret_cast<const Elf64_Sym *>(img.fdata() + dsh.sh_offset) + idx;
  if (s->st_name == 0 || s->st_name >= ssh.sh_size) {
    return {};
  }
  return std::string_view(strtab + s->st_name);
}

std::int64_t sym_index_by_name(const Image &img, std::string_view base) {
  const auto n = dynsym_count(img);
  for (std::size_t i = 1; i < n; ++i) {
    const auto nm = dynsym_name(img, i);
    const auto at = nm.find('@');
    const auto b = nm.substr(0, at);
    if (b == base) {
      return static_cast<std::int64_t>(i);
    }
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Version needs helpers
// ---------------------------------------------------------------------------
VersionNeeds version_needs(const Image &img) {
  VersionNeeds vn;
  const auto idx = img.find(".gnu.version_r");
  if (idx < 0) {
    return vn;
  }
  const auto &sh = img.shdrs[idx];
  const auto &ssh = img.shdrs[sh.sh_link];
  const char *strtab =
      reinterpret_cast<const char *>(img.fdata() + ssh.sh_offset);
  const u8 *p = img.fdata() + sh.sh_offset;
  const u8 *end = p + sh.sh_size;
  while (p + 16 <= end) {
    const auto *ver = reinterpret_cast<const Elf64_Verneed *>(p);
    if (ver->vn_version != 1) {
      break;
    }
    const u8 *aux = p + ver->vn_aux;
    for (u16 i = 0; i < ver->vn_cnt; ++i) {
      const auto *vna = reinterpret_cast<const Elf64_Vernaux *>(aux);
      vn.list.emplace_back(strtab + vna->vna_name, vna->vna_other);
      if (vna->vna_next == 0) {
        break;
      }
      aux += vna->vna_next;
    }
    if (ver->vn_next == 0) {
      break;
    }
    p += ver->vn_next;
  }
  return vn;
}

u16 version_index(const VersionNeeds &vn, std::string_view name) {
  for (const auto &[n, idx] : vn.list) {
    if (n == name) {
      return idx;
    }
  }
  return 0;
}

u16 remap_version(u16 pver, const VersionNeeds &pv, const VersionNeeds &hv) {
  if (pver <= 1 || (pver & 0x8000)) {
    return pver; // local / global / hidden
  }
  std::string name;
  for (const auto &[n, idx] : pv.list) {
    if (idx == pver) {
      name = n;
      break;
    }
  }
  check(!name.empty(), "version index not found in payload");
  for (const auto &[n, idx] : hv.list) {
    if (n == name) {
      return idx;
    }
  }
  fail("payload version not present in host: " + name);
}

} // namespace elf
