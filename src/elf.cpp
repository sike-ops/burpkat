#include "elf.hpp"
#include <algorithm>
#include <fstream>
#include <map>
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
// Dynamic table helpers
// ---------------------------------------------------------------------------
std::optional<u64> dynamic_tag(const Image &img, s64 tag) {
  const auto di = img.find(".dynamic");
  if (di < 0) {
    return std::nullopt;
  }
  const auto &sh = img.shdrs[di];
  const u8 *p = img.fdata() + sh.sh_offset;
  const u8 *end = p + sh.sh_size;
  while (p + 16 <= end) {
    s64 t;
    u64 v;
    std::memcpy(&t, p, 8);
    std::memcpy(&v, p + 8, 8);
    if (t == DT_NULL) {
      break;
    }
    if (t == tag) {
      return v;
    }
    p += 16;
  }
  return std::nullopt;
}

std::vector<std::string> needed_libraries(const Image &img) {
  std::vector<std::string> out;
  const auto di = img.find(".dynamic");
  const auto si = img.find(".dynstr");
  if (di < 0 || si < 0) {
    return out;
  }
  const auto &dsh = img.shdrs[di];
  const auto &ssh = img.shdrs[si];
  const char *str = reinterpret_cast<const char *>(img.fdata() + ssh.sh_offset);
  const u8 *p = img.fdata() + dsh.sh_offset;
  const u8 *end = p + dsh.sh_size;
  while (p + 16 <= end) {
    s64 tag;
    u64 val;
    std::memcpy(&tag, p, 8);
    std::memcpy(&val, p + 8, 8);
    if (tag == DT_NULL) {
      break;
    }
    if (tag == DT_NEEDED && val < ssh.sh_size) {
      out.emplace_back(str + val);
    }
    p += 16;
  }
  return out;
}

std::vector<u64> relr_targets(const Image &img) {
  std::vector<u64> targets;
  const auto relr = dynamic_tag(img, DT_RELR);
  const auto relrsz = dynamic_tag(img, DT_RELRSZ);
  if (!relr || !relrsz || *relrsz == 0) {
    return targets;
  }
  check(*relr + *relrsz <= img.span, "RELR table out of range");
  const u8 *p = img.vmem.data<u8>() + *relr;
  const u8 *end = p + *relrsz;
  u64 where = 0;
  while (p + 8 <= end) {
    u64 entry;
    std::memcpy(&entry, p, 8);
    p += 8;
    if ((entry & 1) == 0) {
      where = entry;
      targets.push_back(where);
      where += 8;
    } else {
      for (int i = 0; (entry >>= 1) != 0; ++i) {
        if ((entry & 1) != 0) {
          targets.push_back(where + 8 * i);
        }
      }
      where += 8 * 63;
    }
  }
  return targets;
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
    const char *file = strtab + ver->vn_file;
    const u8 *aux = p + ver->vn_aux;
    for (u16 i = 0; i < ver->vn_cnt; ++i) {
      const auto *vna = reinterpret_cast<const Elf64_Vernaux *>(aux);
      vn.list.push_back({file, strtab + vna->vna_name, vna->vna_other});
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
  for (const auto &v : vn.list) {
    if (v.name == name) {
      return v.index;
    }
  }
  return 0;
}

namespace {

u32 elf_hash(const char *name) {
  u32 hash = 0;
  const auto *p = reinterpret_cast<const u8 *>(name);
  while (*p != '\0') {
    u32 hi;
    hash = (hash << 4) + *p++;
    hi = hash & 0xf0000000u;
    if (hi != 0) {
      hash ^= hi >> 24;
    }
    hash &= ~hi;
  }
  return hash;
}

} // namespace

std::vector<u8> merge_verneed(const Image &host,
                              const std::vector<VersionNeed> &added,
                              std::vector<u8> &dynstr) {
  std::vector<u8> out;
  const auto hidx = host.find(".gnu.version_r");
  if (hidx >= 0) {
    const auto &sh = host.shdrs[hidx];
    out.assign(host.fdata() + sh.sh_offset,
               host.fdata() + sh.sh_offset + sh.sh_size);
  }
  if (added.empty()) {
    return out;
  }

  // group `added` by owning library, preserving order
  std::vector<std::pair<std::string, std::vector<const VersionNeed *>>> groups;
  for (const auto &a : added) {
    if (groups.empty() || groups.back().first != a.file) {
      groups.emplace_back(a.file, std::vector<const VersionNeed *>{});
    }
    groups.back().second.push_back(&a);
  }

  // intern strings into dynstr, returning their offset
  std::map<std::string, u32> str_off;
  const auto intern = [&](const std::string &s) -> u32 {
    const auto it = str_off.find(s);
    if (it != str_off.end()) {
      return it->second;
    }
    const u32 off = static_cast<u32>(dynstr.size());
    dynstr.insert(dynstr.end(), s.begin(), s.end());
    dynstr.push_back('\0');
    str_off.emplace(s, off);
    return off;
  };

  // locate the last host Verneed (its vn_next must be patched to point at the
  // first appended record)
  std::size_t last = 0;
  if (!out.empty()) {
    std::size_t p = 0;
    while (p + 16 <= out.size()) {
      const auto *ver = reinterpret_cast<const Elf64_Verneed *>(out.data() + p);
      if (ver->vn_version != 1) {
        break;
      }
      last = p;
      if (ver->vn_next == 0) {
        break;
      }
      p += ver->vn_next;
    }
  }

  // record offsets: each group contributes one Verneed + vn_cnt Vernaux
  const std::size_t base = out.size();
  std::vector<std::size_t> vn_off(groups.size());
  std::size_t cursor = base;
  for (std::size_t g = 0; g < groups.size(); ++g) {
    vn_off[g] = cursor;
    cursor += sizeof(Elf64_Verneed) +
              groups[g].second.size() * sizeof(Elf64_Vernaux);
  }
  out.resize(cursor);

  // patch the host's terminating vn_next to the first appended record
  if (!out.empty() && base != 0) {
    auto *ver = reinterpret_cast<Elf64_Verneed *>(out.data() + last);
    ver->vn_next = static_cast<u32>(vn_off[0] - last);
  }

  for (std::size_t g = 0; g < groups.size(); ++g) {
    auto &[file, versions] = groups[g];
    auto *ver = reinterpret_cast<Elf64_Verneed *>(out.data() + vn_off[g]);
    ver->vn_version = 1;
    ver->vn_cnt = static_cast<u16>(versions.size());
    ver->vn_file = intern(file);
    ver->vn_aux = sizeof(Elf64_Verneed);
    ver->vn_next =
        (g + 1 < groups.size()) ? static_cast<u32>(vn_off[g + 1] - vn_off[g])
                                : 0;

    auto *aux = reinterpret_cast<Elf64_Vernaux *>(out.data() + vn_off[g] +
                                                  sizeof(Elf64_Verneed));
    for (std::size_t k = 0; k < versions.size(); ++k) {
      aux[k].vna_hash = elf_hash(versions[k]->name.c_str());
      aux[k].vna_flags = 0;
      aux[k].vna_other = versions[k]->index;
      aux[k].vna_name = intern(versions[k]->name);
      aux[k].vna_next =
          (k + 1 < versions.size()) ? sizeof(Elf64_Vernaux) : 0;
    }
  }

  return out;
}

} // namespace elf
