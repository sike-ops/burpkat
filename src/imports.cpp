#include "imports.hpp"

namespace imports {

using elf::check;
using elf::rd32;
using elf::wr32;

u32 merge_index(u32 host_idx, u32 symoffset, u32 count) {
  return host_idx >= symoffset ? host_idx + count : host_idx;
}

Imports build_imports(const elf::Image &host,
                      const std::vector<NewSym> &new_syms,
                      std::optional<u32> host_pthread_index) {
  Imports im;

  const auto di = host.find(".dynsym");
  check(di >= 0, "no .dynsym");
  const auto &dsh = host.shdrs[di];
  const auto nsym = dsh.sh_size / dsh.sh_entsize;
  const auto *old_sym =
      reinterpret_cast<const Elf64_Sym *>(host.fdata() + dsh.sh_offset);

  const auto gi = host.find(".gnu.hash");
  check(gi >= 0, "no .gnu.hash");
  const u8 *gh = host.fdata() + host.shdrs[gi].sh_offset;
  const u32 symoffset = rd32(gh + 4);
  im.symoffset = symoffset;
  im.count = static_cast<u32>(new_syms.size());

  const auto si = host.find(".dynstr");
  check(si >= 0, "no .dynstr");
  const auto &ssh = host.shdrs[si];
  im.dynstr.assign(host.fdata() + ssh.sh_offset,
                   host.fdata() + ssh.sh_offset + ssh.sh_size);

  im.dynsym.assign(old_sym, old_sym + nsym);
  std::vector<u32> name_offs(new_syms.size());
  for (std::size_t i = 0; i < new_syms.size(); ++i) {
    name_offs[i] = static_cast<u32>(im.dynstr.size());
    im.dynstr.insert(im.dynstr.end(), new_syms[i].name.begin(),
                     new_syms[i].name.end());
    im.dynstr.push_back('\0');
  }
  if (host_pthread_index) {
    im.pthread_index =
        merge_index(*host_pthread_index, symoffset, static_cast<u32>(new_syms.size()));
  } else {
    im.pthread_index = 0;
    for (std::size_t i = 0; i < new_syms.size(); ++i) {
      if (new_syms[i].name == "pthread_create") {
        im.pthread_index = symoffset + static_cast<u32>(i);
        break;
      }
    }
    check(im.pthread_index != 0, "no pthread_create symbol available");
  }
  for (std::size_t i = 0; i < new_syms.size(); ++i) {
    Elf64_Sym s = new_syms[i].sym;
    s.st_name = name_offs[i];
    s.st_shndx = SHN_UNDEF;
    im.dynsym.insert(im.dynsym.begin() + symoffset + i, s);
  }

  const auto vi = host.find(".gnu.version");
  check(vi >= 0, "no .gnu.version");
  const auto &vsh = host.shdrs[vi];
  const auto nv = vsh.sh_size / vsh.sh_entsize;
  const auto *ov = reinterpret_cast<const u16 *>(host.fdata() + vsh.sh_offset);
  im.versym.assign(ov, ov + nv);
  for (std::size_t i = 0; i < new_syms.size(); ++i) {
    im.versym.insert(im.versym.begin() + symoffset + i, new_syms[i].version);
  }

  im.gnuhash.assign(gh, gh + host.shdrs[gi].sh_size);
  wr32(im.gnuhash.data() + 4, symoffset + im.count);
  const u32 nbuckets = rd32(gh);
  const u32 bloom_size = rd32(gh + 8);
  const std::size_t buckets_off = 16 + static_cast<std::size_t>(bloom_size) * 8;
  for (u32 b = 0; b < nbuckets; ++b) {
    auto *bucket = reinterpret_cast<u32 *>(im.gnuhash.data() + buckets_off) + b;
    if (*bucket != 0) {
      *bucket += im.count;
    }
  }

  const auto ri = host.find(".rela.dyn");
  check(ri >= 0, "no .rela.dyn");
  const auto &rsh = host.shdrs[ri];
  const auto nr = rsh.sh_size / rsh.sh_entsize;
  const auto *old_rela =
      reinterpret_cast<const Elf64_Rela *>(host.fdata() + rsh.sh_offset);
  im.rela.assign(old_rela, old_rela + nr);
  for (auto &r : im.rela) {
    u32 sym = ELF64_R_SYM(r.r_info);
    if (sym >= symoffset) {
      sym += im.count;
    }
    r.r_info = ELF64_R_INFO(sym, ELF64_R_TYPE(r.r_info));
  }

  const auto bi = host.find(".bss");
  check(bi >= 0, "no .bss");
  im.got_slot = host.shdrs[bi].sh_addr + host.shdrs[bi].sh_size - 8;

  Elf64_Rela pcrel{};
  pcrel.r_offset = im.got_slot;
  pcrel.r_info = ELF64_R_INFO(im.pthread_index, R_X86_64_GLOB_DAT);
  im.rela.push_back(pcrel);

  return im;
}

} // namespace imports
