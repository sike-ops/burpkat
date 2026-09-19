#include "build.hpp"
#include "graft.hpp"
#include "imports.hpp"
#include "log.hpp"
#include "patch.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace build {

using elf::u8;
using elf::u16;
using elf::u32;
using elf::u64;
using elf::check;
using elf::dynsym;
using elf::dynsym_count;
using elf::dynsym_name;
using elf::fail;
using elf::remap_version;
using elf::sym_index_by_name;
using elf::version_needs;

std::vector<u8> combine(const elf::Image &host, const elf::Image &payload) {
  check(host.eh.e_type == ET_EXEC, "host must be an ET_EXEC");
  check(payload.eh.e_type == ET_DYN, "payload must be a PIE (ET_DYN)");

  const u64 host_entry = host.eh.e_entry;
  const u64 B = host.base + host.span; // payload load bias

  // collect new undefined symbols: payload imports the host lacks (payload
  // symbols that are already defined/imported by the host are resolved directly
  // against the host's symbols).
  //
  // pthread_create is special: the shellcode calls it to spawn the payload. If
  // the host already imports it (the common case) we reuse the host symbol and
  // its version; only when the host has none do we synthesize one, resolving the
  // version index against the host's own version table rather than guessing.
  std::vector<imports::NewSym> new_syms;
  std::optional<u32> host_pthread;
  {
    const auto pc = sym_index_by_name(host, "pthread_create");
    if (pc >= 0) {
      host_pthread = static_cast<u32>(pc);
      logging::debug("host already imports pthread_create at index {}", pc);
    } else {
      const auto hv = version_needs(host);
      imports::NewSym ns;
      ns.name = "pthread_create";
      ns.sym = {};
      ns.sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
      ns.version = version_index(hv, "GLIBC_2.34");
      if (ns.version == 0) {
        ns.version = version_index(hv, "GLIBC_2.2.5");
      }
      check(ns.version != 0, "host has no usable pthread_create version");
      logging::debug("host lacks pthread_create, adding version {}", ns.version);
      new_syms.push_back(ns);
    }
  }
  {
    const auto pv = version_needs(payload);
    const auto hv = version_needs(host);
    logging::debug("payload version needs: {}", pv);
    logging::debug("host version needs:    {}", hv);
    const auto pvi = payload.find(".gnu.version");
    check(pvi >= 0, "payload has no .gnu.version");
    const auto &pvsh = payload.shdrs[pvi];
    const auto *pversym =
        reinterpret_cast<const u16 *>(payload.fdata() + pvsh.sh_offset);
    const auto n = dynsym_count(payload);
    for (std::size_t i = 1; i < n; ++i) {
      const auto *s = dynsym(payload, i);
      if (s->st_shndx != SHN_UNDEF || s->st_name == 0) {
        continue;
      }
      const auto nm = dynsym_name(payload, i);
      const std::string_view base = nm.substr(0, nm.find('@'));
      if (sym_index_by_name(host, base) >= 0) {
        continue;
      }
      if (base == "pthread_create") {
        continue; // already handled above
      }
      imports::NewSym ns;
      ns.name = std::string(base);
      ns.sym = *s;
      ns.version = remap_version(pversym[i], pv, hv);
      new_syms.push_back(ns);
    }
  }

  imports::Imports im = imports::build_imports(host, new_syms, host_pthread);
  logging::debug("imports: {}", im);
  for (const auto &ns : new_syms) {
    logging::debug("new symbol: {}", ns);
  }

  graft::PayloadReloc pr;
  std::vector<u8> payload_mem =
      graft::graft_payload(host, payload, im, new_syms, B, pr);
  logging::debug("payload relocations: {}", pr);

  const u64 payload_entry = B + payload.eh.e_entry;
  logging::debug("load bias B=0x{:x}, payload entry=0x{:x}, got slot=0x{:x}", B,
             payload_entry, im.got_slot);
  auto shellcode = graft::make_shellcode(payload_entry, host_entry, im.got_slot);
  logging::debug("shellcode: {} bytes", shellcode.size());

  // merged relocations
  std::vector<Elf64_Rela> merged_rela = im.rela;
  merged_rela.insert(merged_rela.end(), pr.rela_dyn.begin(), pr.rela_dyn.end());

  // host rela.plt, remapped
  std::vector<Elf64_Rela> merged_jmprel;
  {
    const auto pi = host.find(".rela.plt");
    check(pi >= 0, "no .rela.plt");
    const auto &sh = host.shdrs[pi];
    const auto n = sh.sh_size / sh.sh_entsize;
    const auto *rela =
        reinterpret_cast<const Elf64_Rela *>(host.fdata() + sh.sh_offset);
    merged_jmprel.assign(rela, rela + n);
    for (auto &r : merged_jmprel) {
      u32 sym = ELF64_R_SYM(r.r_info);
      if (sym >= im.symoffset) {
        sym += im.count;
      }
      r.r_info = ELF64_R_INFO(sym, ELF64_R_TYPE(r.r_info));
    }
  }
  merged_jmprel.insert(merged_jmprel.end(), pr.rela_plt.begin(),
                       pr.rela_plt.end());

  // serialize tables
  std::vector<u8> dynsym_bytes(im.dynsym.size() * sizeof(Elf64_Sym));
  std::memcpy(dynsym_bytes.data(), im.dynsym.data(), dynsym_bytes.size());
  std::vector<u8> versym_bytes(im.versym.size() * sizeof(u16));
  std::memcpy(versym_bytes.data(), im.versym.data(), versym_bytes.size());
  std::vector<u8> rela_bytes(merged_rela.size() * sizeof(Elf64_Rela));
  std::memcpy(rela_bytes.data(), merged_rela.data(), rela_bytes.size());
  std::vector<u8> jmprel_bytes(merged_jmprel.size() * sizeof(Elf64_Rela));
  std::memcpy(jmprel_bytes.data(), merged_jmprel.data(), jmprel_bytes.size());

  // new program headers = host + one per payload PT_LOAD + one extra segment
  std::vector<Elf64_Phdr> ploads;
  for (const auto &ph : payload.phdrs) {
    if (ph.p_type == PT_LOAD) {
      ploads.push_back(ph);
    }
  }
  check(!ploads.empty(), "payload has no LOAD segments");

  std::vector<Elf64_Phdr> phdrs = host.phdrs;
  const std::size_t host_phnum = phdrs.size();
  const std::size_t extra_phdr = host_phnum + ploads.size();
  for (std::size_t i = 0; i <= ploads.size(); ++i) {
    Elf64_Phdr p{};
    p.p_type = PT_LOAD;
    p.p_align = 0x1000;
    phdrs.push_back(p);
  }

  const u64 F = utils::page_align(host.fsize());

  // payload file/VA footprint
  u64 payload_file_end = 0;
  u64 payload_va_end = 0;
  for (const auto &ph : ploads) {
    payload_file_end = std::max(payload_file_end, ph.p_offset + ph.p_filesz);
    payload_va_end = std::max(payload_va_end, ph.p_vaddr + ph.p_memsz);
  }

  const u64 extra_va = utils::page_align(B + payload_va_end);
  const u64 extra_file = utils::page_align(F + payload_file_end);
  logging::debug("layout: file base F=0x{:x}, extra file=0x{:x}, extra va=0x{:x}",
             F, extra_file, extra_va);

  // map every payload LOAD segment, preserving p_offset/p_vaddr congruence
  for (std::size_t i = 0; i < ploads.size(); ++i) {
    auto &p = phdrs[host_phnum + i];
    p.p_offset = F + ploads[i].p_offset;
    p.p_vaddr = B + ploads[i].p_vaddr;
    p.p_paddr = B + ploads[i].p_vaddr;
    p.p_filesz = ploads[i].p_filesz;
    p.p_memsz = ploads[i].p_memsz;
    p.p_flags = ploads[i].p_flags;
  }

  // lay out the extra segment (shellcode + tables + phdrs)
  struct Blob {
    u64 align;
    std::span<const u8> data;
    u64 off = 0;
  };
  std::vector<u8> phdr_bytes(phdrs.size() * sizeof(Elf64_Phdr));
  std::array<Blob, 8> blobs = {
      Blob{1, shellcode},    Blob{8, dynsym_bytes}, Blob{1, im.dynstr},
      Blob{2, versym_bytes}, Blob{8, im.gnuhash},   Blob{8, rela_bytes},
      Blob{8, jmprel_bytes}, Blob{8, phdr_bytes},
  };

  u64 cursor = 0;
  for (auto &b : blobs) {
    cursor = (cursor + b.align - 1) & ~(b.align - 1);
    b.off = cursor;
    cursor += b.data.size();
  }
  const u64 extra_size = cursor;

  phdrs[extra_phdr].p_offset = extra_file;
  phdrs[extra_phdr].p_vaddr = extra_va;
  phdrs[extra_phdr].p_paddr = extra_va;
  phdrs[extra_phdr].p_filesz = extra_size;
  phdrs[extra_phdr].p_memsz = extra_size;
  phdrs[extra_phdr].p_flags = PF_R | PF_X;

  // repoint PT_PHDR to the relocated table
  phdrs[0].p_type = PT_PHDR;
  phdrs[0].p_offset = extra_file + blobs[7].off;
  phdrs[0].p_vaddr = extra_va + blobs[7].off;
  phdrs[0].p_paddr = extra_va + blobs[7].off;
  phdrs[0].p_filesz = phdr_bytes.size();
  phdrs[0].p_memsz = phdr_bytes.size();
  phdrs[0].p_flags = PF_R;
  phdrs[0].p_align = 8;
  std::memcpy(phdr_bytes.data(), phdrs.data(), phdr_bytes.size());

  const u64 dynsym_va = extra_va + blobs[1].off;
  const u64 dynstr_va = extra_va + blobs[2].off;
  const u64 versym_va = extra_va + blobs[3].off;
  const u64 gnuhash_va = extra_va + blobs[4].off;
  const u64 rela_va = extra_va + blobs[5].off;
  const u64 jmprel_va = extra_va + blobs[6].off;

  // assemble output: host intact + grafted payload + extra segment
  std::vector<u8> out(extra_file + extra_size, 0);
  std::memcpy(out.data(), host.fdata(), host.fsize());

  // graft payload segments (use the relocated image)
  for (const auto &ph : payload.phdrs) {
    if (ph.p_type != PT_LOAD) {
      continue;
    }
    std::memcpy(out.data() + F + ph.p_offset, payload_mem.data() + ph.p_vaddr,
                ph.p_filesz);
  }

  // write extra segment blobs
  for (const auto &b : blobs) {
    std::memcpy(out.data() + extra_file + b.off, b.data.data(), b.data.size());
  }

  patch::dynamic(out, host, dynsym_va, dynstr_va, versym_va, gnuhash_va, rela_va,
                 rela_bytes.size(), jmprel_va, jmprel_bytes.size(),
                 im.dynstr.size());

  // header: entry, phnum, phoff
  u64 entry = extra_va;
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_entry), &entry, 8);
  u16 phnum = static_cast<u16>(phdrs.size());
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_phnum), &phnum, 2);
  u64 phoff = extra_file + blobs[7].off;
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_phoff), &phoff, 8);

  patch::build_id(out, host);
  return out;
}

} // namespace build
