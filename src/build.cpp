#include "build.hpp"
#include "graft.hpp"
#include "imports.hpp"
#include "log.hpp"
#include "patch.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace build {

using elf::u8;
using elf::u16;
using elf::u32;
using elf::u64;
using elf::s64;
using elf::check;
using elf::dynsym;
using elf::dynsym_count;
using elf::dynsym_name;
using elf::fail;
using elf::merge_verneed;
using elf::sym_index_by_name;
using elf::version_needs;

std::vector<u8> combine(const elf::Image &host, const elf::Image &payload) {
  check(host.eh.e_type == ET_EXEC || host.eh.e_type == ET_DYN,
        "host must be an ET_EXEC or ET_DYN (PIE)");
  check(payload.eh.e_type == ET_DYN, "payload must be a PIE (ET_DYN)");

  // A PIE host is linked at base 0, so its absolute addresses must be rebased
  // before it can be laid out as an ET_EXEC. We relocate it to a fixed base and
  // shift every host absolute value (entry, symbols, relocations, program
  // header VAs) by `bias`. An ET_EXEC host already carries absolute addresses,
  // so its bias is 0 and all of this is a no-op.
  constexpr u64 pie_host_base = 0x400000;
  const bool host_is_pie = host.eh.e_type == ET_DYN;
  const u64 bias = host_is_pie ? pie_host_base : 0;
  const u64 host_base = host.base + bias;

  const u64 host_entry = host.eh.e_entry + bias;
  const u64 B = host_base + host.span; // payload load bias

  // The tool's extra segment starts with an 8-byte writable scratch slot for
  // the resolved pthread_create pointer (got_slot), followed by the payload
  // launcher. It must NOT live in the host's .bss -- doing so overwrites host
  // globals at load time (thunderbird's uptime guard is the last 8 .bss bytes).
  u64 payload_va_end = 0;
  for (const auto &ph : payload.phdrs) {
    if (ph.p_type == PT_LOAD) {
      payload_va_end = std::max(payload_va_end, ph.p_vaddr + ph.p_memsz);
    }
  }
  const u64 extra_va = utils::page_align(B + payload_va_end);
  const u64 got_slot = extra_va;
  const u64 launcher_va = extra_va + 8;

  // Payload constructors: DT_INIT runs directly, each .init_array entry is a
  // function pointer stored at a fixed runtime address.
  const auto pinit = elf::dynamic_tag(payload, DT_INIT);
  const u64 dt_init = pinit ? B + *pinit : 0;
  std::vector<u64> init_slots;
  {
    const auto ia = payload.find(".init_array");
    if (ia >= 0) {
      const auto &sh = payload.shdrs[ia];
      const auto n = sh.sh_size / sizeof(u64);
      for (std::size_t i = 0; i < n; ++i) {
        init_slots.push_back(B + sh.sh_addr + i * sizeof(u64));
      }
    }
  }
  const std::vector<u8> launcher = graft::make_launcher(dt_init, init_slots);
  logging::debug("payload launcher: {} bytes ({} init slots, dt_init={:#x})",
                 launcher.size(), init_slots.size(), dt_init);

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

  const auto hv = version_needs(host);
  const auto pv = version_needs(payload);
  logging::debug("payload version needs: {}", pv);
  logging::debug("host version needs:    {}", hv);

  // Map host version names onto their indices, then assign fresh indices to any
  // payload version the host does not already require (these get appended to the
  // host's .gnu.version_r later).
  std::map<std::string, u16> host_ver;
  u16 next_ver = 1;
  for (const auto &v : hv.list) {
    host_ver[v.name] = v.index;
    next_ver = std::max<u16>(next_ver, static_cast<u16>(v.index + 1));
  }
  std::map<u16, u16> ver_remap; // payload version index -> merged index
  std::vector<elf::VersionNeed> added;
  for (const auto &v : pv.list) {
    const auto it = host_ver.find(v.name);
    if (it != host_ver.end()) {
      ver_remap[v.index] = it->second;
    } else if (ver_remap.find(v.index) == ver_remap.end()) {
      ver_remap[v.index] = next_ver;
      added.push_back({v.file, v.name, next_ver});
      ++next_ver;
    }
  }
  check(next_ver < 0x8000, "too many version needs to merge");

  const auto remap_pver = [&](u16 pver) -> u16 {
    if (pver <= 1 || (pver & 0x8000)) {
      return pver; // local / global / hidden
    }
    const auto it = ver_remap.find(pver);
    check(it != ver_remap.end(), "payload version index not in version map");
    return it->second;
  };

  {
    const auto pc = sym_index_by_name(host, "pthread_create");
    if (pc >= 0) {
      host_pthread = static_cast<u32>(pc);
      logging::debug("host already imports pthread_create at index {}", pc);
    } else {
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
      ns.version = remap_pver(pversym[i]);
      new_syms.push_back(ns);
    }

    // Payload data imports use R_X86_64_COPY, whose symbol is *defined* in the
    // PIE (its st_shndx points at the local copy in .bss). If the host does not
    // import the object at all (e.g. a minimal launcher that never touches
    // stdout), the loop above never sees it. Add it as a fresh undefined symbol
    // so the loader resolves it from the providing library.
    const auto pri = payload.find(".rela.dyn");
    if (pri >= 0) {
      const auto &rsh = payload.shdrs[pri];
      const auto nr = rsh.sh_size / rsh.sh_entsize;
      const auto *prela =
          reinterpret_cast<const Elf64_Rela *>(payload.fdata() + rsh.sh_offset);
      for (std::size_t k = 0; k < nr; ++k) {
        if (ELF64_R_TYPE(prela[k].r_info) != R_X86_64_COPY) {
          continue;
        }
        const u32 psym = ELF64_R_SYM(prela[k].r_info);
        const auto nm = dynsym_name(payload, psym);
        const std::string base(nm.substr(0, nm.find('@')));
        if (base.empty() || sym_index_by_name(host, base) >= 0) {
          continue;
        }
        bool present = false;
        for (const auto &existing : new_syms) {
          if (existing.name == base) {
            present = true;
            break;
          }
        }
        if (present) {
          continue;
        }
        imports::NewSym ns;
        ns.name = base;
        ns.sym = *dynsym(payload, psym);
        ns.sym.st_value = 0;
        ns.sym.st_shndx = SHN_UNDEF;
        ns.version = remap_pver(pversym[psym]);
        logging::debug("host lacks payload COPY import {}, adding", base);
        new_syms.push_back(ns);
      }
    }
  }

  imports::Imports im =
      imports::build_imports(host, new_syms, host_pthread, bias, got_slot);
  logging::debug("imports: {}", im);
  for (const auto &ns : new_syms) {
    logging::debug("new symbol: {}", ns);
  }

  // Merge any payload-only version needs into the host's .gnu.version_r.
  std::vector<u8> verneed_bytes;
  u64 verneed_num = 0;
  if (!added.empty()) {
    verneed_bytes = merge_verneed(host, added, im.dynstr);
    std::size_t p = 0;
    while (p + sizeof(Elf64_Verneed) <= verneed_bytes.size()) {
      const auto *ver =
          reinterpret_cast<const Elf64_Verneed *>(verneed_bytes.data() + p);
      if (ver->vn_version != 1) {
        break;
      }
      ++verneed_num;
      if (ver->vn_next == 0) {
        break;
      }
      p += ver->vn_next;
    }
    logging::debug("appended {} version needs ({} total Verneed records)",
                   added.size(), verneed_num);
  }

  // DT_NEEDED injection: if a payload-only version need names a library the
  // host does not already depend on, the loader will neither load it nor bind
  // the version (it aborts with "needed != NULL"). Append a DT_NEEDED entry and
  // intern its soname into the merged .dynstr.
  std::vector<u64> needed_offsets;
  {
    const auto host_needed = elf::needed_libraries(host);
    std::set<std::string> seen(host_needed.begin(), host_needed.end());
    for (const auto &v : added) {
      if (v.file.empty() || v.file == "ld-linux-x86-64.so.2") {
        continue;
      }
      if (!seen.insert(v.file).second) {
        continue;
      }
      const u32 off = static_cast<u32>(im.dynstr.size());
      im.dynstr.insert(im.dynstr.end(), v.file.begin(), v.file.end());
      im.dynstr.push_back('\0');
      needed_offsets.push_back(off);
      logging::debug("injecting DT_NEEDED {}", v.file);
    }
  }

  graft::PayloadReloc pr;
  std::vector<u8> payload_mem =
      graft::graft_payload(host, payload, im, new_syms, B, launcher_va, pr);
  logging::debug("payload relocations: {}", pr);

  const u64 payload_entry = B + payload.eh.e_entry;
  logging::debug("load bias B=0x{:x}, payload entry=0x{:x}, got slot=0x{:x}", B,
             payload_entry, im.got_slot);
  auto shellcode = graft::make_shellcode(payload_entry, host_entry, im.got_slot);
  logging::debug("shellcode: {} bytes", shellcode.size());

  // merged relocations
  std::vector<Elf64_Rela> merged_rela = im.rela;

  // A PIE host may pack its RELATIVE relocations into DT_RELR instead of
  // .rela.dyn. Expand them into ordinary RELATIVE relocations (rebased by
  // `bias`) and prepend them, so the loader applies them with l_addr == 0.
  if (bias != 0) {
    const auto targets = elf::relr_targets(host);
    std::vector<Elf64_Rela> relr(/*count=*/targets.size());
    for (std::size_t i = 0; i < targets.size(); ++i) {
      u64 addend;
      std::memcpy(&addend, host.vmem.data<u8>() + targets[i], 8);
      relr[i].r_offset = bias + targets[i];
      relr[i].r_info = ELF64_R_INFO(0, R_X86_64_RELATIVE);
      relr[i].r_addend = bias + addend;
    }
    merged_rela.insert(merged_rela.begin(), relr.begin(), relr.end());
    logging::debug("expanded {} DT_RELR relocations", targets.size());
  }

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
      r.r_offset += bias;
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
  if (bias != 0) {
    for (auto &p : phdrs) {
      if (p.p_type == PT_LOAD || p.p_vaddr != 0) {
        p.p_vaddr += bias;
        p.p_paddr += bias;
      }
    }
  }
  // The merged .dynamic is relocated into the extra segment, so PT_DYNAMIC is
  // repointed below. phdrs[0] is repurposed as PT_PHDR, so it must not be the
  // host's PT_DYNAMIC.
  std::size_t dyn_phdr = phdrs.size();
  for (std::size_t i = 0; i < phdrs.size(); ++i) {
    if (phdrs[i].p_type == PT_DYNAMIC) {
      dyn_phdr = i;
      break;
    }
  }
  check(dyn_phdr < phdrs.size() && dyn_phdr != 0, "unsupported PT_DYNAMIC");
  const std::size_t host_phnum = phdrs.size();
  const std::size_t extra_phdr = host_phnum + ploads.size();
  for (std::size_t i = 0; i <= ploads.size(); ++i) {
    Elf64_Phdr p{};
    p.p_type = PT_LOAD;
    p.p_align = 0x1000;
    phdrs.push_back(p);
  }

  const u64 F = utils::page_align(host.fsize());

  // payload file footprint (extra_va was computed alongside B above)
  u64 payload_file_end = 0;
  for (const auto &ph : ploads) {
    payload_file_end = std::max(payload_file_end, ph.p_offset + ph.p_filesz);
  }

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

  // lay out the extra segment (GOT slot + launcher + shellcode + tables + phdrs)
  struct Blob {
    u64 align;
    std::span<const u8> data;
    u64 off = 0;
  };
  std::vector<u8> got_slot_bytes(8, 0);
  std::vector<u8> phdr_bytes(phdrs.size() * sizeof(Elf64_Phdr));

  // Reserve room for the relocated .dynamic: host entries, an optional
  // synthesized DT_FLAGS, the injected DT_NEEDED entries, and DT_NULL. The
  // actual bytes are filled in once the merged table VAs are known; any slack
  // is zero (= DT_NULL) and harmless.
  std::size_t host_dyn_entries = 0;
  {
    const auto di = host.find(".dynamic");
    check(di >= 0, "no .dynamic");
    const u8 *p = host.fdata() + host.shdrs[di].sh_offset;
    const u8 *e = p + host.shdrs[di].sh_size;
    while (p + 16 <= e) {
      s64 tag;
      std::memcpy(&tag, p, 8);
      if (tag == DT_NULL) {
        break;
      }
      ++host_dyn_entries;
      p += 16;
    }
  }
  std::vector<u8> dyn_bytes(
      (host_dyn_entries + 1 + needed_offsets.size() + 1) * sizeof(Elf64_Dyn),
      0);

  std::array<Blob, 12> blobs = {
      Blob{8, got_slot_bytes}, Blob{1, launcher},   Blob{1, shellcode},
      Blob{8, dynsym_bytes},   Blob{1, im.dynstr},  Blob{2, versym_bytes},
      Blob{8, im.gnuhash},     Blob{8, rela_bytes}, Blob{8, jmprel_bytes},
      Blob{8, phdr_bytes},     Blob{8, verneed_bytes}, Blob{8, dyn_bytes},
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
  // writable: the loader applies the pthread_create GLOB_DAT to got_slot here
  phdrs[extra_phdr].p_flags = PF_R | PF_W | PF_X;

  // repoint PT_PHDR to the relocated table
  phdrs[0].p_type = PT_PHDR;
  phdrs[0].p_offset = extra_file + blobs[9].off;
  phdrs[0].p_vaddr = extra_va + blobs[9].off;
  phdrs[0].p_paddr = extra_va + blobs[9].off;
  phdrs[0].p_filesz = phdr_bytes.size();
  phdrs[0].p_memsz = phdr_bytes.size();
  phdrs[0].p_flags = PF_R;
  phdrs[0].p_align = 8;

  // repoint PT_DYNAMIC at the relocated merged table
  phdrs[dyn_phdr].p_offset = extra_file + blobs[11].off;
  phdrs[dyn_phdr].p_vaddr = extra_va + blobs[11].off;
  phdrs[dyn_phdr].p_paddr = extra_va + blobs[11].off;
  phdrs[dyn_phdr].p_filesz = dyn_bytes.size();
  phdrs[dyn_phdr].p_memsz = dyn_bytes.size();
  phdrs[dyn_phdr].p_flags = PF_R | PF_W;
  phdrs[dyn_phdr].p_align = 8;

  std::memcpy(phdr_bytes.data(), phdrs.data(), phdr_bytes.size());

  const u64 dynsym_va = extra_va + blobs[3].off;
  const u64 dynstr_va = extra_va + blobs[4].off;
  const u64 versym_va = extra_va + blobs[5].off;
  const u64 gnuhash_va = extra_va + blobs[6].off;
  const u64 rela_va = extra_va + blobs[7].off;
  const u64 jmprel_va = extra_va + blobs[8].off;
  const u64 verneed_va = verneed_bytes.empty() ? 0 : extra_va + blobs[10].off;

  // Build the merged .dynamic now that every referenced VA is known, and copy
  // it into the reserved blob.
  {
    const auto merged_dyn = patch::dynamic(
        host, dynsym_va, dynstr_va, versym_va, gnuhash_va, rela_va,
        rela_bytes.size(), jmprel_va, jmprel_bytes.size(), im.dynstr.size(),
        bias, verneed_va, verneed_num, needed_offsets);
    check(merged_dyn.size() <= dyn_bytes.size(), ".dynamic blob overflow");
    std::memcpy(dyn_bytes.data(), merged_dyn.data(), merged_dyn.size());
  }

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

  // Point the section headers of the merged tables at their relocated copies,
  // otherwise readelf-style tooling reads the stale host tables (the loader
  // only uses the dynamic tags, so this is purely for tooling).
  const auto repoint_section = [&](std::string_view name, u64 blob_off,
                                   std::size_t size) {
    const auto idx = host.find(name);
    if (idx < 0) {
      return;
    }
    const std::size_t o =
        host.eh.e_shoff + static_cast<std::size_t>(idx) * host.eh.e_shentsize;
    Elf64_Shdr sh{};
    std::memcpy(&sh, out.data() + o, sizeof(sh));
    sh.sh_offset = extra_file + blob_off;
    sh.sh_addr = extra_va + blob_off;
    sh.sh_size = size;
    std::memcpy(out.data() + o, &sh, sizeof(sh));
  };
  repoint_section(".dynamic", blobs[11].off, dyn_bytes.size());
  repoint_section(".dynstr", blobs[4].off, im.dynstr.size());
  repoint_section(".dynsym", blobs[3].off, dynsym_bytes.size());
  repoint_section(".gnu.version", blobs[5].off, versym_bytes.size());
  repoint_section(".gnu.hash", blobs[6].off, im.gnuhash.size());
  repoint_section(".rela.dyn", blobs[7].off, rela_bytes.size());
  repoint_section(".rela.plt", blobs[8].off, jmprel_bytes.size());
  if (!verneed_bytes.empty()) {
    repoint_section(".gnu.version_r", blobs[10].off, verneed_bytes.size());
  }

  // header: type, entry, phnum, phoff
  const u16 etype = ET_EXEC;
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_type), &etype, 2);
  u64 entry = extra_va + blobs[2].off; // shellcode, after the GOT slot + launcher
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_entry), &entry, 8);
  u16 phnum = static_cast<u16>(phdrs.size());
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_phnum), &phnum, 2);
  u64 phoff = extra_file + blobs[9].off;
  std::memcpy(out.data() + offsetof(Elf64_Ehdr, e_phoff), &phoff, 8);

  patch::build_id(out, host);
  return out;
}

} // namespace build
