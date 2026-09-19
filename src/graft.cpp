#include "graft.hpp"
#include "log.hpp"
#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <map>
#include <string>

namespace graft {

using elf::u8;
using elf::u32;
using elf::u64;
using elf::check;
using elf::dynsym;
using elf::dynsym_count;
using elf::dynsym_name;
using elf::fail;

std::vector<u8> graft_payload(const elf::Image &host, const elf::Image &payload,
                              imports::Imports &im,
                              const std::vector<imports::NewSym> &new_syms,
                              u64 B, u64 launcher_va, PayloadReloc &pr) {
  // base name -> merged dynsym index
  std::map<std::string, u32> sym_map;
  for (std::size_t i = 1; i < dynsym_count(host); ++i) {
    const auto nm = dynsym_name(host, i);
    const auto base = nm.substr(0, nm.find('@'));
    if (!base.empty()) {
      sym_map[std::string(base)] = imports::merge_index(i, im.symoffset, im.count);
    }
  }
  for (std::size_t j = 0; j < new_syms.size(); ++j) {
    sym_map[new_syms[j].name] = im.symoffset + j;
  }

  u64 hi = 0;
  for (const auto &ph : payload.phdrs) {
    if (ph.p_type == PT_LOAD) {
      hi = std::max(hi, ph.p_vaddr + ph.p_memsz);
    }
  }
  const std::size_t span = utils::page_align(hi);
  std::vector<u8> mem(span, 0);
  logging::debug("grafting payload into {} byte image at bias 0x{:x}", span, B);

  for (const auto &ph : payload.phdrs) {
    if (ph.p_type != PT_LOAD) {
      continue;
    }
    std::memcpy(mem.data() + ph.p_vaddr, payload.fdata() + ph.p_offset,
                ph.p_filesz);
  }

  auto apply_rela = [&](std::string_view sec) {
    const auto idx = payload.find(sec);
    check(idx >= 0, std::string("payload missing ") + sec.data());
    const auto &sh = payload.shdrs[idx];
    const auto n = sh.sh_size / sh.sh_entsize;
    const auto *rela =
        reinterpret_cast<const Elf64_Rela *>(payload.fdata() + sh.sh_offset);
    for (std::size_t i = 0; i < n; ++i) {
      const auto &r = rela[i];
      const u32 type = ELF64_R_TYPE(r.r_info);
      const u32 psym = ELF64_R_SYM(r.r_info);
      const u64 target = r.r_offset;

      if (type == R_X86_64_RELATIVE) {
        u64 v = B + r.r_addend;
        std::memcpy(mem.data() + target, &v, 8);
        continue;
      }

      // A COPY relocation always refers to an imported data object. In a PIE its
      // symbol can carry a real st_shndx (pointing at the local .bss copy), so
      // it must be treated as an import before the defined-symbol check below.
      if (type == R_X86_64_COPY) {
        const auto nm = dynsym_name(payload, psym);
        const auto base = std::string(nm.substr(0, nm.find('@')));
        const auto it = sym_map.find(base);
        check(it != sym_map.end(),
              "payload COPY import not in merged symtab: " + base);
        // The host symbol is an ordinary import (e.g. GLOB_DAT) and may carry
        // st_size == 0, while the payload's COPY symbol knows the real object
        // size. Use the larger size so the loader copies the whole object and
        // does not emit "Symbol `X' has different size in shared object".
        const auto *ps = dynsym(payload, psym);
        Elf64_Sym &ms = im.dynsym[it->second];
        ms.st_size = std::max<u64>(ms.st_size, ps->st_size);
        pr.rela_dyn.push_back(
            {B + target, ELF64_R_INFO(it->second, R_X86_64_COPY), 0});
        continue;
      }

      const auto *s = dynsym(payload, psym);
      if (s->st_shndx != SHN_UNDEF) {
        // reference to a symbol defined inside the payload
        if (type == R_X86_64_64) {
          u64 v = B + s->st_value + r.r_addend;
          std::memcpy(mem.data() + target, &v, 8);
          continue;
        }
        fail("unexpected defined-symbol relocation");
      }

      const auto nm = dynsym_name(payload, psym);
      const auto base = std::string(nm.substr(0, nm.find('@')));

      // The payload's `_start` calls `__libc_start_main`, which would re-run
      // the host's constructors (glibc uses the process main map). Point the
      // payload's GOT slot at our launcher instead of the libc symbol.
      if (base == "__libc_start_main") {
        std::memcpy(mem.data() + target, &launcher_va, 8);
        continue;
      }

      const auto it = sym_map.find(base);
      check(it != sym_map.end(),
            "payload import not in merged symtab: " + base);
      const u32 midx = it->second;
      const Elf64_Sym &ms = im.dynsym[midx];
      const bool defined = ms.st_shndx != SHN_UNDEF;

      switch (type) {
      case R_X86_64_64:
        if (defined) {
          u64 v = ms.st_value + r.r_addend;
          std::memcpy(mem.data() + target, &v, 8);
        } else {
          pr.rela_dyn.push_back(
              {B + target, ELF64_R_INFO(midx, R_X86_64_64), r.r_addend});
        }
        break;
      case R_X86_64_GLOB_DAT:
        if (defined) {
          u64 v = ms.st_value;
          std::memcpy(mem.data() + target, &v, 8);
        } else {
          pr.rela_dyn.push_back(
              {B + target, ELF64_R_INFO(midx, R_X86_64_GLOB_DAT), 0});
        }
        break;
      case R_X86_64_JUMP_SLOT:
        pr.rela_plt.push_back(
            {B + target, ELF64_R_INFO(midx, R_X86_64_JUMP_SLOT), 0});
        break;
      default:
        fail("unsupported payload relocation type " + std::to_string(type));
      }
    }
  };

  apply_rela(".rela.dyn");
  apply_rela(".rela.plt");

  return mem;
}

std::vector<u8> make_shellcode(u64 payload_entry, u64 host_entry,
                               u64 got_slot) {
  std::vector<u8> sc;
  const auto push = [&](std::initializer_list<u8> b) {
    sc.insert(sc.end(), b);
  };
  const auto imm64 = [&](u64 v) {
    for (int i = 0; i < 8; ++i) {
      sc.push_back(static_cast<u8>((v >> (8 * i)) & 0xff));
    }
  };

  push({0x48, 0x83, 0xec, 0x10}); // sub rsp, 16
  push({0x48, 0x89, 0xe7});       // mov rdi, rsp
  push({0x31, 0xf6});             // xor esi, esi
  push({0x48, 0xba});             // movabs rdx, payload_entry
  imm64(payload_entry);
  push({0x31, 0xc9}); // xor ecx, ecx
  push({0x48, 0xa1}); // movabs rax, [got_slot]
  imm64(got_slot);
  push({0xff, 0xd0});             // call rax
  push({0x48, 0x83, 0xc4, 0x10}); // add rsp, 16
  push({0x48, 0xb8});             // movabs rax, host_entry
  imm64(host_entry);
  push({0xff, 0xe0}); // jmp rax
  return sc;
}

std::vector<u8> make_launcher(u64 dt_init, const std::vector<u64> &init_slots) {
  std::vector<u8> c;
  const auto push = [&](std::initializer_list<u8> b) {
    c.insert(c.end(), b);
  };
  const auto imm64 = [&](u64 v) {
    for (int i = 0; i < 8; ++i) {
      c.push_back(static_cast<u8>((v >> (8 * i)) & 0xff));
    }
  };

  // prologue: preserve callee-saved regs, keep rsp 16-byte aligned before calls
  push({0x55});                   // push rbp
  push({0x48, 0x89, 0xe5});       // mov rbp, rsp
  push({0x41, 0x54});             // push r12
  push({0x41, 0x55});             // push r13
  push({0x41, 0x56});             // push r14
  push({0x48, 0x83, 0xec, 0x08}); // sub rsp, 8
  push({0x49, 0x89, 0xfc});       // mov r12, rdi   (payload main)
  push({0x49, 0x89, 0xf5});       // mov r13, rsi   (argc)
  push({0x49, 0x89, 0xd6});       // mov r14, rdx   (argv)

  // DT_INIT runs before .init_array
  if (dt_init != 0) {
    push({0x48, 0xb8}); // movabs rax, dt_init
    imm64(dt_init);
    push({0xff, 0xd0}); // call rax
  }

  // each .init_array entry is a function pointer stored at a fixed address
  for (u64 slot : init_slots) {
    push({0x48, 0xb8}); // movabs rax, &slot
    imm64(slot);
    push({0x48, 0x8b, 0x00}); // mov rax, [rax]
    push({0x48, 0x85, 0xc0}); // test rax, rax
    push({0x74, 0x02});       // je +2 (skip the call)
    push({0xff, 0xd0});       // call rax
  }

  push({0x4c, 0x89, 0xef}); // mov rdi, r13
  push({0x4c, 0x89, 0xf6}); // mov rsi, r14
  push({0x31, 0xd2});       // xor edx, edx
  push({0x41, 0xff, 0xd4}); // call r12
  // main returned: never return to _start's `hlt`; park the thread
  push({0xf3, 0x90}); // pause
  push({0xeb, 0xfc}); // jmp back to pause
  return c;
}

} // namespace graft
