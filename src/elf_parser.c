#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *elf_osabi_name(uint8_t osabi) {
    switch (osabi) {
        case 0:  return "UNIX - System V";
        case 3:  return "Linux";
        case 6:  return "Solaris";
        case 9:  return "FreeBSD";
        case 12: return "OpenBSD";
        default: return "Other";
    }
}

static const char *elf_type_name(uint16_t type) {
    switch (type) {
        case 0: return "NONE (No file type)";
        case 1: return "REL (Relocatable object)";
        case 2: return "EXEC (Executable file)";
        case 3: return "DYN (Shared object / PIE)";
        case 4: return "CORE (Core file)";
        default: return "Unknown";
    }
}

static const char *elf_machine_name(uint16_t machine) {
    switch (machine) {
        case 3:   return "x86 (IA-32)";
        case 8:   return "MIPS";
        case 40:  return "ARM (32-bit)";
        case 62:  return "x86-64 (AMD64)";
        case 183: return "AArch64 (ARM64)";
        case 243: return "RISC-V";
        default:  return "Other";
    }
}

static const char *elf_ptype_name(uint32_t ptype) {
    switch (ptype) {
        case 0:          return "NULL";
        case 1:          return "LOAD";
        case 2:          return "DYNAMIC";
        case 3:          return "INTERP";
        case 4:          return "NOTE";
        case 6:          return "PHDR";
        case 7:          return "TLS";
        case 0x6474e550: return "GNU_EH_FRAME";
        case 0x6474e551: return "GNU_STACK";
        case 0x6474e552: return "GNU_RELRO";
        case 0x6474e553: return "GNU_PROPERTY";
        default:         return "OTHER";
    }
}

static const char *elf_shtype_name(uint32_t shtype) {
    switch (shtype) {
        case 0:  return "NULL";
        case 1:  return "PROGBITS";
        case 2:  return "SYMTAB";
        case 3:  return "STRTAB";
        case 4:  return "RELA";
        case 5:  return "HASH";
        case 6:  return "DYNAMIC";
        case 7:  return "NOTE";
        case 8:  return "NOBITS";
        case 9:  return "REL";
        case 11: return "DYNSYM";
        case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY";
        default: return "OTHER";
    }
}

static void format_elf_sec_name(const uint8_t *data, size_t size,
                                uint64_t strtab_off, uint64_t strtab_size,
                                uint32_t name_idx, char out[24]) {
    if (strtab_size == 0 || (uint64_t)name_idx >= strtab_size ||
        !in_bounds(size, strtab_off, strtab_size)) {
        snprintf(out, 24, "<idx:%" PRIu32 ">", name_idx);
        return;
    }

    uint64_t start = strtab_off + (uint64_t)name_idx;
    uint64_t max_len = strtab_size - (uint64_t)name_idx;
    size_t pos = 0;

    for (uint64_t i = 0; i < max_len && pos < 23; i++) {
        uint8_t c = data[start + i];
        if (c == '\0') break;
        out[pos++] = isprint((unsigned char)c) ? (char)c : '.';
    }
    out[pos] = '\0';
    if (pos == 0) {
        snprintf(out, 24, "<empty>");
    }
}

int inspect_elf(const uint8_t *data, size_t size, const InspectOptions *opts) {
    const bool c = opts->use_color;

    if (size < 52) {
        fprintf(stderr, "Error: File too small to be a valid ELF binary.\n");
        return 1;
    }

    uint8_t ei_class = data[4];
    uint8_t ei_data = data[5];
    uint8_t ei_osabi = data[7];

    if (ei_class != 1 && ei_class != 2) {
        fprintf(stderr, "Error: Unsupported ELF class (%u).\n", ei_class);
        return 1;
    }
    if (ei_data != 1 && ei_data != 2) {
        fprintf(stderr, "Error: Invalid ELF endianness (%u).\n", ei_data);
        return 1;
    }

    bool is64 = (ei_class == 2);
    bool be = (ei_data == 2);

    if (is64 && size < 64) {
        fprintf(stderr, "Error: Truncated ELF64 header.\n");
        return 1;
    }

    uint16_t e_type = read_u16(data + 16, be);
    uint16_t e_machine = read_u16(data + 18, be);
    uint64_t e_entry, e_phoff, e_shoff;
    uint16_t e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;

    if (is64) {
        e_entry = read_u64(data + 24, be);
        e_phoff = read_u64(data + 32, be);
        e_shoff = read_u64(data + 40, be);
        e_phentsize = read_u16(data + 54, be);
        e_phnum = read_u16(data + 56, be);
        e_shentsize = read_u16(data + 58, be);
        e_shnum = read_u16(data + 60, be);
        e_shstrndx = read_u16(data + 62, be);
    } else {
        e_entry = read_u32(data + 24, be);
        e_phoff = read_u32(data + 28, be);
        e_shoff = read_u32(data + 32, be);
        e_phentsize = read_u16(data + 42, be);
        e_phnum = read_u16(data + 44, be);
        e_shentsize = read_u16(data + 46, be);
        e_shnum = read_u16(data + 48, be);
        e_shstrndx = read_u16(data + 50, be);
    }

    printf("\n%s[ ELF Header ]%s\n", clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
    printf("  Class       : %s\n", is64 ? "ELF64 (64-bit)" : "ELF32 (32-bit)");
    printf("  Endianness  : %s\n", be ? "Big Endian (MSB)" : "Little Endian (LSB)");
    printf("  OS / ABI    : %s (%u)\n", elf_osabi_name(ei_osabi), ei_osabi);
    printf("  Type        : %s\n", elf_type_name(e_type));
    printf("  Architecture: %s (0x%" PRIx16 ")\n", elf_machine_name(e_machine), e_machine);
    printf("  Entry Point : %s0x%" PRIx64 "%s\n",
           clr(c, ANSI_GOLD), e_entry, clr(c, ANSI_RESET));
    printf("  Segments    : %" PRIu16 " (offset 0x%" PRIx64 ")\n", e_phnum, e_phoff);
    printf("  Sections    : %" PRIu16 " (offset 0x%" PRIx64 ")\n", e_shnum, e_shoff);

    bool has_nx_stack = false;
    bool has_exec_stack = false;
    bool has_relro = false;
    bool has_rwx_load = false;

    uint16_t ph_min = is64 ? 56 : 32;
    uint64_t ph_total = (uint64_t)e_phnum * (uint64_t)e_phentsize;

    if (e_phnum > 0 && e_phentsize >= ph_min && in_bounds(size, e_phoff, ph_total)) {
        if (opts->show_segments) {
            printf("\n%s[ Program Headers (Segments) ]%s\n",
                   clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
            printf("  %-13s %-5s %-12s %-18s %-10s %-10s\n",
                   "TYPE", "FLAGS", "OFFSET", "VADDR", "FILESZ", "MEMSZ");
        }

        for (uint16_t i = 0; i < e_phnum; i++) {
            const uint8_t *p = data + e_phoff + (uint64_t)i * (uint64_t)e_phentsize;
            uint32_t p_type = read_u32(p, be);
            uint32_t p_flags;
            uint64_t p_offset, p_vaddr, p_filesz, p_memsz;

            if (is64) {
                p_flags = read_u32(p + 4, be);
                p_offset = read_u64(p + 8, be);
                p_vaddr = read_u64(p + 16, be);
                p_filesz = read_u64(p + 32, be);
                p_memsz = read_u64(p + 40, be);
            } else {
                p_offset = read_u32(p + 4, be);
                p_vaddr = read_u32(p + 8, be);
                p_filesz = read_u32(p + 16, be);
                p_memsz = read_u32(p + 20, be);
                p_flags = read_u32(p + 24, be);
            }

            char fl[4] = {
                (p_flags & 4U) ? 'R' : '-',
                (p_flags & 2U) ? 'W' : '-',
                (p_flags & 1U) ? 'X' : '-',
                '\0'
            };

            if (p_type == 0x6474e551U) {
                if (p_flags & 1U) has_exec_stack = true;
                else has_nx_stack = true;
            }
            if (p_type == 0x6474e552U) has_relro = true;
            if (p_type == 1U && (p_flags & 7U) == 7U) has_rwx_load = true;

            if (opts->show_segments) {
                const char *flag_clr = ((p_flags & 7U) == 7U) ? clr(c, ANSI_RED) : "";
                printf("  %-13s %s%-5s%s 0x%010" PRIx64 " 0x%016" PRIx64 " 0x%08" PRIx64 " 0x%08" PRIx64 "\n",
                       elf_ptype_name(p_type), flag_clr, fl, clr(c, ANSI_RESET),
                       p_offset, p_vaddr, p_filesz, p_memsz);
            }
        }
    }

    printf("\n%s[ Security Summary ]%s\n", clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
    printf("  PIE / DYN   : %s%s%s\n",
           clr(c, e_type == 3 ? ANSI_GREEN : ANSI_GOLD),
           e_type == 3 ? "Enabled (ET_DYN)" : "Disabled / Static",
           clr(c, ANSI_RESET));
    printf("  NX Stack    : %s%s%s\n",
           clr(c, has_exec_stack ? ANSI_RED : (has_nx_stack ? ANSI_GREEN : ANSI_DIM)),
           has_exec_stack ? "WARNING: Executable Stack!" : (has_nx_stack ? "Enabled (Non-Executable)" : "Not specified"),
           clr(c, ANSI_RESET));
    printf("  GNU_RELRO   : %s%s%s\n",
           clr(c, has_relro ? ANSI_GREEN : ANSI_GOLD),
           has_relro ? "Present" : "Not present",
           clr(c, ANSI_RESET));
    if (has_rwx_load) {
        printf("  RWX Segment : %sWARNING: Writable + Executable LOAD segment detected!%s\n",
               clr(c, ANSI_RED), clr(c, ANSI_RESET));
    }

    uint16_t sh_min = is64 ? 64 : 40;
    uint64_t sh_total = (uint64_t)e_shnum * (uint64_t)e_shentsize;

    if (opts->show_sections && e_shnum > 0 && e_shentsize >= sh_min &&
        in_bounds(size, e_shoff, sh_total)) {
        uint64_t strtab_off = 0;
        uint64_t strtab_size = 0;

        if (e_shstrndx < e_shnum) {
            const uint8_t *sp = data + e_shoff + (uint64_t)e_shstrndx * (uint64_t)e_shentsize;
            if (is64) {
                strtab_off = read_u64(sp + 24, be);
                strtab_size = read_u64(sp + 32, be);
            } else {
                strtab_off = read_u32(sp + 16, be);
                strtab_size = read_u32(sp + 20, be);
            }
        }

        printf("\n%s[ Section Headers ]%s\n", clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
        printf("  %-4s %-22s %-11s %-5s %-12s %-10s %-7s\n",
               "IDX", "NAME", "TYPE", "FLAGS", "OFFSET", "SIZE", "ENTROPY");

        for (uint16_t i = 0; i < e_shnum; i++) {
            const uint8_t *s = data + e_shoff + (uint64_t)i * (uint64_t)e_shentsize;
            uint32_t sh_name = read_u32(s, be);
            uint32_t sh_type = read_u32(s + 4, be);
            uint64_t sh_flags, sh_offset, sh_size;

            if (is64) {
                sh_flags = read_u64(s + 8, be);
                sh_offset = read_u64(s + 24, be);
                sh_size = read_u64(s + 32, be);
            } else {
                sh_flags = read_u32(s + 8, be);
                sh_offset = read_u32(s + 16, be);
                sh_size = read_u32(s + 20, be);
            }

            char name[24];
            format_elf_sec_name(data, size, strtab_off, strtab_size, sh_name, name);

            char fl[4] = {
                (sh_flags & 2U) ? 'A' : '-',
                (sh_flags & 1U) ? 'W' : '-',
                (sh_flags & 4U) ? 'X' : '-',
                '\0'
            };

            double ent = 0.0;
            if (sh_type != 8 && sh_size > 0 && in_bounds(size, sh_offset, sh_size)) {
                ent = calc_entropy(data + sh_offset, (size_t)sh_size);
            }

            const char *ent_clr = (ent >= 7.2) ? clr(c, ANSI_RED) : "";
            printf("  %-4" PRIu16 " %-22s %-11s %-5s 0x%010" PRIx64 " 0x%08" PRIx64 " %s%.2f%s\n",
                   i, name, elf_shtype_name(sh_type), fl,
                   sh_offset, sh_size, ent_clr, ent, clr(c, ANSI_RESET));
        }
    }

    return 0;
}
