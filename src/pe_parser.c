#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>

static const char *pe_machine_name(uint16_t machine) {
    switch (machine) {
        case 0x014c: return "x86 (i386)";
        case 0x8664: return "x86-64 (AMD64)";
        case 0x01c4: return "ARM Thumb-2";
        case 0xaa64: return "ARM64 (AArch64)";
        default:     return "Other";
    }
}

static const char *pe_subsystem_name(uint16_t subsys) {
    switch (subsys) {
        case 1:  return "Native (Driver)";
        case 2:  return "Windows GUI";
        case 3:  return "Windows Console (CUI)";
        case 10: return "EFI Application";
        case 11: return "EFI Boot Service Driver";
        case 12: return "EFI Runtime Driver";
        default: return "Other";
    }
}

int inspect_pe(const uint8_t *data, size_t size, const InspectOptions *opts) {
    const bool c = opts->use_color;

    if (size < 64) {
        fprintf(stderr, "Error: File too small for DOS header.\n");
        return 1;
    }

    uint32_t pe_off = read_u32_le(data + 0x3C);
    if (!in_bounds(size, pe_off, 24)) {
        fprintf(stderr, "Error: Invalid PE header offset (0x%" PRIx32 ").\n", pe_off);
        return 1;
    }

    if (data[pe_off] != 'P' || data[pe_off + 1] != 'E' ||
        data[pe_off + 2] != 0 || data[pe_off + 3] != 0) {
        fprintf(stderr, "Error: Missing PE\\0\\0 signature (DOS-only executable).\n");
        return 1;
    }

    const uint8_t *coff = data + pe_off + 4;
    uint16_t machine = read_u16_le(coff + 0);
    uint16_t num_sections = read_u16_le(coff + 2);
    uint32_t timestamp = read_u32_le(coff + 4);
    uint16_t opt_size = read_u16_le(coff + 16);
    uint16_t characteristics = read_u16_le(coff + 18);

    uint64_t opt_off = (uint64_t)pe_off + 24ULL;
    bool has_opt = (opt_size >= 24 && in_bounds(size, opt_off, opt_size));
    bool is_pe64 = false;
    uint32_t entry_rva = 0;
    uint64_t image_base = 0;
    uint16_t subsystem = 0;
    uint16_t dll_chars = 0;
    bool has_subsys = false;

    if (has_opt) {
        const uint8_t *opt = data + opt_off;
        uint16_t magic = read_u16_le(opt + 0);
        is_pe64 = (magic == 0x020B);
        entry_rva = read_u32_le(opt + 16);

        if (is_pe64 && opt_size >= 32) {
            image_base = read_u64_le(opt + 24);
        } else if (!is_pe64 && opt_size >= 32) {
            image_base = read_u32_le(opt + 28);
        }

        if (opt_size >= 72) {
            subsystem = read_u16_le(opt + 68);
            dll_chars = read_u16_le(opt + 70);
            has_subsys = true;
        }
    }

    printf("\n%s[ PE / COFF Header ]%s\n", clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
    printf("  Format      : %s\n", is_pe64 ? "PE32+ (64-bit Windows)" : "PE32 (32-bit Windows)");
    printf("  Architecture: %s (0x%04" PRIx16 ")\n", pe_machine_name(machine), machine);
    printf("  File Type   : %s\n", (characteristics & 0x2000U) ? "DLL Library" : "Executable (.exe)");
    printf("  Timestamp   : 0x%08" PRIx32 "\n", timestamp);
    printf("  Sections    : %" PRIu16 "\n", num_sections);

    if (has_opt) {
        printf("  Entry RVA   : %s0x%08" PRIx32 "%s\n",
               clr(c, ANSI_GOLD), entry_rva, clr(c, ANSI_RESET));
        printf("  Image Base  : 0x%" PRIx64 "\n", image_base);
    }
    if (has_subsys) {
        printf("  Subsystem   : %s (%" PRIu16 ")\n", pe_subsystem_name(subsystem), subsystem);
    }

    if (has_subsys) {
        bool aslr = (dll_chars & 0x0040U) != 0;
        bool dep = (dll_chars & 0x0100U) != 0;
        bool cfg = (dll_chars & 0x4000U) != 0;
        bool high_ent = (dll_chars & 0x0020U) != 0;

        printf("\n%s[ Security Mitigations ]%s\n", clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
        printf("  ASLR (DynBase) : %s%s%s\n",
               clr(c, aslr ? ANSI_GREEN : ANSI_RED), aslr ? "Enabled" : "Disabled", clr(c, ANSI_RESET));
        printf("  DEP (NX)       : %s%s%s\n",
               clr(c, dep ? ANSI_GREEN : ANSI_RED), dep ? "Enabled" : "Disabled", clr(c, ANSI_RESET));
        printf("  High-Entropy VA: %s%s%s\n",
               clr(c, high_ent ? ANSI_GREEN : ANSI_DIM), high_ent ? "Enabled" : "Off", clr(c, ANSI_RESET));
        printf("  Control Flow G.: %s%s%s\n",
               clr(c, cfg ? ANSI_GREEN : ANSI_DIM), cfg ? "Enabled" : "Off", clr(c, ANSI_RESET));
    }

    uint64_t sec_off = opt_off + (uint64_t)opt_size;
    uint64_t sec_total = (uint64_t)num_sections * 40ULL;

    if (opts->show_sections && num_sections > 0 && in_bounds(size, sec_off, sec_total)) {
        printf("\n%s[ PE Sections ]%s\n", clr(c, ANSI_CYAN), clr(c, ANSI_RESET));
        printf("  %-10s %-6s %-10s %-10s %-10s %-10s %-7s\n",
               "NAME", "PERMS", "VADDR", "VSIZE", "RAW_OFF", "RAW_SIZE", "ENTROPY");

        for (uint16_t i = 0; i < num_sections; i++) {
            const uint8_t *s = data + sec_off + (uint64_t)i * 40ULL;
            char name[9];
            for (int k = 0; k < 8; k++) {
                uint8_t ch = s[k];
                if (ch == 0) {
                    name[k] = '\0';
                    break;
                }
                name[k] = isprint((unsigned char)ch) ? (char)ch : '.';
            }
            name[8] = '\0';

            uint32_t vsize = read_u32_le(s + 8);
            uint32_t vaddr = read_u32_le(s + 12);
            uint32_t raw_size = read_u32_le(s + 16);
            uint32_t raw_off = read_u32_le(s + 20);
            uint32_t schars = read_u32_le(s + 36);

            bool r = (schars & 0x40000000U) != 0;
            bool w = (schars & 0x80000000U) != 0;
            bool x = (schars & 0x20000000U) != 0;
            char perms[4] = {r ? 'R' : '-', w ? 'W' : '-', x ? 'X' : '-', '\0'};

            double ent = 0.0;
            if (raw_size > 0 && in_bounds(size, raw_off, raw_size)) {
                ent = calc_entropy(data + raw_off, (size_t)raw_size);
            }

            const char *p_clr = (r && w && x) ? clr(c, ANSI_RED) : "";
            const char *e_clr = (ent >= 7.2) ? clr(c, ANSI_RED) : "";

            printf("  %-10s %s%-6s%s 0x%08" PRIx32 " 0x%08" PRIx32 " 0x%08" PRIx32 " 0x%08" PRIx32 " %s%.2f%s\n",
                   name, p_clr, perms, clr(c, ANSI_RESET),
                   vaddr, vsize, raw_off, raw_size,
                   e_clr, ent, clr(c, ANSI_RESET));
        }
    }

    return 0;
}
