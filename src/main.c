#include "common.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE_BYTES (256UL * 1024UL * 1024UL)

static void print_usage(const char *prog) {
    printf("r8-bininspect v%s — Fast ELF/PE Binary Inspector & Hex Viewer (R8Force)\n\n",
           R8_BININSPECT_VERSION);
    printf("Usage:\n");
    printf("  %s <file> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -x, --hex            Print hex + ASCII dump (default: 256 bytes)\n");
    printf("      --offset <num>   Start offset for hex dump (dec or 0x hex)\n");
    printf("      --len <num>      Byte count for hex dump (0 = until EOF)\n");
    printf("  -s, --strings        Extract printable ASCII strings\n");
    printf("      --min-str <num>  Minimum string length (default: 4)\n");
    printf("      --no-sections    Hide section table\n");
    printf("      --no-segments    Hide ELF program headers\n");
    printf("      --no-color       Disable ANSI terminal colors\n");
    printf("  -v, --version        Show version\n");
    printf("  -h, --help           Show this help message\n");
}

static bool parse_size_arg(const char *arg, size_t *out) {
    if (!arg || *arg == '\0' || *arg == '-') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long val = strtoull(arg, &end, 0);
    if (errno != 0 || end == arg || *end != '\0') return false;
    *out = (size_t)val;
    return true;
}

static uint8_t *load_file_bytes(const char *path, size_t *out_size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("Error opening file");
        return NULL;
    }

    size_t cap = 65536;
    size_t len = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "Error: Out of memory.\n");
        return NULL;
    }

    for (;;) {
        if (len == cap) {
            if (cap >= MAX_FILE_BYTES) {
                fprintf(stderr, "Error: File exceeds 256 MB safety limit.\n");
                free(buf);
                fclose(fp);
                return NULL;
            }
            size_t next_cap = cap * 2;
            if (next_cap > MAX_FILE_BYTES) next_cap = MAX_FILE_BYTES;
            uint8_t *tmp = (uint8_t *)realloc(buf, next_cap);
            if (!tmp) {
                fprintf(stderr, "Error: Out of memory while reading file.\n");
                free(buf);
                fclose(fp);
                return NULL;
            }
            buf = tmp;
            cap = next_cap;
        }

        size_t n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (n == 0) {
            if (ferror(fp)) {
                perror("Error reading file");
                free(buf);
                fclose(fp);
                return NULL;
            }
            break;
        }
    }

    fclose(fp);
    *out_size = len;
    return buf;
}

static const char *detect_format(const uint8_t *data, size_t size, int *kind) {
    if (size >= 4 && data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F') {
        *kind = 1;
        return "ELF (Linux / Unix Executable)";
    }
    if (size >= 2 && data[0] == 'M' && data[1] == 'Z') {
        *kind = 2;
        return "PE / MZ (Windows Executable)";
    }
    if (size >= 4) {
        uint32_t m = read_u32_be(data);
        if (m == 0xFEEDFACEU || m == 0xFEEDFACFU ||
            m == 0xCEFAEDFEU || m == 0xCFFAEDFEU) {
            *kind = 3;
            return "Mach-O (macOS / iOS Binary)";
        }
    }
    *kind = 0;
    return "Raw / Unknown Binary";
}

int main(int argc, char **argv) {
    InspectOptions opts = {
        .use_color = true,
        .show_sections = true,
        .show_segments = true,
        .show_hex = false,
        .show_strings = false,
        .hex_offset = 0,
        .hex_length = 256,
        .min_string_len = 4
    };

    const char *file_path = NULL;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--version") == 0) {
            printf("r8-bininspect %s (R8Force)\n", R8_BININSPECT_VERSION);
            return 0;
        } else if (strcmp(arg, "-x") == 0 || strcmp(arg, "--hex") == 0) {
            opts.show_hex = true;
        } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--strings") == 0) {
            opts.show_strings = true;
        } else if (strcmp(arg, "--no-sections") == 0) {
            opts.show_sections = false;
        } else if (strcmp(arg, "--no-segments") == 0) {
            opts.show_segments = false;
        } else if (strcmp(arg, "--no-color") == 0) {
            opts.use_color = false;
        } else if (strcmp(arg, "--offset") == 0) {
            if (i + 1 >= argc || !parse_size_arg(argv[++i], &opts.hex_offset)) {
                fprintf(stderr, "Error: Invalid value for --offset.\n");
                return 1;
            }
            opts.show_hex = true;
        } else if (strcmp(arg, "--len") == 0) {
            if (i + 1 >= argc || !parse_size_arg(argv[++i], &opts.hex_length)) {
                fprintf(stderr, "Error: Invalid value for --len.\n");
                return 1;
            }
            opts.show_hex = true;
        } else if (strcmp(arg, "--min-str") == 0) {
            if (i + 1 >= argc || !parse_size_arg(argv[++i], &opts.min_string_len)) {
                fprintf(stderr, "Error: Invalid value for --min-str.\n");
                return 1;
            }
            opts.show_strings = true;
        } else if (arg[0] == '-') {
            fprintf(stderr, "Error: Unknown option '%s'. Use --help.\n", arg);
            return 1;
        } else if (!file_path) {
            file_path = arg;
        } else {
            fprintf(stderr, "Error: Unexpected argument '%s'.\n", arg);
            return 1;
        }
    }

    if (!file_path) {
        print_usage(argv[0]);
        return 1;
    }

    size_t size = 0;
    uint8_t *data = load_file_bytes(file_path, &size);
    if (!data) return 1;

    int kind = 0;
    const char *fmt_name = detect_format(data, size, &kind);
    double entropy = calc_entropy(data, size);
    uint64_t hash = fnv1a_64(data, size);
    const bool c = opts.use_color;

    printf("%s==================================================%s\n",
           clr(c, ANSI_DIM), clr(c, ANSI_RESET));
    printf(" %sR8Force Binary Inspector%s v%s\n",
           clr(c, ANSI_BOLD), clr(c, ANSI_RESET), R8_BININSPECT_VERSION);
    printf("%s==================================================%s\n",
           clr(c, ANSI_DIM), clr(c, ANSI_RESET));
    printf("  File        : %s\n", file_path);
    printf("  Size        : %" PRIu64 " bytes (0x%" PRIx64 ")\n",
           (uint64_t)size, (uint64_t)size);
    printf("  Format      : %s%s%s\n",
           clr(c, ANSI_GOLD), fmt_name, clr(c, ANSI_RESET));
    printf("  FNV-1a 64   : 0x%016" PRIx64 "\n", hash);
    printf("  Entropy     : %s%.4f bits/byte%s%s\n",
           clr(c, entropy >= 7.2 ? ANSI_RED : ANSI_GREEN),
           entropy,
           clr(c, ANSI_RESET),
           entropy >= 7.2 ? " (high: possibly packed/encrypted)" : "");

    int rc = 0;
    if (kind == 1) {
        rc = inspect_elf(data, size, &opts);
    } else if (kind == 2) {
        rc = inspect_pe(data, size, &opts);
    }

    if (opts.show_hex) {
        print_hex_dump(data, size, opts.hex_offset, opts.hex_length, opts.use_color);
    }
    if (opts.show_strings) {
        print_strings(data, size, opts.min_string_len, opts.use_color);
    }

    free(data);
    return rc;
}
