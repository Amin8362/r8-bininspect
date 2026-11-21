#include "common.h"

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>

double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;

    size_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    const double total = (double)len;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / total;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

uint64_t fnv1a_64(const uint8_t *data, size_t len) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void print_hex_dump(const uint8_t *data, size_t total_size,
                    size_t offset, size_t length, bool use_color) {
    printf("\n%s[ Hex Dump ]%s\n", clr(use_color, ANSI_CYAN), clr(use_color, ANSI_RESET));

    if (offset >= total_size) {
        printf("  Offset 0x%" PRIx64 " is beyond file size (0x%" PRIx64 ").\n",
               (uint64_t)offset, (uint64_t)total_size);
        return;
    }

    size_t remaining = total_size - offset;
    size_t actual_len = (length == 0 || length > remaining) ? remaining : length;

    for (size_t row = 0; row < actual_len; row += 16) {
        size_t cur = offset + row;
        printf("  %s%08" PRIx64 "%s  ",
               clr(use_color, ANSI_GOLD), (uint64_t)cur, clr(use_color, ANSI_RESET));

        for (size_t col = 0; col < 16; col++) {
            if (col == 8) putchar(' ');
            if (row + col < actual_len) {
                uint8_t b = data[cur + col];
                if (b == 0x00) {
                    printf("%s00%s ", clr(use_color, ANSI_DIM), clr(use_color, ANSI_RESET));
                } else {
                    printf("%02x ", b);
                }
            } else {
                printf("   ");
            }
        }

        printf(" %s|%s", clr(use_color, ANSI_DIM), clr(use_color, ANSI_RESET));
        for (size_t col = 0; col < 16 && (row + col) < actual_len; col++) {
            uint8_t b = data[cur + col];
            if (isprint((unsigned char)b)) {
                printf("%s%c%s", clr(use_color, ANSI_GREEN), (char)b, clr(use_color, ANSI_RESET));
            } else {
                putchar('.');
            }
        }
        printf("%s|%s\n", clr(use_color, ANSI_DIM), clr(use_color, ANSI_RESET));
    }
}

void print_strings(const uint8_t *data, size_t total_size,
                   size_t min_len, bool use_color) {
    if (min_len < 2) min_len = 2;

    printf("\n%s[ Printable ASCII Strings (min length: %" PRIu64 ") ]%s\n",
           clr(use_color, ANSI_CYAN), (uint64_t)min_len, clr(use_color, ANSI_RESET));

    size_t count = 0;
    size_t i = 0;
    while (i < total_size) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) {
            size_t start = i;
            while (i < total_size && data[i] >= 0x20 && data[i] <= 0x7E) {
                i++;
            }
            size_t len = i - start;
            if (len >= min_len) {
                printf("  %s0x%08" PRIx64 "%s  ",
                       clr(use_color, ANSI_GOLD), (uint64_t)start, clr(use_color, ANSI_RESET));
                fwrite(data + start, 1, len, stdout);
                putchar('\n');
                count++;
            }
        } else {
            i++;
        }
    }

    printf("  %sTotal strings found: %" PRIu64 "%s\n",
           clr(use_color, ANSI_DIM), (uint64_t)count, clr(use_color, ANSI_RESET));
}
