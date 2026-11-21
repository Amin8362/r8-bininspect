#ifndef R8_BININSPECT_COMMON_H
#define R8_BININSPECT_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define R8_BININSPECT_VERSION "1.0.0"

#define ANSI_RESET "\x1b[0m"
#define ANSI_BOLD  "\x1b[1m"
#define ANSI_CYAN  "\x1b[36m"
#define ANSI_GOLD  "\x1b[33m"
#define ANSI_GREEN "\x1b[32m"
#define ANSI_RED   "\x1b[31m"
#define ANSI_DIM   "\x1b[90m"

typedef struct {
    bool use_color;
    bool show_sections;
    bool show_segments;
    bool show_hex;
    bool show_strings;
    size_t hex_offset;
    size_t hex_length;
    size_t min_string_len;
} InspectOptions;

static inline const char *clr(bool enabled, const char *code) {
    return enabled ? code : "";
}

static inline uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint64_t read_u64_le(const uint8_t *p) {
    return (uint64_t)read_u32_le(p) | ((uint64_t)read_u32_le(p + 4) << 32);
}

static inline uint16_t read_u16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline uint64_t read_u64_be(const uint8_t *p) {
    return ((uint64_t)read_u32_be(p) << 32) | (uint64_t)read_u32_be(p + 4);
}

static inline uint16_t read_u16(const uint8_t *p, bool big_endian) {
    return big_endian ? read_u16_be(p) : read_u16_le(p);
}

static inline uint32_t read_u32(const uint8_t *p, bool big_endian) {
    return big_endian ? read_u32_be(p) : read_u32_le(p);
}

static inline uint64_t read_u64(const uint8_t *p, bool big_endian) {
    return big_endian ? read_u64_be(p) : read_u64_le(p);
}

static inline bool in_bounds(size_t total, uint64_t offset, uint64_t len) {
    if (offset > (uint64_t)total) return false;
    if (len > (uint64_t)total - offset) return false;
    return true;
}

double calc_entropy(const uint8_t *data, size_t len);
uint64_t fnv1a_64(const uint8_t *data, size_t len);
void print_hex_dump(const uint8_t *data, size_t total_size,
                    size_t offset, size_t length, bool use_color);
void print_strings(const uint8_t *data, size_t total_size,
                   size_t min_len, bool use_color);

int inspect_elf(const uint8_t *data, size_t size, const InspectOptions *opts);
int inspect_pe(const uint8_t *data, size_t size, const InspectOptions *opts);

#endif /* R8_BININSPECT_COMMON_H */
