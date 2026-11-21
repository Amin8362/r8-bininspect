# r8-bininspect

A fast, zero-dependency **C11** binary analyzer for **ELF (Linux/Unix)** and **PE (Windows)** executables, featuring security mitigation checks, per-section Shannon entropy, colorized hex dump, and ASCII string extraction.

[![Download Release](https://img.shields.io/badge/Download-Linux_%26_Windows-A8B9CC?style=for-the-badge&logo=c&logoColor=black)](https://github.com/Amin8362/r8-bininspect/releases/latest)

---

## Features

- **ELF32 & ELF64 Inspector:** Parses headers (Little & Big Endian), program segments, section tables, and checks **PIE**, **NX Stack**, **GNU_RELRO**, and **RWX** segments.
- **PE32 & PE32+ Inspector:** Parses DOS/COFF/Optional headers, subsystems, section permissions, and Windows security flags (**ASLR**, **DEP/NX**, **High-Entropy VA**, **CFG**).
- **Shannon Entropy Analysis:** Calculates whole-file and per-section entropy to flag packed or encrypted binaries (`>= 7.20 bits/byte`).
- **Built-in Hex Viewer & Strings Extractor:** Inspect arbitrary byte ranges (`--hex --offset --len`) and extract printable ASCII strings (`--strings`) without external tools.
- **Memory-Safe Parsing:** All offsets and table sizes are strictly bounds-checked with explicit endian-aware byte readers (zero unaligned casts, zero external libraries).

## Build from Source

```bash
make
./r8-bininspect ./r8-bininspect
