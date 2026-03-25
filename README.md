# opcode-counter
# Opcode Analyzer

A dual-language tool for analyzing binary files: detecting CPU architecture, finding cryptographic constants, calculating entropy, and generating opcode statistics.

## Features

- Architecture Detection (ELF/PE)
- Entropy Calculation
- Crypto Constant Finder (MD5, SHA, TEA, etc.)
- Opcode Statistics
- Instruction Classification
- Top Opcodes

## Quick Start

### C Version
```bash
cd c
make
./opcode-analyzer ../examples/sample.bin
