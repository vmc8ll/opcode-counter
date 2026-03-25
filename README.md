# opcode-counter
# Opcode Analyzer

[![C](https://img.shields.io/badge/C-00599C?style=flat&logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Haskell](https://img.shields.io/badge/Haskell-5e5086?style=flat&logo=haskell&logoColor=white)](https://www.haskell.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A dual-language tool for analyzing binary files: detecting CPU architecture, finding cryptographic constants, calculating entropy, and generating opcode statistics.

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Architecture Detection** | Automatically identifies ELF and PE binaries (x86, x64, ARM, ARM64, MIPS) |
| **Entropy Analysis** | Shannon entropy calculation to detect packed/encrypted files |
| **Crypto Constant Finder** | Searches for known cryptographic constants (MD5, SHA, TEA, etc.) |
| **Opcode Statistics** | Instruction type classification and frequency analysis |
| **Top Opcodes** | Lists the most common mnemonics in the binary |
| **Heuristic Analysis** | Detects patterns indicating obfuscation or crypto code |

## 📦 Two Implementations

| Language | Pros | Cons |
|----------|------|------|
| **C** | ⚡ High performance, minimal memory footprint | 🛡️ Manual memory management |
| **Haskell** | 🛡️ Type safety, elegant code, rapid prototyping | 🐌 Slightly slower startup |

## 🔧 Installation

### Prerequisites

**For both versions:**
```bash
# Install Capstone (required for C version)
sudo apt-get install libcapstone-dev  # Debian/Ubuntu
brew install capstone                   # macOS
For Haskell version:
bash

# Install GHC and Cabal
sudo apt-get install ghc cabal-install  # Debian/Ubuntu
brew install ghc cabal-install           # macOS

Build from Source
bash

# Clone the repository
git clone https://github.com/yourusername/opcode-analyzer.git
cd opcode-analyzer

# Build C version
cd c && make && cd ..

# Build Haskell version
cd haskell && cabal build && cd ..

🎯 Usage
C Version
bash

cd c
./opcode-analyzer firmware.bin
./opcode-analyzer firmware.bin --verbose

Haskell Version
bash

cd haskell
cabal run opcode-analyzer -- firmware.bin
cabal run opcode-analyzer -- firmware.bin --verbose
