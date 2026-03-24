#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <capstone/capstone.h>

typedef struct {
    uint64_t total_instructions;
    uint64_t total_bytes;
    uint64_t data_transfer;
    uint64_t arithmetic;
    uint64_t logic;
    uint64_t control_flow;
    uint64_t comparison;
    uint64_t stack_ops;
    uint64_t string_ops;
    uint64_t other;
} OpcodeStats;

typedef struct {
    char filename[256];
    size_t file_size;
    double entropy;
    int is_packed;
    uint32_t crypto_constants[10];
    int crypto_count;
} FileInfo;

double calculate_entropy(const uint8_t *data, size_t size) {
    if (size == 0) return 0.0;
    
    uint64_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void find_crypto_constants(const uint8_t *data, size_t size, FileInfo *info) {
    const uint32_t constants[] = {
        0x9E3779B9, 0x61C88647, 0x67452301, 0xEFCDAB89, 0x98BADCFE,
        0x10325476, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6,
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F,
        0x9B05688C, 0x1F83D9AB, 0x5BE0CD19, 0x428A2F98, 0x71374491,
        0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
        0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1,
        0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA,
        0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8,
        0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354,
        0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
        0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585,
        0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE,
        0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB,
        0xBEF9A3F7, 0xC67178F2
    };
    
    const int num_constants = sizeof(constants) / sizeof(constants[0]);
    info->crypto_count = 0;
    
    for (size_t i = 0; i < size - 3 && info->crypto_count < 10; i++) {
        uint32_t val = *(uint32_t*)(data + i);
        for (int j = 0; j < num_constants; j++) {
            if (val == constants[j]) {
                info->crypto_constants[info->crypto_count++] = val;
                break;
            }
        }
    }
}

void classify_instruction(cs_insn *insn, OpcodeStats *stats) {
    const char *mnemonic = insn->mnemonic;
    
    if (strstr(mnemonic, "jmp") || strstr(mnemonic, "call") || 
        strstr(mnemonic, "ret") || strstr(mnemonic, "j") ||
        strstr(mnemonic, "loop")) {
        stats->control_flow++;
    }
    else if (strstr(mnemonic, "mov") || strstr(mnemonic, "lea") || 
             strstr(mnemonic, "xchg") || strstr(mnemonic, "cmov")) {
        stats->data_transfer++;
    }
    else if (strstr(mnemonic, "add") || strstr(mnemonic, "sub") || 
             strstr(mnemonic, "mul") || strstr(mnemonic, "div") ||
             strstr(mnemonic, "inc") || strstr(mnemonic, "dec") ||
             strstr(mnemonic, "neg") || strstr(mnemonic, "adc") ||
             strstr(mnemonic, "sbb") || strstr(mnemonic, "imul")) {
        stats->arithmetic++;
    }
    else if (strstr(mnemonic, "and") || strstr(mnemonic, "or") || 
             strstr(mnemonic, "xor") || strstr(mnemonic, "not") ||
             strstr(mnemonic, "shl") || strstr(mnemonic, "shr") ||
             strstr(mnemonic, "rol") || strstr(mnemonic, "ror")) {
        stats->logic++;
    }
    else if (strstr(mnemonic, "cmp") || strstr(mnemonic, "test")) {
        stats->comparison++;
    }
    else if (strstr(mnemonic, "push") || strstr(mnemonic, "pop")) {
        stats->stack_ops++;
    }
    else if (strstr(mnemonic, "movs") || strstr(mnemonic, "stos") || 
             strstr(mnemonic, "lods") || strstr(mnemonic, "scas") ||
             strstr(mnemonic, "cmps")) {
        stats->string_ops++;
    }
    else {
        stats->other++;
    }
}

cs_arch detect_architecture(const uint8_t *data, size_t size, cs_mode *mode) {
    if (size > 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        uint16_t elf_machine = *(uint16_t*)(data + 18);
        
        switch(elf_machine) {
            case 3:
                *mode = CS_MODE_32;
                return CS_ARCH_X86;
            case 62:
                *mode = CS_MODE_64;
                return CS_ARCH_X86;
            case 40:
                *mode = CS_MODE_ARM;
                return CS_ARCH_ARM;
            case 183:
                *mode = CS_MODE_ARM;
                return CS_ARCH_ARM64;
            case 8:
                *mode = CS_MODE_MIPS32;
                return CS_ARCH_MIPS;
            case 10:
                *mode = CS_MODE_PPC32;
                return CS_ARCH_PPC;
            default:
                return CS_ARCH_X86;
        }
    }
    
    if (size > 2 && data[0] == 'M' && data[1] == 'Z') {
        uint32_t pe_offset = *(uint32_t*)(data + 0x3C);
        if (size > pe_offset + 4 && data[pe_offset] == 'P' && data[pe_offset+1] == 'E') {
            uint16_t machine = *(uint16_t*)(data + pe_offset + 4);
            switch(machine) {
                case 0x14C:
                    *mode = CS_MODE_32;
                    return CS_ARCH_X86;
                case 0x8664:
                    *mode = CS_MODE_64;
                    return CS_ARCH_X86;
                case 0x1C0:
                    *mode = CS_MODE_ARM;
                    return CS_ARCH_ARM;
                case 0xAA64:
                    *mode = CS_MODE_ARM;
                    return CS_ARCH_ARM64;
                default:
                    return CS_ARCH_X86;
            }
        }
    }
    
    fprintf(stderr, "Warning: Could not determine architecture, assuming x86_64\n");
    *mode = CS_MODE_64;
    return CS_ARCH_X86;
}

void print_progress(size_t current, size_t total) {
    if (total == 0) return;
    int percent = (current * 100) / total;
    printf("\r[");
    for (int i = 0; i < 50; i++) {
        if (i < percent / 2) printf("=");
        else if (i == percent / 2) printf(">");
        else printf(" ");
    }
    printf("] %d%%", percent);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <binary_file> [--verbose]\n", argv[0]);
        printf("Example: %s firmware.bin --verbose\n", argv[0]);
        return 1;
    }
    
    int verbose = 0;
    if (argc >= 3 && strcmp(argv[2], "--verbose") == 0) {
        verbose = 1;
    }
    
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        printf("Error: Cannot open file: %s\n", argv[1]);
        return 1;
    }
    
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (size == 0) {
        printf("Error: File is empty\n");
        fclose(file);
        return 1;
    }
    
    uint8_t *buffer = (uint8_t*)malloc(size);
    if (!buffer) {
        printf("Error: Memory allocation failed\n");
        fclose(file);
        return 1;
    }
    
    if (fread(buffer, 1, size, file) != size) {
        printf("Error: Failed to read file\n");
        free(buffer);
        fclose(file);
        return 1;
    }
    fclose(file);
    
    printf("\n=== Opcode Analyzer ===\n");
    printf("File: %s\n", argv[1]);
    printf("Size: %zu bytes\n", size);
    
    double entropy = calculate_entropy(buffer, size);
    printf("Entropy: %.2f (max 8.00)\n", entropy);
    if (entropy > 7.5) {
        printf("[!] High entropy detected: file is likely packed or encrypted\n");
    }
    
    FileInfo info;
    strncpy(info.filename, argv[1], 255);
    info.file_size = size;
    info.entropy = entropy;
    find_crypto_constants(buffer, size, &info);
    
    if (info.crypto_count > 0) {
        printf("\n[+] Crypto constants found:\n");
        for (int i = 0; i < info.crypto_count; i++) {
            printf("    0x%08X\n", info.crypto_constants[i]);
        }
    }
    
    cs_arch arch;
    cs_mode mode;
    arch = detect_architecture(buffer, size, &mode);
    
    const char *arch_name = "Unknown";
    if (arch == CS_ARCH_X86 && mode == CS_MODE_32) arch_name = "x86 (32-bit)";
    else if (arch == CS_ARCH_X86 && mode == CS_MODE_64) arch_name = "x86 (64-bit)";
    else if (arch == CS_ARCH_ARM && mode == CS_MODE_ARM) arch_name = "ARM";
    else if (arch == CS_ARCH_ARM64) arch_name = "ARM64";
    else if (arch == CS_ARCH_MIPS) arch_name = "MIPS";
    else if (arch == CS_ARCH_PPC) arch_name = "PowerPC";
    
    printf("\nArchitecture: %s\n", arch_name);
    
    csh handle;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        printf("Error: Failed to initialize Capstone\n");
        free(buffer);
        return 1;
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    cs_insn *insn;
    size_t count = cs_disasm(handle, buffer, size, 0x1000, 0, &insn);
    
    if (count <= 0) {
        printf("\nNo instructions found (file may be data, not code)\n");
        cs_close(&handle);
        free(buffer);
        return 0;
    }
    
    OpcodeStats stats = {0};
    stats.total_instructions = count;
    
    typedef struct {
        char name[16];
        uint64_t count;
    } OpcodeFreq;
    
    OpcodeFreq *opcode_freq = malloc(count * sizeof(OpcodeFreq));
    int unique_opcodes = 0;
    
    printf("\nAnalyzing instructions...\n");
    
    for (size_t i = 0; i < count; i++) {
        if (verbose && i % (count / 100 + 1) == 0) {
            print_progress(i, count);
        }
        
        stats.total_bytes += insn[i].size;
        classify_instruction(&insn[i], &stats);
        
        int found = 0;
        for (int j = 0; j < unique_opcodes; j++) {
            if (strcmp(opcode_freq[j].name, insn[i].mnemonic) == 0) {
                opcode_freq[j].count++;
                found = 1;
                break;
            }
        }
        if (!found && unique_opcodes < count) {
            strncpy(opcode_freq[unique_opcodes].name, insn[i].mnemonic, 15);
            opcode_freq[unique_opcodes].name[15] = '\0';
            opcode_freq[unique_opcodes].count = 1;
            unique_opcodes++;
        }
    }
    
    if (verbose) {
        print_progress(count, count);
        printf("\n");
    }
    
    printf("\n=== Statistics ===\n");
    printf("Total instructions: %"PRIu64"\n", stats.total_instructions);
    printf("Total opcode bytes: %"PRIu64"\n", stats.total_bytes);
    printf("Average instruction length: %.2f bytes\n", 
           (double)stats.total_bytes / stats.total_instructions);
    
    printf("\n=== Instruction Type Distribution ===\n");
    printf("Data transfer (mov, lea, etc):  %8"PRIu64" (%5.1f%%)\n", 
           stats.data_transfer, (double)stats.data_transfer * 100 / stats.total_instructions);
    printf("Arithmetic (add, sub, mul):     %8"PRIu64" (%5.1f%%)\n", 
           stats.arithmetic, (double)stats.arithmetic * 100 / stats.total_instructions);
    printf("Logic (and, or, xor):           %8"PRIu64" (%5.1f%%)\n", 
           stats.logic, (double)stats.logic * 100 / stats.total_instructions);
    printf("Control flow (jmp, call, ret):  %8"PRIu64" (%5.1f%%)\n", 
           stats.control_flow, (double)stats.control_flow * 100 / stats.total_instructions);
    printf("Comparison (cmp, test):         %8"PRIu64" (%5.1f%%)\n", 
           stats.comparison, (double)stats.comparison * 100 / stats.total_instructions);
    printf("Stack operations (push, pop):   %8"PRIu64" (%5.1f%%)\n", 
           stats.stack_ops, (double)stats.stack_ops * 100 / stats.total_instructions);
    printf("String operations (movs, stos): %8"PRIu64" (%5.1f%%)\n", 
           stats.string_ops, (double)stats.string_ops * 100 / stats.total_instructions);
    printf("Other:                          %8"PRIu64" (%5.1f%%)\n", 
           stats.other, (double)stats.other * 100 / stats.total_instructions);
    
    printf("\n=== Top 10 Opcodes ===\n");
    
    for (int i = 0; i < unique_opcodes - 1; i++) {
        for (int j = i + 1; j < unique_opcodes; j++) {
            if (opcode_freq[i].count < opcode_freq[j].count) {
                OpcodeFreq tmp = opcode_freq[i];
                opcode_freq[i] = opcode_freq[j];
                opcode_freq[j] = tmp;
            }
        }
    }
    
    int top = (unique_opcodes < 10) ? unique_opcodes : 10;
    for (int i = 0; i < top; i++) {
        printf("  %2d. %-10s %8"PRIu64"\n", i+1, opcode_freq[i].name, opcode_freq[i].count);
    }
    
    if (stats.logic > stats.total_instructions * 0.3) {
        printf("\n[!] High percentage of logic operations (XOR, AND, OR)\n");
        printf("    This may indicate cryptographic code or obfuscation\n");
    }
    
    if (stats.control_flow < stats.total_instructions * 0.05) {
        printf("\n[!] Very few control flow instructions\n");
        printf("    Code might be highly linear or obfuscated\n");
    }
    
    free(opcode_freq);
    cs_free(insn, count);
    cs_close(&handle);
    free(buffer);
    
    printf("\n=== Analysis Complete ===\n");
    
    return 0;
}
