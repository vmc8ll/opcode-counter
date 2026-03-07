#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <capstone/capstone.h>

int main(int argc, char **argv) {
    csh handle;
    cs_insn *insn;
    size_t count, i;
    uint8_t *buffer;
    FILE *file;

   
    file = fopen(argv[1], "rb");
    if (!file) {
        printf("Не удалось открыть файл: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

   
    buffer = (uint8_t*)malloc(size);
    if (!buffer) {
        printf("Ошибка выделения памяти\n");
        exit(EXIT_FAILURE);
    }

   
    if (fread(buffer, 1, size, file) != size) {
        printf("Не удалось прочитать файл: %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("Не удалось инициализировать Capstone\n");
        exit(EXIT_FAILURE);
    }

    count = cs_disasm(handle, buffer, size, 0x00000000, 0, &insn);
    if (count <= 0) {
        printf("Не были найдены инструкции\n");
        exit(EXIT_FAILURE);
    }

    uint64_t opcode_count = 0;
    for (i = 0; i < count; i++) {
        opcode_count++;
    }

  ы
    printf("Общее количество опкодов: %"PRIu64"\n", opcode_count);

    
    cs_free(insn, count);
    cs_close(&handle);
    free(buffer);

    return 0;
}
