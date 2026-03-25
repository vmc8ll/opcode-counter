makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/usr/include/capstone
LDFLAGS = -lcapstone -lm

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = .

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = opcode-analyzer

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

test: $(TARGET)
	./$(TARGET) ../examples/sample.bin
	./$(TARGET) ../examples/sample.bin --verbose
