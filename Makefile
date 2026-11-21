CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?= -lm
TARGET  ?= r8-bininspect
SRCS    := src/main.c src/elf_parser.c src/pe_parser.c src/hex_view.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRCS) src/common.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

test: $(TARGET)
	./$(TARGET) ./$(TARGET) --hex --len 64

clean:
	rm -f $(TARGET) *.exe
