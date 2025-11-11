# Compiler and flags
CC = cc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =

# Targets
TARGETS = jpg2bmp fuzzer

# Check for required commands
REQUIRED_CMDS = $(CC)

# Default target
all: check-deps $(TARGETS)

# Check if required commands are installed
check-deps:
	@echo "Checking for required commands..."
	@command -v $(CC) >/dev/null 2>&1 || { echo "Error: $(CC) is not installed. Please install a C compiler."; exit 1; }
	@echo "All required commands are available."

# Build jpg2bmp (requires math library)
jpg2bmp: jpg2bmp.c
	$(CC) $(CFLAGS) -o jpg2bmp jpg2bmp.c -lm

# Build fuzzer from main.c
fuzzer: main.c
	$(CC) $(CFLAGS) -o fuzzer main.c $(LDFLAGS)

# Debug builds with DEBUG flag enabled
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Clean build artifacts
clean:
	rm -f $(TARGETS)

# Phony targets
.PHONY: all clean debug check-deps
