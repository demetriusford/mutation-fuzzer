# Compiler and flags
CC = cc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =

# Targets (jpg2bmp, fuzzer)
TARGETS = jpg2bmp fuzzer

# Check for required commands
REQUIRED_CMDS = $(CC)

# Default target
all: check-deps $(TARGETS)
	@echo "==> Build complete!"

# Check if required commands are installed
check-deps:
	@echo "==> Checking for required commands..."
	@command -v $(CC) >/dev/null 2>&1 || { echo "Error: $(CC) is not installed. Please install a C compiler."; exit 1; }

# Build jpg2bmp (requires math library)
jpg2bmp: jpg2bmp.c
	@echo "==> Building jpg2bmp..."
	@$(CC) $(CFLAGS) -o jpg2bmp jpg2bmp.c -lm

# Build fuzzer from main.c
fuzzer: main.c
	@echo "==> Building fuzzer..."
	@$(CC) $(CFLAGS) -o fuzzer main.c $(LDFLAGS)

# Debug builds with DEBUG flag enabled
debug: CFLAGS += -g -DDEBUG
debug: clean all

# Clean build artifacts
clean:
	rm -f $(TARGETS)

# Phony targets
.PHONY: all clean debug check-deps
