/* Must precede all includes so glibc exposes explicit_bzero() even under
 * a strict -std=c11 build (where _DEFAULT_SOURCE is not auto-defined). */
#define _DEFAULT_SOURCE

/**
 * @author  Demetrius Ford
 * @date    15 November 2020
 * @updated 09 November 2026
 * @brief   Mutation-based test-case generator for security research and testing
 *
 * Reads an input file, applies random byte substitutions to a bounded fraction
 * of its bytes, and writes a single mutated copy to a secure temporary file.
 * This is the mutation engine a fuzzer would drive; it does not itself execute
 * or observe a target. Seeds are reproducible (optional CLI arg + logged) and a
 * sidecar .mutations file records every change for crash triage.
 *
 * Security features: O_NOFOLLOW, zero-init memory, file type validation,
 * atomic temp file creation, fd-based permissioning (no path race), explicit
 * memory clearing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>    /* For variadic functions */
#include <fcntl.h>     /* For open() with O_NOFOLLOW flag */
#include <sys/stat.h>  /* For fchmod() and fstat() */

/** Cryptographically secure random seed source */
#define OS_SOURCE "/dev/urandom"

/** Mutation rate: fraction of file bytes substituted (distinct offsets) */
#define MUTATIONS 0.01

/** Maximum input file size to prevent resource exhaustion (10 MiB) */
#define MAX_BYTES 10485760

/** Output directory for generated files */
#define OUTPUT_DIR "/tmp"

/** Maximum path length to prevent buffer overflow vulnerabilities */
#define MAX_PATH_LEN 4096

/** Message severity levels for diagnostic output */
typedef enum {
    MSG_INFO,      /**< Informational messages */
    MSG_WARNING,   /**< Warning messages for non-fatal issues */
    MSG_ERROR      /**< Error messages for fatal conditions */
} message_level;

/**
 * @brief Output formatted diagnostic message
 * @param level     Severity level of the message
 * @param exit_code Exit code (non-zero terminates program on errors)
 * @param format    Printf-style format string
 */
void message_base(message_level level, unsigned char exit_code, const char* format, ...);

/** Convenience macro for informational messages */
#define info(...) message_base(MSG_INFO, 0, __VA_ARGS__)

/** Convenience macro for warning messages (non-fatal; never exits) */
#define warning(...) message_base(MSG_WARNING, 0, __VA_ARGS__)

/** Convenience macro for error messages with exit code (code != 0 aborts) */
#define error(code, ...) message_base(MSG_ERROR, code, __VA_ARGS__)

/**
 * @brief Retrieve cryptographically secure random seed
 * @return Unsigned integer seed value from /dev/urandom
 */
unsigned int get_seed(void);

/**
 * @brief Create secure temporary file with atomic operations
 * @param path_out Buffer to receive generated file path
 * @param path_len Size of path_out buffer
 * @return File pointer to created temporary file, NULL on failure
 */
FILE* temp_file(char* path_out, size_t path_len);

/**
 * @brief Determine file size and validate file type
 * @param fd Open file descriptor
 * @return File size in bytes, -1 on error, 0 for empty files
 */
long int file_size(int fd);

/**
 * @brief Perform mutation on buffer and write to temporary file
 * @param buffer      Input buffer containing file data
 * @param size        Size of buffer in bytes
 * @param output_path Buffer to receive output file path
 * @param seed        Seed in effect (recorded in the mutation log)
 */
void mutate(uint8_t* buffer, size_t size, char* output_path, unsigned int seed);

/**
 * @brief Validate file path for basic sanity checks
 * @param path File path to validate
 * @return 1 if valid, 0 if invalid
 */
int validate_path(const char* path);

/**
 * @brief Securely zero memory, preventing compiler optimization removal
 * @param ptr Pointer to memory to clear
 * @param len Number of bytes to zero
 */
void secure_memset(void* ptr, size_t len);

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        error(2, "usage: fuzzer <file> [seed]");
    }

    if (!validate_path(argv[1])) {
        error(1, "invalid file path.");
    }

    /* Open with O_NOFOLLOW to reject symlinks, preventing unauthorized access
     * to system files. O_CLOEXEC prevents descriptor leaks to child processes. */
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

    if (fd == -1) {
        error(1, "target does not exist or is a symlink.");
    }

    long int bytes = file_size(fd);

    if (bytes <= 0) {
        close(fd);
        if (bytes == 0) {
            error(1, "can't fuzz empty file.");
        } else {
            error(1, "failed to determine file size.");
        }
    }

    /* Enforce 10 MiB limit to prevent memory exhaustion and DoS attacks.
     * file_size() no longer folds this into its -1, so this branch now
     * reports the real cause instead of "failed to determine file size." */
    if (bytes > MAX_BYTES) {
        close(fd);
        error(1, "target > 10 megabytes.");
    }

    /* Use calloc() for zero-initialization to prevent information leakage
     * through uninitialized memory (similar to Heartbleed vulnerability) */
    uint8_t* buffer = (uint8_t*) calloc(bytes, sizeof(uint8_t));

    if (buffer == NULL) {
        close(fd);
        error(1, "memory not accessible.");
    }

    ssize_t size = read(fd, buffer, bytes);

    if (size != bytes) {
        if (size < 0) {
            warning("failed to read file.");  /* non-fatal: real exit is below */
        } else {
            warning("read %zd bytes, expected %ld", size, bytes);
        }
        secure_memset(buffer, bytes);
        free(buffer);
        close(fd);
        error(1, "file read incomplete.");
    }

    close(fd);

    /* Reproducible seeding: take an explicit seed if given, else draw a secure
     * one. Either way the seed is logged so a crashing mutant can be regenerated
     * with: fuzzer <file> <seed> */
    unsigned int seed = (argc == 3)
        ? (unsigned int) strtoul(argv[2], NULL, 10)
        : get_seed();
    srand(seed);
    info("seed: %u", seed);

    char output_path[MAX_PATH_LEN];
    mutate(buffer, size, output_path, seed);

    printf("Mutated file created: %s\n", output_path);

    /* Clear sensitive data from memory before deallocation. Uses secure_memset()
     * instead of memset() to prevent dead store elimination - compilers with
     * -O2/-O3 can remove regular memset() calls before free() as "dead code" */
    secure_memset(buffer, size);
    free(buffer);

    return 0;
}

void message_base(message_level level, unsigned char exit_code, const char* format, ...) {
    const char* prefix;
    FILE* stream;
    va_list args;

    switch(level) {
        case MSG_INFO:
            prefix = "Info";
            stream = stdout;
            break;
        case MSG_WARNING:
            prefix = "Warning";
            stream = stderr;
            break;
        case MSG_ERROR:
            prefix = "Error";
            stream = stderr;
            break;
        default:
            prefix = "Message";
            stream = stdout;
            break;
    }

    fprintf(stream, "%s: ", prefix);

    va_start(args, format);
    vfprintf(stream, format, args);
    va_end(args);

    fprintf(stream, "\n");

    if (level == MSG_ERROR && exit_code != 0) {
        exit(exit_code);
    }
}

unsigned int get_seed(void) {
    FILE* file = fopen(OS_SOURCE, "rb");
    unsigned int seed = 0;

    if (file == NULL) {
        error(1, "random device not found.");
    }

    size_t bytes_read = fread(&seed, sizeof(seed), 1, file);
    fclose(file);

    if (bytes_read != 1) {
        error(1, "failed to read random seed.");
    }

    return seed;
}

/**
 * Create secure temporary file using mkstemp() for atomic creation with
 * unpredictable names and owner-only permissions (0600), preventing TOCTOU
 * race conditions and symlink attacks inherent in tmpnam()/tempnam().
 */
FILE* temp_file(char* path_out, size_t path_len) {
    FILE* file = NULL;
    int fd = -1;

    /* Build the template from OUTPUT_DIR rather than hardcoding /tmp. */
    char temp_scheme[MAX_PATH_LEN];
    int n = snprintf(temp_scheme, sizeof(temp_scheme), "%s/fuzz_XXXXXX", OUTPUT_DIR);
    if (n < 0 || (size_t)n >= sizeof(temp_scheme)) {
        error(1, "failed to build temp path.");
    }

    /* mkstemp() atomically creates file with O_EXCL and secure permissions */
    fd = mkstemp(temp_scheme);

    if (fd == -1) {
        error(1, "mkstemp call returned -1.");
    }

    if (path_out != NULL && path_len > 0) {
        strncpy(path_out, temp_scheme, path_len - 1);
        path_out[path_len - 1] = '\0';
    }

    file = fdopen(fd, "wb");

    if (file == NULL) {
        close(fd);
        unlink(temp_scheme);
        error(1, "temporary file not found.");
    }

    return file;
}

/**
 * Retrieve file size via fstat() and validate it's a regular file.
 * Rejects special files (devices, FIFOs, sockets) to prevent DoS attacks
 * from infinite reads or blocking operations. The MAX_BYTES cap is enforced
 * by the caller so it can report that specific cause.
 */
long int file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) != 0) {
        return -1;
    }

    /* Only accept regular files - reject devices, FIFOs, etc. that could
     * cause infinite reads (/dev/zero) or blocking (/dev/random, pipes) */
    if (!S_ISREG(st.st_mode)) {
        warning("target is not a regular file.");  /* non-fatal; caller handles -1 */
        return -1;
    }

    if (st.st_size < 0) {
        return -1;
    }

    return st.st_size;
}

/**
 * Draw a wide random value by packing three 15-bit rand() results into 45 bits.
 * rand() is only guaranteed to span [0, 32767], so a single call cannot address
 * past byte 32767 of a larger file. uint64_t (not long) because long is 32-bit
 * on LLP64 and would drop the high bits.
 *
 * Two draws (30 bits) already cover the 10 MiB cap, which needs 24. The third is
 * deliberate margin: it makes rand_index's modulo bias negligible (raw range far
 * larger than the bound) and leaves headroom if MAX_BYTES is ever raised past a
 * gigabyte. The extra rand() call is trivial.
 */
static uint64_t rand_bits(void) {
    uint64_t bits = 0;
    for (int i = 0; i < 3; i++) {
        bits = (bits << 15) | ((uint64_t)rand() & 0x7FFFu);
    }
    return bits;
}

/** Uniform-enough index in [0, bound); modulo bias is negligible since bound << 2^45. */
static size_t rand_index(size_t bound) {
    return (size_t)(rand_bits() % (uint64_t)bound);
}

/**
 * Apply `count` = max(1, MUTATIONS * size) byte substitutions to the buffer and
 * persist it to a secure temporary file. Offsets are distinct (tracked with a
 * bitmap) and every write is effective (the replacement always differs from the
 * original), so the realized number of changed bytes equals `count`. Each change
 * is recorded in a "<path>.mutations" sidecar for crash triage.
 */
void mutate(uint8_t* buffer, size_t size, char* output_path, unsigned int seed) {
    char path[MAX_PATH_LEN];
    FILE* candidate = temp_file(path, sizeof(path));

    unsigned int count = (unsigned int)(MUTATIONS * size);
    if (count == 0) {
        count = 1;   /* floor: files < 100 bytes would otherwise get 0 mutations */
    }

    /* One bit per byte so each offset is mutated at most once; this makes the
     * realized change count match `count` instead of being eroded by collisions. */
    uint8_t* visited = (uint8_t*) calloc((size + 7) / 8, 1);
    if (visited == NULL) {
        fclose(candidate);
        unlink(path);
        error(1, "memory not accessible for mutation map.");
    }

    /* Sidecar log of every change (offset, original, replacement). Non-fatal if
     * it can't be opened - the mutant is still produced. */
    char log_path[MAX_PATH_LEN];
    int path_len = snprintf(log_path, sizeof(log_path), "%s.mutations", path);
    FILE* log = (path_len > 0 && (size_t)path_len < sizeof(log_path)) ? fopen(log_path, "w") : NULL;
    if (log != NULL) {
        fprintf(log, "# seed=%u size=%zu count=%u\n", seed, size, count);
        fprintf(log, "offset,original,replacement\n");
    }

    unsigned int applied = 0;
    while (applied < count) {
        size_t index = rand_index(size);
        if (visited[index >> 3] & (1u << (index & 7))) {
            continue;                        /* offset already mutated */
        }

        uint8_t original = buffer[index];
        uint8_t replacement;
        do {
            replacement = (uint8_t)(rand() & 0xFF);
        } while (replacement == original);  /* never a no-op write */

        buffer[index] = replacement;
        visited[index >> 3] |= (1u << (index & 7));
        applied++;

        if (log != NULL) {
            fprintf(log, "%zu,0x%02X,0x%02X\n", index, original, replacement);
        }
    }

    free(visited);
    if (log != NULL) {
        fclose(log);
    }

    size_t written = fwrite(buffer, 1, size, candidate);

    if (written != size) {
        fclose(candidate);
        unlink(path);
        error(1, "failed to write mutated file.");
    }

    /* Ensure data reaches physical disk before continuing, preventing loss
     * from power failure or cache inconsistencies in automated pipelines */
    fflush(candidate);
    int fd = fileno(candidate);

    if (fsync(fd) != 0) {
        fclose(candidate);
        unlink(path);
        error(1, "failed to sync file to disk.");
    }

    /* Operate on the open descriptor, not the path. Doing a path-based chmod
     * here would reintroduce exactly the TOCTOU window mkstemp() was chosen to
     * avoid. fchmod() targets the fd and cannot be raced. */
    if (fchmod(fd, 0600) != 0) {
        fclose(candidate);
        unlink(path);
        error(1, "permission setting failed - file removed.");
    }

    /* A failed close can mean data never flushed; treat it as fatal for a tool
     * whose output must be trustworthy. */
    if (fclose(candidate) != 0) {
        unlink(path);
        error(1, "failed to close output file.");
    }

    strncpy(output_path, path, MAX_PATH_LEN - 1);
    output_path[MAX_PATH_LEN - 1] = '\0';
}

/**
 * Validate file path for basic integrity requirements.
 */
int validate_path(const char* path) {
    if (path == NULL || strlen(path) == 0) {
        return 0;
    }

    if (strlen(path) >= MAX_PATH_LEN) {
        return 0;
    }

    return 1;
}

/**
 * Securely zeroes memory in a way that prevents dead store elimination (DSE),
 * an optimization where compilers remove "unnecessary" writes to memory that
 * won't be read again.
 *
 * Standard memset() before free() can be optimized away under -O2/-O3, which
 * C11 explicitly permits (§5.1.2.3 footnote, CWE-14). The result is sensitive
 * data left in freed memory, recoverable via heap reuse, core dumps, or memory
 * forensics. explicit_bzero() is guaranteed not to be elided; the volatile-loop
 * fallback forces the writes anywhere that function is unavailable.
 *
 * References:
 * - CWE-14: Compiler Removal of Code to Clear Buffers
 * - "Dead Store Elimination (Still) Considered Harmful" (USENIX Security 2017)
 */
void secure_memset(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }

#if defined(__linux__)
    /* glibc: explicit_bzero() is guaranteed not to be optimized away.
     * Requires _DEFAULT_SOURCE, defined at the top of this file. */
    explicit_bzero(ptr, len);
#else
    /* Portable fallback: volatile pointer prevents dead store elimination.
     * The volatile qualifier tells the compiler the memory could be observed
     * externally, forcing it to perform the write operations. */
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }

    /* Memory barrier to prevent reordering optimizations across this point. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#endif
#endif
}
