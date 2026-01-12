/**
 * @author  Demetrius Ford
 * @date    15 November 2020
 * @updated 05 November 2025
 * @brief   Mutation-based file fuzzer for security research and testing
 *
 * Performs random byte mutations on input files for authorized penetration
 * testing and vulnerability discovery. Implements security controls to prevent
 * misuse including symlink protection, resource limits, and secure file handling.
 *
 * Security features: O_NOFOLLOW, zero-init memory, file type validation,
 * integer overflow checks, atomic temp file creation, explicit memory clearing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdarg.h>    /* For variadic functions */
#include <fcntl.h>     /* For open() with O_NOFOLLOW flag */
#include <sys/stat.h>  /* For chmod() and fstat() */

/** Cryptographically secure random number generator source */
#define OS_SOURCE "/dev/urandom"

/** Mutation rate: percentage of file bytes subject to modification */
#define MUTATIONS 0.01

/** Maximum input file size to prevent resource exhaustion (10 MiB) */
#define MAX_BYTES 10485760

/** Default output directory for generated files */
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

/** Convenience macro for warning messages */
#define warning(...) message_base(MSG_WARNING, 0, __VA_ARGS__)

/** Convenience macro for error messages with exit code */
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
 */
void mutate(uint8_t* buffer, size_t size, char* output_path);

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
    if (argc != 2) {
        error(2, "usage: fuzzer <file>");
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

    /* Enforce 10 MiB limit to prevent memory exhaustion and DoS attacks */
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
            error(0, "failed to read file.");
        } else {
            warning("read %zd bytes, expected %ld", size, bytes);
        }
        secure_memset(buffer, bytes);
        free(buffer);
        close(fd);
        error(1, "file read incomplete.");
    }

    close(fd);

    /* Initialize PRNG with cryptographically secure seed */
    srand(get_seed());

    char output_path[MAX_PATH_LEN];
    mutate(buffer, size, output_path);

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
    char temp_scheme[] = "/tmp/fuzz_XXXXXX";

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
 * from infinite reads or blocking operations.
 */
long int file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) != 0) {
        return -1;
    }

    /* Only accept regular files - reject devices, FIFOs, etc. that could
     * cause infinite reads (/dev/zero) or blocking (/dev/random, pipes) */
    if (!S_ISREG(st.st_mode)) {
        error(0, "target is not a regular file.");
        return -1;
    }

    if (st.st_size < 0 || st.st_size > MAX_BYTES) {
        return -1;
    }

    return st.st_size;
}

/**
 * Perform mutation operations on input buffer and persist to temporary file.
 * Randomly modifies MUTATIONS percentage of bytes using secure RNG seed.
 */
void mutate(uint8_t* buffer, size_t size, char* output_path) {
    char path[MAX_PATH_LEN];
    FILE* candidate = temp_file(path, sizeof(path));

    /* Prevent integer overflow in mutation calculations that could lead to
     * heap corruption on 32-bit systems or with near-SIZE_MAX inputs */
    if (size > SIZE_MAX / sizeof(unsigned int)) {
        fclose(candidate);
        unlink(path);
        error(1, "file too large for mutation.");
    }

    unsigned int count = (unsigned int)(MUTATIONS * size);

    if (count > size) {
        count = size;
    }

    /* Apply random byte mutations */
    for (size_t i = 0; i < count; i++) {
        size_t index = (size_t)rand() % size;
        buffer[index] = (uint8_t)(rand() % 256);
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

    fclose(candidate);

    /* Enforce owner-only permissions (0600) to prevent information disclosure
     * in multi-user environments. Defense-in-depth despite mkstemp() defaults. */
    if (chmod(path, 0600) != 0) {
        warning("failed to set permissions on %s", path);
        unlink(path);
        error(1, "permission setting failed - file removed.");
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
 * Problem: Standard memset() before free() can be optimized away:
 *
 *   memset(buffer, 0, size);  // Compiler sees this write...
 *   free(buffer);              // ...is never read before deallocation
 *   // Optimizer removes memset() as "dead code"
 *
 * This occurs with -O2/-O3 optimization in GCC/Clang and is explicitly
 * permitted by C11 standard. Result: Sensitive data persists in freed memory,
 * recoverable via heap reuse, core dumps, or memory forensics.
 *
 * Solution: Use platform-specific secure clearing functions or volatile
 * pointers to prevent optimization. The volatile qualifier forces the compiler
 * to perform actual memory writes, as the memory could theoretically be
 * accessed by external observers (hardware, other threads, etc.).
 *
 * References:
 * - C11 Standard §5.1.2.3 footnote 146 (allows DSE optimization)
 * - CWE-14: Compiler Removal of Code to Clear Buffers
 * - "Dead Store Elimination (Still) Considered Harmful" (USENIX Security 2017)
 */
void secure_memset(void* ptr, size_t len) {
    if (ptr == NULL || len == 0) {
        return;
    }

#if defined(__linux__) && defined(_DEFAULT_SOURCE)
    /* Linux/BSD: explicit_bzero() is guaranteed not to be optimized away */
    explicit_bzero(ptr, len);
#elif defined(__STDC_LIB_EXT1__) && defined(__STDC_WANT_LIB_EXT1__)
    /* C11 Annex K: memset_s() with bounds checking (limited platform support) */
    memset_s(ptr, len, 0, len);
#else
    /* Portable fallback: volatile pointer prevents dead store elimination.
     * The volatile qualifier tells the compiler the memory could be observed
     * externally, forcing it to perform the write operations. */
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }

    /* Memory barrier to prevent reordering optimizations across this point.
     * Ensures clearing completes before function returns. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#endif
#endif
}
