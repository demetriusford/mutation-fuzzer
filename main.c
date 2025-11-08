/**
 * @author  Demetrius Ford
 * @date    15 November 2020
 * @updated 05 November 2025
 * @brief   Secure file fuzzer for penetration testing and security research
 *
 * @section DESCRIPTION
 *
 * This tool performs mutation-based fuzzing on input files by randomly
 * modifying byte sequences. It is designed for authorized penetration testing,
 * security research, and vulnerability discovery in file parsing implementations.
 *
 * @section SECURITY_FEATURES
 *
 * The implementation incorporates defense-in-depth security controls to prevent
 * misuse and maintain system integrity during fuzzing operations:
 *
 * 1. Symlink Attack Prevention (O_NOFOLLOW)
 *    - Prevents symbolic link traversal to system files
 *    - Mitigates unauthorized access to /etc/passwd, device files, etc.
 *
 * 2. Memory Disclosure Prevention (calloc)
 *    - Zero-initialization of allocated buffers
 *    - Prevents information leakage via uninitialized memory
 *
 * 3. Secure Memory Deallocation
 *    - Explicit memory sanitization before deallocation
 *    - Mitigates memory dump and heap reuse attacks
 *
 * 4. File Type Validation (S_ISREG)
 *    - Restricts operations to regular files only
 *    - Prevents DoS via device files, FIFOs, and special files
 *
 * 5. Integer Overflow Protection
 *    - Validates arithmetic operations before execution
 *    - Prevents buffer overflows from integer wraparound
 *
 * 6. Data Integrity Assurance (fsync)
 *    - Guarantees physical disk writes
 *    - Prevents data loss from cache-only writes
 *
 * 7. Restrictive File Permissions (0600)
 *    - Owner-only access to generated files
 *    - Prevents information disclosure in multi-user environments
 *
 * 8. Resource Exhaustion Prevention
 *    - 10MB maximum file size limit
 *    - Prevents memory exhaustion and DoS attacks
 *
 * 9. Atomic Temporary File Creation (mkstemp)
 *    - TOCTOU-resistant file creation
 *    - Prevents race conditions and symlink attacks
 *
 * @section THREAT_MODEL
 *
 * Mitigated Threats:
 * - Malicious file paths and symbolic link attacks
 * - Information disclosure through memory leaks or file permissions
 * - Denial of service via resource exhaustion
 * - Data corruption from incomplete writes or race conditions
 * - Privilege escalation through device file access
 *
 * @section LICENSE
 *
 * For authorized security testing and research purposes only.
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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        error(2, "usage: fuzzer <file>");
    }

    /* Validate input path meets basic requirements */
    if (!validate_path(argv[1])) {
        error(1, "invalid file path.");
    }

    /*
     * SECURITY: Symlink Attack Prevention (O_NOFOLLOW)
     *
     * Utilizes open() with security-hardened flags to prevent symbolic link
     * traversal attacks that could target system-critical files.
     *
     * Flags:
     * - O_RDONLY:   Read-only access, prevents inadvertent modifications
     * - O_NOFOLLOW: Rejects symbolic links, mitigates path traversal
     * - O_CLOEXEC:  Prevents descriptor leaks to child processes
     *
     * Threat Scenario:
     * An attacker creates a symbolic link to a privileged file:
     *   ln -s /etc/passwd input.txt
     *
     * Without O_NOFOLLOW, the fuzzer would dereference the symlink and process
     * /etc/passwd, potentially exposing authentication data or enabling
     * unauthorized system file access in shared environments.
     *
     * Mitigation: O_NOFOLLOW causes open() to fail on symlinks, preventing
     * unauthorized file access and maintaining least-privilege principles.
     */
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        error(1, "target does not exist or is a symlink.");
    }

    /*
     * Validate file size. Returns -1 on error, 0 for empty files.
     * Both conditions prevent meaningful fuzzing operations.
     */
    long int bytes = file_size(fd);
    if (bytes <= 0) {
        close(fd);
        if (bytes == 0) {
            error(1, "can't fuzz empty file.");
        } else {
            error(1, "failed to determine file size.");
        }
    }

    /*
     * SECURITY: Resource Exhaustion Prevention (File Size Limit)
     *
     * Enforces a 10 MiB maximum file size to mitigate resource exhaustion attacks
     * that could compromise system availability or stability.
     *
     * Threat Scenarios Mitigated:
     *
     * 1. Memory Exhaustion: Large file allocations can trigger OOM conditions,
     *    causing system thrashing, process termination, or complete DoS.
     *
     * 2. Container Resource Limits: In containerized environments, oversized
     *    allocations cause pod crashes and restart loops, affecting orchestration.
     *
     * 3. Algorithmic Complexity: O(n) mutation complexity on multi-gigabyte files
     *    results in extended CPU consumption and processing delays.
     *
     * 4. Swap Exhaustion: Virtual memory overcommit can exhaust swap space,
     *    causing system-wide freezes requiring manual intervention.
     *
     * 5. Multi-Instance Amplification: Concurrent fuzzer instances processing
     *    large files can multiplicatively exhaust system resources.
     *
     * 6. Disk Space Depletion: Output files in /tmp can fill partitions,
     *    disrupting system services and other applications.
     *
     * Rationale for 10 MiB Limit:
     * - Sufficient for most fuzzing use cases (configs, documents, media)
     * - Prevents memory exhaustion on resource-constrained systems
     * - Enables safe concurrent execution (10 instances = 100 MiB total)
     * - Aligns with industry best practices (HTTP servers, email systems, parsers)
     *
     * Mitigation: Validates file size before allocation, rejecting oversized inputs
     * to prevent resource exhaustion attacks.
     */
    if (bytes > MAX_BYTES) {
        close(fd);
        error(1, "target > 10 megabytes.");
    }

    /*
     * SECURITY: Memory Disclosure Prevention (Zero Initialization)
     *
     * Allocates zero-initialized memory using calloc() to prevent information
     * leakage through uninitialized buffer contents.
     *
     * Threat Scenario:
     * malloc() returns uninitialized memory containing remnants from previous
     * allocations, which may include:
     * - Cryptographic material (keys, passwords, tokens)
     * - Personally identifiable information
     * - Application-specific sensitive data
     *
     * Vulnerability Mechanism:
     * Partial read operations or buffer oversizing can cause uninitialized
     * memory regions to be written to output files or processed during mutation,
     * exposing previous memory contents (analogous to CVE-2014-0160/Heartbleed).
     *
     * Example: A 1000-byte malloc() followed by a 500-byte read leaves 500 bytes
     * of uninitialized data. Writing the full buffer exposes 500 bytes of
     * potentially sensitive historical memory contents.
     *
     * Mitigation: calloc() guarantees zero-initialization, eliminating residual
     * data exposure regardless of read completeness or buffer utilization.
     */
    uint8_t* buffer = (uint8_t*) calloc(bytes, sizeof(uint8_t));
 
    if (buffer == NULL) {
        close(fd);
        error(1, "memory not accessible.");
    }

    /* Read file contents via file descriptor */
    ssize_t size = read(fd, buffer, bytes);
   
    if (size != bytes) {
        if (size < 0) {
            error(0, "failed to read file.");
        } else {
            warning("read %zd bytes, expected %ld", size, bytes);
        }
        memset(buffer, 0, bytes);
        free(buffer);
        close(fd);
        error(1, "file read incomplete.");
    }

    close(fd);

    /* Initialize pseudorandom number generator with secure seed */
    srand(get_seed());

    char output_path[MAX_PATH_LEN];
    mutate(buffer, size, output_path);

    /* Output generated file path for user reference */
    printf("Mutated file created: %s\n", output_path);

    /*
     * SECURITY: Secure Memory Deallocation (Explicit Sanitization)
     *
     * Overwrites buffer contents before deallocation to prevent recovery of
     * sensitive data from freed memory regions.
     *
     * Vulnerability Context:
     * The free() function returns memory to the heap allocator without clearing
     * contents. Data persists in physical RAM until overwritten, creating
     * opportunities for unauthorized access.
     *
     * Attack Vectors:
     *
     * 1. Memory Forensics: Cold boot attacks, debugger introspection (gdb/ptrace),
     *    or forensic tools can extract data from RAM dumps.
     *
     * 2. Heap Reuse: Subsequent allocations may receive the same memory region,
     *    exposing previous contents to unrelated processes (cross-process leakage).
     *
     * 3. Core Dump Exposure: Process crashes generate core dumps containing freed
     *    memory, potentially accessible to unauthorized users.
     *
     * Example Attack:
     * Processing a file containing "apikey=sk-prod-..." without sanitization:
     *   1. Buffer contains sensitive credential after processing
     *   2. free() returns memory without clearing
     *   3. Attacker triggers core dump or memory scan
     *   4. Pattern matching reveals credential in "freed" memory
     *   5. Unauthorized access to protected resources
     *
     * Mitigation: Explicit memset() ensures cryptographic erasure before
     * deallocation, preventing data recovery via any mechanism. Implements
     * defense-in-depth data sanitization principles.
     */
    memset(buffer, 0, size);
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
 * SECURITY: Atomic Temporary File Creation (TOCTOU Prevention)
 *
 * Implements secure temporary file generation using mkstemp() to prevent
 * time-of-check-time-of-use (TOCTOU) race conditions and symlink attacks.
 */
FILE* temp_file(char* path_out, size_t path_len) {
    FILE* file = NULL;
    int fd = -1;
    char temp_scheme[] = "/tmp/fuzz_XXXXXX";

    /*
     * SECURITY: mkstemp() for Race-Free File Creation
     *
     * Utilizes mkstemp() for atomic temporary file creation, eliminating
     * TOCTOU vulnerabilities inherent in tmpnam()/tempnam() approaches.
     *
     * mkstemp() Guarantees:
     * 1. Atomic creation and opening (single system call)
     * 2. Exclusive access via O_EXCL flag
     * 3. Secure permissions (0600 owner-only)
     * 4. Unpredictable filenames via randomization
     * 5. Returns open file descriptor (no separate open() required)
     *
     * Threat Scenarios Mitigated:
     *
     * 1. TOCTOU Race Conditions: Non-atomic tmpnam() creates a window between
     *    name generation and file creation where attackers can inject symlinks
     *    to sensitive files (/etc/passwd), causing writes to unintended targets.
     *    Historical reference: CVE-2005-0838
     *
     * 2. Predictable Filenames: tmpnam() generates sequential names enabling
     *    attackers to pre-create files or symlinks with predicted paths,
     *    controlling fuzzer output destinations.
     *
     * 3. Symlink Replacement: Directory monitoring (inotify) allows attackers
     *    to inject symlinks between filename generation and file creation,
     *    redirecting writes to system logs or other critical files.
     *
     * 4. Permission Race Windows: fopen() creates files with default umask
     *    permissions (often world-readable), exposing data before chmod()
     *    applies restrictive permissions.
     *
     * Example Attack (tmpnam vulnerability):
     *   Fuzzer: tmpnam() -> "/tmp/file123"
     *   Attacker: ln -s /etc/passwd /tmp/file123
     *   Fuzzer: fopen("/tmp/file123", "w")
     *   Result: Overwrites /etc/passwd, compromising system authentication
     *
     * Mitigation: mkstemp() atomically creates files with secure permissions
     * and unpredictable names, eliminating all TOCTOU attack vectors. The
     * returned file descriptor refers to a newly created, exclusively owned,
     * properly permissioned regular file.
     */
    fd = mkstemp(temp_scheme);

    if (fd == -1) {
        error(1, "mkstemp call returned -1.");
    }

    /* Copy generated path to output buffer for caller reference */
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
 * SECURITY: File Type Validation and Size Determination
 *
 * Retrieves file metadata via fstat() and validates that the target is a
 * regular file to prevent DoS and information disclosure attacks.
 *
 * @param fd Open file descriptor
 * @return File size in bytes (-1 on error, 0 for empty files)
 */
long int file_size(int fd) {
    struct stat st;

    if (fstat(fd, &st) != 0) {
        return -1;
    }

    /*
     * SECURITY: Special File Protection (S_ISREG Validation)
     *
     * Restricts operations to regular files only, rejecting special file types
     * that could enable DoS or information disclosure attacks.
     *
     * Rejected File Types:
     * - Block devices (/dev/sda, /dev/nvme0n1)
     * - Character devices (/dev/zero, /dev/urandom, /dev/null)
     * - FIFOs (named pipes)
     * - Unix domain sockets
     * - Directories
     *
     * Threat Scenarios Mitigated:
     *
     * 1. Infinite Read DoS: Character devices like /dev/zero produce infinite
     *    data streams. Without validation, read() operations would hang
     *    indefinitely or exhaust system memory.
     *
     * 2. FIFO Blocking: Named pipes block on read() until a writer provides
     *    data. Attackers can create FIFOs causing the fuzzer to hang,
     *    consuming process resources without termination.
     *
     * 3. Raw Device Access: Block device access (/dev/sda1) bypasses filesystem
     *    permissions, potentially exposing unencrypted data, deleted file
     *    contents, or other sensitive disk sectors.
     *
     * 4. Entropy Pool Depletion: Reading from /dev/random drains system entropy,
     *    blocking cryptographic operations system-wide and degrading security
     *    for all processes.
     *
     * Mitigation: S_ISREG() ensures only regular files are processed, preventing
     * all special file attack vectors and maintaining predictable I/O behavior.
     */
    if (!S_ISREG(st.st_mode)) {
        error(0, "target is not a regular file.");
        return -1;
    }

    /* Validate file size is within acceptable bounds */
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

    /*
     * SECURITY: Integer Overflow Prevention
     *
     * Validates that mutation count calculations will not overflow, preventing
     * buffer overflows and heap corruption from arithmetic wraparound.
     *
     * Vulnerability Context:
     * Multiplying large size values can exceed SIZE_MAX, causing integer
     * wraparound that produces unexpectedly small results. This can lead to
     * undersized allocations or incorrect loop bounds.
     *
     * Attack Scenario:
     * On 32-bit systems with SIZE_MAX = 4,294,967,295:
     *   size = 4,000,000,000 bytes
     *   calculation = size * 4 = 16,000,000,000
     *   After overflow = 16,000,000,000 mod 2^32 = unexpected small value
     *
     * Consequences:
     * - Undersized allocations leading to heap buffer overflows
     * - Heap metadata corruption enabling exploitation
     * - Memory safety violations causing crashes or code execution
     *
     * Example Exploitation Path:
     *   1. Attacker provides near-SIZE_MAX file
     *   2. Overflow causes incorrect allocation size
     *   3. Mutation loop writes beyond buffer bounds
     *   4. Corrupts adjacent heap structures
     *   5. Enables control flow hijacking
     *
     * Mitigation: Pre-validates that size * sizeof(unsigned int) will not
     * exceed SIZE_MAX before performing any arithmetic operations, rejecting
     * inputs that would cause overflow.
     */
    if (size > SIZE_MAX / sizeof(unsigned int)) {
        fclose(candidate);
        unlink(path);
        error(1, "file too large for mutation.");
    }

    unsigned int count = (unsigned int)(MUTATIONS * size);

    /* Constrain mutation count to buffer size */
    if (count > size) {
        count = size;
    }

    /* Apply random byte mutations using PRNG */
    for (size_t i = 0; i < count; i++) {
        /* Size validated non-zero in main(), modulo operation is safe */
        size_t index = (size_t)rand() % size;
        buffer[index] = (uint8_t)(rand() % 256);
    }

    size_t written = fwrite(buffer, 1, size, candidate);

    if (written != size) {
        fclose(candidate);
        unlink(path);
        error(1, "failed to write mutated file.");
    }

    /*
     * SECURITY: Data Integrity Assurance (Forced Disk Synchronization)
     *
     * Guarantees physical disk persistence via fsync() to prevent data loss
     * from buffering-related race conditions.
     *
     * I/O Buffering Architecture:
     * 1. fwrite() -> Userspace buffer (application memory)
     * 2. fflush() -> Kernel page cache (system memory)
     * 3. fsync()  -> Physical storage media (persistent)
     *
     * Threat Scenarios Without fsync():
     *
     * 1. Power Loss Race Condition: System crashes after fclose() but before
     *    kernel writes cached data to disk, resulting in zero-byte or partially
     *    written files that appear successfully created to the application.
     *
     * 2. Automated Pipeline Integrity: High-throughput fuzzing operations may
     *    generate files faster than kernel writeback intervals, causing
     *    downstream consumers to read incomplete data from cache-disk
     *    inconsistencies.
     *
     * 3. Test Case Preservation: Critical vulnerability-triggering test cases
     *    may be lost if the system crashes before cache eviction, allowing
     *    reproducible bugs to go undetected.
     *
     * 4. Remote Transfer Corruption: Immediate file transfers (scp, rsync) may
     *    read stale disk contents before cache synchronization, transmitting
     *    corrupt or empty files.
     *
     * Mitigation Strategy:
     * - fflush(): Commits userspace buffers to kernel
     * - fsync():  Blocks until physical write completion confirmed by storage
     * - Guarantees: Data durability before success indication
     *
     * Result: Eliminates timing-dependent data integrity issues in fuzzing
     * workflows, ensuring reliable test case persistence.
     */
    fflush(candidate);
    int fd = fileno(candidate);

    if (fsync(fd) != 0) {
        fclose(candidate);
        unlink(path);
        error(1, "failed to sync file to disk.");
    }

    fclose(candidate);

    /*
     * SECURITY: Restrictive File Permissions (Least Privilege)
     *
     * Enforces owner-only access (0600) to prevent information disclosure in
     * multi-user environments. Implements defense-in-depth despite mkstemp()
     * default permissions.
     *
     * Permission Structure (0600):
     * - Owner:  read + write (rw-)
     * - Group:  no access    (---)
     * - Others: no access    (---)
     *
     * Rationale:
     * While mkstemp() creates files with 0600 by default, explicit chmod()
     * ensures security regardless of umask configuration or filesystem behavior.
     *
     * Threat Scenarios Mitigated:
     *
     * 1. Information Disclosure on Shared Systems: Default 0644 permissions
     *    (-rw-r--r--) allow group and world read access, exposing file contents
     *    to unauthorized users on multi-tenant servers or CI/CD infrastructure.
     *
     * 2. Intellectual Property Theft: Competitors on shared development
     *    infrastructure can monitor /tmp for fuzzing artifacts, reverse
     *    engineering proprietary file formats or business logic from mutated
     *    outputs.
     *
     * 3. Regulatory Compliance Violations: Processing files containing PII
     *    (personally identifiable information) with permissive access modes
     *    creates GDPR/CCPA exposure through unauthorized data access.
     *
     * 4. Credential Exposure: Configuration files containing API keys, database
     *    credentials, or authentication tokens remain partially intact after
     *    mutation, enabling unauthorized system access if world-readable.
     *
     * 5. Cryptographic Material Leakage: Statistical analysis of multiple
     *    mutated versions of key material may enable partial key recovery,
     *    especially if accessible to cryptanalysts.
     *
     * Defense-in-Depth Principle:
     * Assumes worst-case scenario where input files contain sensitive data.
     * Applies most restrictive permissions by default to prevent:
     * - Unintended data exposure from mutation artifacts
     * - Cross-user information leakage
     * - Compliance violations
     *
     * Mitigation: chmod(0600) restricts access to file owner exclusively,
     * implementing least-privilege access control for generated artifacts.
     */
    if (chmod(path, 0600) != 0) {
        warning("failed to set permissions on %s", path);
        unlink(path);
        error(1, "permission setting failed - file removed.");
    }

    /* Copy output path to caller's buffer */
    strncpy(output_path, path, MAX_PATH_LEN - 1);
    output_path[MAX_PATH_LEN - 1] = '\0';
}

/**
 * Validate file path for basic integrity requirements.
 *
 * @param path File path to validate
 * @return 1 if valid, 0 if invalid
 */
int validate_path(const char* path) {
    if (path == NULL || strlen(path) == 0) {
        return 0;
    }

    /* Enforce maximum path length to prevent buffer overflow */
    if (strlen(path) >= MAX_PATH_LEN) {
        return 0;
    }

    return 1;
}
