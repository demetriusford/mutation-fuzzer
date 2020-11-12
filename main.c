#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define OS_SOURCE "/dev/urandom"
#define MAX_BYTES 104857600

#define MIN_MUTATIONS 1
#define MAX_MUTATIONS 50

void error(const char* message, unsigned char code);
unsigned int get_seed();
FILE* temp_file();
long int file_size(FILE* file);
void mutate(uint8_t* buffer, size_t size);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    error("missing file argument.", 2);
  }

  FILE* file = fopen(argv[1], "rb");
  long int bytes = 0;

  uint8_t* buffer = NULL;
  size_t size = 0;

  srand(get_seed());

  if (file == NULL) {
    error("target does not exist.", 1);
  }

  bytes = file_size(file);

  if (bytes == 0) {
    error("target is empty.", 1);
  }

  if (bytes > MAX_BYTES) {
    error("target > 100 MB.", 1);
  }

  buffer = (uint8_t*)malloc(bytes * sizeof(uint8_t));

  if (buffer == NULL) {
    error("memory was not allocated to buffer.", 1);
  }

  size = fread(buffer, 1, bytes, file);

  if (bytes != size) {
    error("read in a size not equal to target.", 1);
  }

  if (ferror(file) != 0) {
    error("could not receive data from target.", 1);
  }

  mutate(buffer, size);

  fclose(file);
  free(buffer);

  return 0;
}

void error(const char* message, unsigned char code) {
  fprintf(stderr, "Error: %s\n", message);
  exit(code);
}

unsigned int get_seed() {
  FILE* file = fopen(OS_SOURCE, "r");
  size_t size = 0;
  unsigned int seed = 0;

  if (file == NULL) {
    error("random device not found.", 1);
  }

  size = fread(&seed, sizeof(seed), 1, file);

  if (size != 1) {
    error("size not equal to 1 byte", 1);
  }

  fclose(file);

  return seed;
}

FILE* temp_file() {
  FILE* file = NULL;
  int fd = -1;
  char temp_scheme[] = "/tmp/tmpXXXXXX";

  if ((fd = mkstemp(temp_scheme)) == -1) {
    error("mkstemp call returned -1.", 1);
  }

  if ((file = fdopen(fd, "wb")) == NULL) {
    error("temporary file not found.", 1);
  }

  return file;
}

long int file_size(FILE* file) {
  long int size = 0;

  if (fseek(file, 0, SEEK_END)) {
    error("file re-positioning failed @ end.", 1);
  }

  size = ftell(file);

  if (fseek(file, 0, SEEK_SET)) {
    error("file re-positioning failed @ set.", 1);
  }

  return size;
}

void mutate(uint8_t* buffer, size_t size) {
  FILE* candidate = temp_file();
  unsigned int mutations =
      (rand() % (MAX_MUTATIONS - MIN_MUTATIONS + 1)) + MIN_MUTATIONS;

  for (size_t _ = 0; _ < mutations; _ += 1) {
    buffer[rand() % size] = rand() % 256;
  }

  fwrite(buffer, 1, size, candidate);
  fclose(candidate);
}
