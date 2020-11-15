/** 
 * @author: Demetrius Ford
 * @date: 15 November 2020
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define OS_SOURCE "/dev/urandom"
#define MAX_BYTES 104857600

const unsigned int MUTATIONS[2] = {1, 50};

void error(const char* message, unsigned char code);
unsigned int get_seed();
FILE* temp_file();
long int file_size(FILE* file);
void mutate(uint8_t* buffer, size_t size);

int main(int argc, char* argv[]) {
  if (argc != 2) {
    error("file argument is required.", 2);
  }

  FILE* file = fopen(argv[1], "rb");
  srand(get_seed());

  if (file == NULL) {
    error("target does not exist.", 1);
  }

  long int bytes = file_size(file);

  if (bytes == 0) {
    error("target is empty.", 1);
  }

  if (bytes > MAX_BYTES) {
    error("target > 100 MB.", 1);
  }

  uint8_t* buffer = (uint8_t*) malloc(bytes * sizeof(uint8_t));

  if (buffer == NULL) {
    error("memory was not allocated to buffer.", 1);
  }

  size_t size = fread(buffer, 1, bytes, file);

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
  unsigned int seed = 0;

  if (file == NULL) {
    error("random device not found.", 1);
  }

  fread(&seed, sizeof(seed), 1, file);
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
  long int bytes = 0;

  fseek(file, 0, SEEK_END);
  bytes = ftell(file);
  fseek(file, 0, SEEK_SET);

  return bytes;
}

void mutate(uint8_t* buffer, size_t size) {
  FILE* candidate = temp_file();
  unsigned int mutations =
      (rand() % (MUTATIONS[1] - MUTATIONS[0] + 1)) + MUTATIONS[0];

  for (size_t _ = 0; _ < mutations; _ += 1) {
    buffer[rand() % size] = rand() % 256;
  }

  fwrite(buffer, 1, size, candidate);
  fclose(candidate);
}
