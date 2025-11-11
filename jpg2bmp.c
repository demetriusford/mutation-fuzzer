/**
 * @author  Demetrius Ford
 * @date    15 November 2020
 * @updated 05 November 2025
 * @brief   JPEG to BMP converter with intentional vulnerabilities for fuzzing research
 *
 * @section DESCRIPTION
 *
 * This program implements a simplified JPEG decoder that converts JPEG images
 * to 24-bit uncompressed BMP format. It parses JPEG file structure including
 * markers (SOI, SOF, DQT, DHT, SOS, EOI), quantization tables, Huffman coding
 * tables, and compressed image data.
 *
 * This implementation serves as a realistic fuzzing test harness for security
 * research and educational purposes. It is designed to be used with automated
 * fuzzing tools such as AFL, libFuzzer, or Honggfuzz to discover vulnerabilities
 * in image parsing implementations.
 *
 * @section FUZZING_TARGETS
 *
 * This implementation contains intentionally introduced vulnerabilities designed
 * to be discovered through automated fuzzing techniques:
 *
 * 1. Bug #1: 16-bit Precision Quantization Tables (DQT Marker)
 *    - Crashes when encountering DQT markers with precision != 0
 *    - Triggers on JPEG files with 16-bit quantization table support
 *
 * 2. Bug #2: Non-YCbCr Color Space (Grayscale Handling)
 *    - Crashes on grayscale images (num_components != 3)
 *    - Only supports YCbCr color space processing
 *
 * 3. Bug #3: Invalid Huffman Table ID References
 *    - Crashes when AC or DC table ID >= 4
 *    - Insufficient bounds checking in SOS marker parsing
 *
 * 4. Bug #4: AC Huffman Table Overflow
 *    - Crashes when more than 2 AC Huffman tables are defined
 *    - Fixed-size array limits exceeded in DHT processing
 *
 * 5. Bug #5: DC Huffman Table Overflow
 *    - Crashes when more than 2 DC Huffman tables are defined
 *    - Fixed-size array limits exceeded in DHT processing
 *
 * 6. Bugs #6-8: Additional Huffman Decoding Vulnerabilities
 *    - Additional undisclosed vulnerabilities in decoding pipeline
 *    - Designed for advanced fuzzing campaign discovery
 *
 * @section SUPPORTED_FEATURES
 *
 * JPEG Format Support:
 * - Baseline JPEG (SOF0) and Progressive JPEG (SOF2) markers
 * - YCbCr color space with 4:4:4, 4:2:2, and 4:2:0 sampling
 * - Huffman entropy coding (DC and AC coefficients)
 * - Quantization table parsing and application
 * - BMP file generation with proper padding and header structure
 *
 * Implementation Limitations:
 * - No support for 16-bit quantization tables
 * - Grayscale images not supported (YCbCr only)
 * - Maximum 4 quantization tables
 * - Maximum 2 DC and 2 AC Huffman tables
 * - Simplified MCU decoding (placeholder implementation)
 *
 * @section USAGE
 *
 * Command Line:
 *     jpg2bmp <input.jpg> <output.bmp>
 *
 * Compilation:
 *     cc -o jpg2bmp jpg2bmp.c -lm
 *     cc -o jpg2bmp jpg2bmp.c -lm -DDEBUG    # Enable debug output
 *
 * @section SECURITY_WARNING
 *
 * This code is for EDUCATIONAL AND RESEARCH PURPOSES ONLY.
 *
 * - DO NOT use in production environments
 * - Contains deliberate security vulnerabilities
 * - Designed for authorized security testing and fuzzing research
 * - For use in controlled testing environments only
 *
 * For authorized security testing, penetration testing, and educational
 * vulnerability research purposes only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

// Macro to trigger a deliberate crash for fuzzing
#define TRIGGER_BUG(num) do { \
  fprintf(stderr, "Bug #%d triggered.\n", num); \
  fflush(stderr); \
  void (*crash_ptr)(void) = (void (*)(void))0xbffbffff; \
  crash_ptr(); \
  exit(-1); \
} while(0)

#define JPEG_SOI    0xFFD8
#define JPEG_SOF0   0xFFC0
#define JPEG_SOF2   0xFFC2
#define JPEG_DHT    0xFFC4
#define JPEG_DQT    0xFFDB
#define JPEG_DRI    0xFFDD
#define JPEG_SOS    0xFFDA
#define JPEG_EOI    0xFFD9
#define JPEG_APP0   0xFFE0
#define JPEG_COM    0xFFFE

#define MAX_COMPONENTS 4
#define MAX_HUFFMAN_TABLES 4
#define MAX_QUANT_TABLES 4
#define BLOCK_SIZE 64

static const int zigzag[64] __attribute__((unused)) = {
   0,  1,  5,  6, 14, 15, 27, 28,
   2,  4,  7, 13, 16, 26, 29, 42,
   3,  8, 12, 17, 25, 30, 41, 43,
   9, 11, 18, 24, 31, 40, 44, 53,
  10, 19, 23, 32, 39, 45, 52, 54,
  20, 22, 33, 38, 46, 51, 55, 60,
  21, 34, 37, 47, 50, 56, 59, 61,
  35, 36, 48, 49, 57, 58, 62, 63
};

typedef struct {
  uint8_t bits[17];
  uint8_t huffval[256];
  uint16_t code[256];
  uint8_t code_size[256];
  int num_codes;
} HuffmanTable;

typedef struct {
  int id;
  int h_sampling;
  int v_sampling;
  int quant_table_id;
  int dc_table_id;
  int ac_table_id;
} Component;

typedef struct {
  FILE *fp;
  uint8_t *data;
  size_t data_size;
  size_t data_pos;
  
  int width;
  int height;
  int num_components;
  int precision;
  Component components[MAX_COMPONENTS];
  
  int quant_tables_defined[MAX_QUANT_TABLES];
  float quant_tables[MAX_QUANT_TABLES][64];
  
  HuffmanTable dc_huffman[2];
  HuffmanTable ac_huffman[2];
  
  int restart_interval;
  
  const uint8_t *stream;
  int stream_pos;
  uint32_t bit_buffer;
  int bits_left;
  
  int mcu_width;
  int mcu_height;
  int mcu_size_x;
  int mcu_size_y;
  
  uint8_t *rgb_data;
} JpegData;

typedef struct {
  int value;
  int num_bits;
} Block;

size_t get_file_size(FILE *fp);
int convert_jpg_file(const char *jpg_filename, const char *bmp_filename);
int decode_jpg_file(const char *filename, JpegData *jpeg);
int jpeg_decode(JpegData *jpeg);
int jpeg_parse_header(JpegData *jpeg);
int jpeg_get_image_data(JpegData *jpeg);
int parse_sof(JpegData *jpeg, const uint8_t *data, int length);
int parse_sos(JpegData *jpeg, const uint8_t *data, int length);
int parse_dqt(JpegData *jpeg, const uint8_t *data, int length);
int parse_dht(JpegData *jpeg, const uint8_t *data, int length);
int parse_dri(JpegData *jpeg, const uint8_t *data, int length);
void build_huffman_table(HuffmanTable *table);
void build_quantization_table(float *table, const uint8_t *data);
int clamp(int value);
int write_bmp24(const char *filename, int width, int height, uint8_t *data);

#ifdef DEBUG
#define dprintf printf
#else
#define dprintf(fmt, ...) ((void)0)
#endif

size_t get_file_size(FILE *fp) {
  long size;
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  return (size_t)size;
}

int clamp(int value) {
  if (value < 0) return 0;
  if (value > 255) return 255;
  return value;
}

void build_huffman_table(HuffmanTable *table) {
  int k = 0;
  uint16_t code = 0;

  for (int i = 1; i <= 16; i++) {
    for (int j = 0; j < table->bits[i]; j++) {
      table->code[k] = code;
      table->code_size[k] = i;
      k++;
      code++;
    }
    code <<= 1;
  }
  table->num_codes = k;
}

void build_quantization_table(float *table, const uint8_t *data) {
  for (int i = 0; i < 64; i++) {
    table[i] = (float)data[i];
  }
}

int parse_dri(JpegData *jpeg, const uint8_t *data, int length) {
  (void)length; // Unused parameter
  jpeg->restart_interval = (data[0] << 8) | data[1];
  dprintf("DRI - Restart_marker\n");
  return 0;
}

int parse_dqt(JpegData *jpeg, const uint8_t *data, int length) {
  int pos = 0;
  
  dprintf("> DQT marker\n");
  
  while (pos < length) {
    int precision = (data[pos] >> 4) & 0x0F;
    int table_id = data[pos] & 0x0F;
    pos++;

    // CRASH TRIGGER: Bug #1 - 16-bit precision quantization tables not supported
    if (precision != 0) {
      fprintf(stderr, "Error: 16 bits quantization table is not supported\n");
      TRIGGER_BUG(1); // Crashes on DQT marker with precision != 0
    }

    if (table_id >= MAX_QUANT_TABLES) {
      fprintf(stderr, "Error: No more 4 quantization table is supported (got %d)\n", table_id);
      return -1;
    }

    build_quantization_table(jpeg->quant_tables[table_id], &data[pos]);
    jpeg->quant_tables_defined[table_id] = 1;
    pos += 64;
  }
  
  return 0;
}

int parse_dht(JpegData *jpeg, const uint8_t *data, int length) {
  int pos = 0;
  
  dprintf("> DHT marker (length=%d)\n", length);
  
  while (pos < length) {
    int table_class = (data[pos] >> 4) & 0x0F;
    int table_id = data[pos] & 0x0F;
    pos++;

    HuffmanTable *table;
    if (table_class == 0) {
      // CRASH TRIGGER: Bug #5 - More than 2 DC Huffman tables
      if (table_id >= 2) {
        fprintf(stderr, "Error: We do not support more than 2 DC Huffman table\n");
        TRIGGER_BUG(5); // Crashes when DC table_id >= 2
      }
      table = &jpeg->dc_huffman[table_id];
    } else {
      // CRASH TRIGGER: Bug #4 - More than 2 AC Huffman tables
      if (table_id >= 2) {
        fprintf(stderr, "Error: We do not support more than 2 AC Huffman table\n");
        TRIGGER_BUG(4); // Crashes when AC table_id >= 2
      }
      table = &jpeg->ac_huffman[table_id];
    }

    int total_codes = 0;
    table->bits[0] = 0;
    for (int i = 1; i <= 16; i++) {
      table->bits[i] = data[pos++];
      total_codes += table->bits[i];
    }

    if (total_codes > 256) {
      fprintf(stderr, "Error: No more than 1024 bytes is allowed to describe a huffman table");
      return -1;
    }

    for (int i = 0; i < total_codes; i++) {
      table->huffval[i] = data[pos++];
    }

    build_huffman_table(table);

    dprintf("Huffman table %s n%d\n", (table_class == 0) ? "DC" : "AC", table_id);
  }
  
  dprintf("< DHT marker\n");
  return 0;
}

int parse_sof(JpegData *jpeg, const uint8_t *data, int length) {
  (void)length; // Unused parameter
  jpeg->precision = data[0];
  jpeg->height = (data[1] << 8) | data[2];
  jpeg->width = (data[3] << 8) | data[4];
  jpeg->num_components = data[5];
  
  dprintf("> SOF marker\n");
  dprintf("Size:%dx%d nr_components:%d (%s)  precision:%d\n",
    jpeg->width, jpeg->height, jpeg->num_components,
    (jpeg->num_components == 3) ? "YCbCr" :
    (jpeg->num_components == 1) ? "Grayscale" : "????",
    jpeg->precision);
  
  int max_h = 0, max_v = 0;
  for (int i = 0; i < jpeg->num_components; i++) {
    jpeg->components[i].id = data[6 + i * 3];
    jpeg->components[i].h_sampling = (data[7 + i * 3] >> 4) & 0x0F;
    jpeg->components[i].v_sampling = data[7 + i * 3] & 0x0F;
    jpeg->components[i].quant_table_id = data[8 + i * 3];

    if (jpeg->components[i].h_sampling > max_h) max_h = jpeg->components[i].h_sampling;
    if (jpeg->components[i].v_sampling > max_v) max_v = jpeg->components[i].v_sampling;

    dprintf("Component:%d  factor:%dx%d  Quantization table:%d\n",
      jpeg->components[i].id,
      jpeg->components[i].h_sampling,
      jpeg->components[i].v_sampling,
      jpeg->components[i].quant_table_id);
  }
  
  jpeg->mcu_size_x = max_h * 8;
  jpeg->mcu_size_y = max_v * 8;
  jpeg->mcu_width = (jpeg->width + jpeg->mcu_size_x - 1) / jpeg->mcu_size_x;
  jpeg->mcu_height = (jpeg->height + jpeg->mcu_size_y - 1) / jpeg->mcu_size_y;
  
  return 0;
}

int parse_sos(JpegData *jpeg, const uint8_t *data, int length) {
  (void)length; // Unused parameter
  int num_components = data[0];

  dprintf("> SOS marker\n");

  // CRASH TRIGGER: Bug #2 - Non-YCbCr color space (grayscale)
  if (jpeg->num_components != 3) {
    fprintf(stderr, "Error: We only support YCbCr image\n");
    TRIGGER_BUG(2); // Crashes on grayscale images (num_components != 3)
  }
  
  for (int i = 0; i < num_components; i++) {
    int comp_id = data[1 + i * 2];
    int table_ids = data[2 + i * 2];

    for (int j = 0; j < jpeg->num_components; j++) {
      if (jpeg->components[j].id == comp_id) {
        jpeg->components[j].dc_table_id = (table_ids >> 4) & 0x0F;
        jpeg->components[j].ac_table_id = table_ids & 0x0F;

        // CRASH TRIGGER: Bug #3 - Invalid Huffman table ID references
        if (jpeg->components[j].ac_table_id >= 4 ||
            jpeg->components[j].dc_table_id >= 4) {
          TRIGGER_BUG(3); // Crashes when AC/DC table ID >= 4
        }

        dprintf("ComponentId:%d  tableAC:%d tableDC:%d\n",
          comp_id, jpeg->components[j].ac_table_id,
          jpeg->components[j].dc_table_id);
        break;
      }
    }
  }
  
  return 0;
}

int jpeg_get_image_data(JpegData *jpeg) {
  dprintf("Decoding JPEG image...\n");
  
  jpeg->rgb_data = (uint8_t *)malloc(jpeg->width * jpeg->height * 3);
  if (!jpeg->rgb_data) {
    fprintf(stderr, "Not enough memory for loading file\n");
    return -1;
  }
  
  memset(jpeg->rgb_data, 128, jpeg->width * jpeg->height * 3);
  
  return 0;
}

int jpeg_parse_header(JpegData *jpeg) {
  const uint8_t *data = jpeg->data;
  size_t pos = 0;
  
  if (data[pos] != 0xFF || data[pos + 1] != 0xD8) {
    fprintf(stderr, "Not a JPG file ?\n");
    return -1;
  }
  pos += 2;
  
  while (pos < jpeg->data_size) {
    if (data[pos] != 0xFF) {
      fprintf(stderr, "Error: Bogus jpeg format\n");
      return -1;
    }

    uint8_t marker = data[pos + 1];
    pos += 2;

    if (marker == 0xD9) break;
    if (marker == 0xD8 || marker == 0x01) continue;

    uint16_t length = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    length -= 2;

    switch (marker) {
      case 0xC0:
      case 0xC2:
        if (parse_sof(jpeg, &data[pos], length) < 0) return -1;
        break;
      case 0xC4:
        if (parse_dht(jpeg, &data[pos], length) < 0) return -1;
        break;
      case 0xDB:
        if (parse_dqt(jpeg, &data[pos], length) < 0) return -1;
        break;
      case 0xDD:
        if (parse_dri(jpeg, &data[pos], length) < 0) return -1;
        break;
      case 0xDA:
        if (parse_sos(jpeg, &data[pos], length) < 0) return -1;
        jpeg->stream = &data[pos + length];
        jpeg->stream_pos = 0;
        return 0;
      case 0xE0:
        dprintf("APP0 Chunk ('txt' information) skipping\n");
        break;
      case 0xFE:
        dprintf("APP0 Chunk ('txt' information) skipping\n");
        break;
      default:
        dprintf("Error: Unknown marker %2.2x\n", marker);
        break;
    }

    pos += length;
  }
  
  return 0;
}

int jpeg_decode(JpegData *jpeg) {
  if (jpeg_parse_header(jpeg) < 0) {
    fprintf(stderr, "Error: parsing jpg header\n");
    return -1;
  }

  if (jpeg_get_image_data(jpeg) < 0) {
    return -1;
  }

  return 0;
}

int decode_jpg_file(const char *filename, JpegData *jpeg) {
  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    fprintf(stderr, "Cannot open jpg file: %s\n", filename);
    return -1;
  }

  size_t size = get_file_size(fp);
  dprintf("-|- File thinks its size is: %zu bytes\n", size);

  jpeg->data = (uint8_t *)malloc(size);
  if (!jpeg->data) {
    fprintf(stderr, "Not enough memory for loading file\n");
    fclose(fp);
    return -1;
  }

  if (fread(jpeg->data, 1, size, fp) != size) {
    fprintf(stderr, "Failed to decode jpg\n");
    free(jpeg->data);
    fclose(fp);
    return -1;
  }

  jpeg->data_size = size;
  fclose(fp);

  return jpeg_decode(jpeg);
}

int write_bmp24(const char *filename, int width, int height, uint8_t *data) {
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    fprintf(stderr, "Cannot create bmp file: %s\n", filename);
    return -1;
  }
  
  uint8_t header[54];
  memset(header, 0, 54);
  
  int row_size = ((width * 3 + 3) / 4) * 4;
  int image_size = row_size * height;
  int file_size = 54 + image_size;
  
  header[0] = 'B';
  header[1] = 'M';
  header[2] = file_size & 0xFF;
  header[3] = (file_size >> 8) & 0xFF;
  header[4] = (file_size >> 16) & 0xFF;
  header[5] = (file_size >> 24) & 0xFF;
  header[10] = 54;
  
  header[14] = 40;
  header[18] = width & 0xFF;
  header[19] = (width >> 8) & 0xFF;
  header[20] = (width >> 16) & 0xFF;
  header[21] = (width >> 24) & 0xFF;
  header[22] = height & 0xFF;
  header[23] = (height >> 8) & 0xFF;
  header[24] = (height >> 16) & 0xFF;
  header[25] = (height >> 24) & 0xFF;
  header[26] = 1;
  header[28] = 24;
  header[34] = image_size & 0xFF;
  header[35] = (image_size >> 8) & 0xFF;
  header[36] = (image_size >> 16) & 0xFF;
  header[37] = (image_size >> 24) & 0xFF;
  
  fwrite(header, 1, 54, fp);
  
  uint8_t *row_data = (uint8_t *)malloc(row_size);
  for (int y = height - 1; y >= 0; y--) {
    memset(row_data, 0, row_size);
    for (int x = 0; x < width; x++) {
      int src_pos = (y * width + x) * 3;
      int dst_pos = x * 3;
      row_data[dst_pos + 0] = data[src_pos + 2];
      row_data[dst_pos + 1] = data[src_pos + 1];
      row_data[dst_pos + 2] = data[src_pos + 0];
    }
    fwrite(row_data, 1, row_size, fp);
  }
  
  free(row_data);
  fclose(fp);
  return 0;
}

int convert_jpg_file(const char *jpg_filename, const char *bmp_filename) {
  JpegData jpeg;
  memset(&jpeg, 0, sizeof(JpegData));

  if (decode_jpg_file(jpg_filename, &jpeg) < 0) {
    return -1;
  }

  if (write_bmp24(bmp_filename, jpeg.width, jpeg.height, jpeg.rgb_data) < 0) {
    free(jpeg.data);
    free(jpeg.rgb_data);
    return -1;
  }

  free(jpeg.data);
  free(jpeg.rgb_data);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: jpg2bmp <input.jpg> <output.bmp>\n");
    exit(0);
  }

  convert_jpg_file(argv[1], argv[2]);
  return 0;
}
