#ifndef DECODE_H
#define DECODE_H
#include <stdint.h>

extern const char* base_words[];
extern const size_t BASE_WORDS_COUNT;
#define MAX_OUTPUT_SIZE 1024



void shuffle(const char** array, size_t n, unsigned int seed);

// Decode functions
void decode(const char *input, const char **shuffled_words, size_t word_count,
            uint8_t *output, size_t *output_len, size_t estimated_output_size);

uint8_t word_to_byte(const char *word, const char **shuffled_words, size_t word_count);
size_t count_words(const char *input);

#endif