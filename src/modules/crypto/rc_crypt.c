#include <stddef.h>
#include <stdio.h>

// Function to perform RC4 encryption/decryption

// To be noted: RC4 is NOT cryptographically secure, as weak keys exist. It is secure ENOUGH for this application
int rc4_crypt(const unsigned char *key, size_t key_len,
              const unsigned char *input, unsigned char *output,
              size_t data_len)
{
  if (key_len < 5 || key_len > 256)
  {
    printf("Error: Key length must be between 5 and 256 bytes.\n");
    return -1;
  }

  unsigned char s[256];
  int i, j = 0;

  // Initialize S-box
  for (i = 0; i < 256; i++)
  {
    s[i] = i;
  }

  // Key Scheduling Algorithm (KSA)
  for (i = 0; i < 256; i++)
  {
    j = (j + s[i] + key[i % key_len]) % 256;
    // Swap s[i] and s[j]
    unsigned char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;
  }

  // Pseudo-Random Generation Algorithm (PRGA) and encryption/decryption
  i = j = 0;
  for (size_t n = 0; n < data_len; n++)
  {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;

    // Swap s[i] and s[j]
    unsigned char tmp = s[i];
    s[i] = s[j];
    s[j] = tmp;

    // Generate keystream byte and XOR with input
    unsigned char k = s[(s[i] + s[j]) % 256];
    output[n] = input[n] ^ k;
  }
  return 0;
}
