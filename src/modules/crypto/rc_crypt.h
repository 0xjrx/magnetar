#ifndef CRYPT_H
#define CRYPT_H

int rc4_crypt(const unsigned char *key, size_t key_len,
               const unsigned char *input, unsigned char *output,
               size_t data_len);

#endif