#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <stddef.h>

extern unsigned char *decrypted_data;
extern size_t decrypted_data_len;

int RC4(void);

int words(void);

#endif