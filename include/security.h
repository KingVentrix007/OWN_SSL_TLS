#ifndef __SECURITY__H
#define __SECURITY__H
#include "stdint.h"
#include "stddef.h"
unsigned char * aes_enc(const unsigned char *plaintext,int plaintext_length,unsigned char *key,uint32_t *enc_data_len);
int aes_dec(const unsigned char *ciphertext,
            uint32_t ciphertext_len,
            unsigned char *plaintext,
            unsigned char *key);

unsigned char *generate_key(size_t size);

#endif