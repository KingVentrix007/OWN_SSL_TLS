#include "openssl/aes.h"
#include "openssl/rsa.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "stdint.h"

#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16


// AES-GCM
unsigned char * aes_enc(const unsigned char *plaintext,int plaintext_length,unsigned char *key,uint32_t *enc_data_len)
{
    unsigned char iv[12];
    unsigned char tag[16];
    RAND_bytes(iv, sizeof(iv));
    unsigned char *enc_data = malloc(12+16+plaintext_length);
    if(enc_data == NULL) return NULL;
    // Format:
    // [IV 12 bytes][CIPHERTEXT][TAG 16 bytes]

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    int len = 0;
    int ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    

    // Position output pointer after IV
    printf("Copy IV\n");
    memcpy(enc_data, iv, sizeof(iv));
    printf("Copy complete\n");
    unsigned char *out_ptr = enc_data + sizeof(iv);

    printf("Start enc\n");
    // Encrypt plaintext
    EVP_EncryptUpdate(ctx, out_ptr, &len, plaintext, plaintext_length);
    ciphertext_len += len;
    // Finalize
    EVP_EncryptFinal_ex(ctx, out_ptr + ciphertext_len, &len);
    ciphertext_len += len;

    // Get TAG
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
    memcpy(out_ptr + ciphertext_len, tag, sizeof(tag));

    // Total output size
    *enc_data_len = sizeof(iv) + ciphertext_len + sizeof(tag);

    EVP_CIPHER_CTX_free(ctx);
    return enc_data;
}

int aes_dec(const unsigned char *ciphertext,
            uint32_t ciphertext_len,
            unsigned char *plaintext,
            unsigned char *key)
{
    unsigned char iv[12];
    unsigned char tag[16];
    // plaintext = malloc(ciphertext_len);
    // Extract IV and TAG
    printf("CPY data: %ld\n",ciphertext_len);
    memcpy(iv, ciphertext, 12);

    printf("Cpy TAG\n");
    memcpy(tag, ciphertext + (ciphertext_len - 16), 16);
    printf("CPY done\n");
    // Extract actual ciphertext
    uint32_t enc_len = ciphertext_len - 12 - 16;
    unsigned char *enc_data = malloc(enc_len);
    if (!enc_data) return 0;
    memcpy(enc_data, ciphertext + 12, enc_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(enc_data); return 0; }

    int len = 0;
    int plaintext_len = 0;

    printf("Decypting\n");
    // Init decrypt
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    printf("Set IV\n");
    // Set IV length
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);

    // Provide key + IV
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    printf("Main dec\n");

    // Decrypt ciphertext
    EVP_DecryptUpdate(ctx, plaintext, &len, enc_data, enc_len);
    plaintext_len += len;

    // Provide tag BEFORE Final
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

    // Finalize – this verifies the tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);

    EVP_CIPHER_CTX_free(ctx);
    free(enc_data);
    printf("Done\n");
    if (ret > 0) {
        // Success
        plaintext_len += len;
        return plaintext_len;
    } else {
        // Authentication failed (wrong key, corrupted data, etc)
        return -1;
    }
}

unsigned char *generate_key(size_t size)
{
    unsigned char *rng_key = malloc(size);
    if (!rng_key) {
        return NULL;
    }

    if (RAND_bytes(rng_key, size) != 1) {
        free(rng_key);
        return NULL;
    }

    return rng_key;  
}