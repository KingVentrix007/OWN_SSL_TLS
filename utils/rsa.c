#include "openssl/aes.h"
#include "openssl/rsa.h"
#include <openssl/pem.h>
#include <openssl/err.h>



RSA*load_pem_rsa_key_pub(const char *pem_key)
{
    BIO *bio = BIO_new_mem_buf((void *)pem_key, -1);
    RSA* rsa = NULL;
    // printf("PEM KEY CLIENT: [%s]\n",pem_key);
    if (!bio) {
            ERR_print_errors_fp(stderr);
            return NULL;
        }

    // Read the private key from the BIO
    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (!rsa) {
        ERR_print_errors_fp(stderr);
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return rsa;
    
}

unsigned char *serialize_rsa_pubkey(RSA *rsa, int *rsa_key_size)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio,rsa);
    unsigned char *data;
    *rsa_key_size = BIO_get_mem_data(bio,&data);
    unsigned char *key_out = malloc(*rsa_key_size);
    memcpy(key_out,data,*rsa_key_size);
    BIO_free(bio);
    return key_out;
}