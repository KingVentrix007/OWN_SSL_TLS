#ifndef __RSAKEY__H
#define __RSAKEY__H
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include <openssl/pem.h>
#include <openssl/err.h>


RSA*load_pem_rsa_key_pub(const char *pem_key);
unsigned char *serialize_rsa_pubkey(RSA *rsa, int *rsa_key_size);

#endif