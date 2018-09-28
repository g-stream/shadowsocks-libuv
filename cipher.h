#ifndef CIPHER_H_
#define CIPHER_H_
#include <sodium.h>
#include <stdint.h>

typedef enum CIPHER_TYPE {
    STREAM_CIPHER,
    AEAD_CIPHER
} cipher_type_t;

typedef struct cipher_info_s {
    cipher_type_t type;
    uint8_t     id;
    size_t nonce_len;
    size_t key_len;
    size_t tag_len;
} cipher_info_t;

typedef struct cipher_s {
    cipher_info_t info;
    uint8_t* key;
    uint8_t* nonce;
    uint8_t* pass;
    uint8_t  counter;
} cipher_t;

void cipher_init(cipher_t* const cipher, const char* cipher_name, const char* pass);
void cipher_release(cipher_t* const cipher);

void ss_encrypt_buf(cipher_t* cipher, uint8_t* buf, size_t size);
void ss_decrypt_buf(cipher_t* cipher, uint8_t* buf, size_t size);

void memset_random_bytes(void * const pt, const size_t size);






#endif
