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

void fill_cipher_info(const char* name, cipher_info_t* info);

#endif
