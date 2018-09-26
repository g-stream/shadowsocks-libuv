#include "cipher.h"
#include <string.h>
#include "utils.h"
#include "md5.h"
#include <stdint.h>
#define SUPPORTED_AEAD_CIPHERS \
/*                  TYPE,           name,                          key_len,                                    nonce_len,                                   tag_len*/\
    AEAD_CIPHER_INFO(AES_256_GCM,             "aes-256-gcm",             crypto_aead_aes256gcm_KEYBYTES,             crypto_aead_aes256gcm_NPUBBYTES,             crypto_aead_aes256gcm_ABYTES)\
    AEAD_CIPHER_INFO(CHACHA20_IEFT_POLY1305,  "chacha20-ietf-poly1305",  crypto_aead_chacha20poly1305_KEYBYTES,      crypto_aead_chacha20poly1305_NPUBBYTES,      crypto_aead_chacha20poly1305_ABYTES)\
    AEAD_CIPHER_INFO(XCHACHA20_IETF_POLY1305, "xchacha20-ietf-poly1305", crypto_aead_chacha20poly1305_IETF_KEYBYTES, crypto_aead_chacha20poly1305_IETF_NPUBBYTES, crypto_aead_chacha20poly1305_IETF_ABYTES)
    

#define SUPPORTED_STREAM_CIPHERS \
    /*                 TYPE,                name                     key_len,                                     nonce_len */\
    STREAM_CIPHER_INFO(SALSA20,               "salsa20",               crypto_stream_salsa20_KEYBYTES  ,            crypto_stream_salsa20_NONCEBYTES)\
    STREAM_CIPHER_INFO(CHACHA20,              "chacha20",              crypto_stream_chacha20_KEYBYTES,             crypto_stream_chacha20_NONCEBYTES)\
    STREAM_CIPHER_INFO(CHACHA20_IETF,         "chacha20-ietf",         crypto_stream_chacha20_ietf_KEYBYTES,        crypto_stream_chacha20_ietf_NONCEBYTES)
    
typedef enum {
#define STREAM_CIPHER_INFO(type, name, kl, nl) type,
    SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
SUPPORTED_STREAM_CIPHER_NUM
} STREAM_CIPHER_TYPE;
static const char* stream_cipher_names[] = {
#define STREAM_CIPHER_INFO(type, name, kl, nl) name,
SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
};
static const int stream_cipher_key_len[] = {
#define STREAM_CIPHER_INFO(type, name, kl, nl) kl,
SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
};
static const int stream_cipher_nonce_len[] = {
#define STREAM_CIPHER_INFO(type, name, kl, nl) nl,
SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
};

typedef enum {
#define AEAD_CIPHER_INFO(type, name, kl, nl, tl) type,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
SUPPORTED_AEAD_CIPHER_NUM
} AEAD_CIPHER_TYPE;
static const char* aead_cipher_names[] = {
#define AEAD_CIPHER_INFO(type, name, kl, nl, tl) name,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};
static const int aead_cipher_key_len[] = {
#define AEAD_CIPHER_INFO(type, name, kl, nl, tl) kl,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};
static const int aead_cipher_nonce_len[] = {
#define AEAD_CIPHER_INFO(type, name, kl, nl, tl) nl,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};
static const int aead_cipher_tag_len[] = {
#define AEAD_CIPHER_INFO(type, name, kl, nl, tl) tl,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};

void memset_random_bytes(void * const pt, const size_t size) {
    randombytes_buf(pt, size);
}

void fill_cipher_info(const char* name, cipher_info_t* info){
    int i;
    for(i = 0; i < SUPPORTED_AEAD_CIPHER_NUM; i++){
        if(strcmp(name, aead_cipher_names[i]) == 0){
            info->type = AEAD_CIPHER;
            info->id   = i;
            info->key_len = aead_cipher_key_len[i];
            info->nonce_len = aead_cipher_nonce_len[i];
            info->tag_len = aead_cipher_tag_len[i];
            return;
        }
    }
    for(i = 0; i < SUPPORTED_STREAM_CIPHER_NUM; i++){
        if(strcmp(name, stream_cipher_names[i]) == 0){
            info->type = STREAM_CIPHER;
            info->id = i;
            info->key_len = stream_cipher_key_len[i];
            info->nonce_len = stream_cipher_nonce_len[i];
            return;
        }
    }
    FATAL("Unsupported cipher");
}

static int
ss_stream_xor(uint8_t *c, const uint8_t *m, uint64_t mlen,
                     const uint8_t *n, const uint8_t *k,
                     int method)
{
    switch (method) {
    case SALSA20:
        return crypto_stream_salsa20_xor(c, m, mlen, n, k);
    case CHACHA20:
        return crypto_stream_chacha20_xor(c, m, mlen, n, k);
    case CHACHA20_IETF:
        return crypto_stream_chacha20_ietf_xor(c, m, mlen, n, k);
    }
    // always return 0
    return 0;
}


int
crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
    size_t datal;
    datal = strlen((const char *)pass);
    struct MD5Context context;
    uint8_t md_buf[16];
    int addmd;
    unsigned int i, j, mds=16;
    for (j = 0, addmd = 0; j < key_len; addmd++) {
        MD5Init(&context);
        if (addmd) {
            MD5Update(&context, md_buf, 16);
        }
        MD5Update(&context, pass, datal);
        MD5Final(md_buf, &context);
        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }
    return key_len;
}

static void 
stream_cipher_malloc(cipher_t* const cipher){
    cipher->key = ss_malloc(cipher->info.key_len);
    cipher->nonce = ss_malloc(cipher->info.nonce_len);
}

static void
stream_cipher_free(cipher_t* cipher){
    free(cipher->key);
    free(cipher->nonce);
    cipher->key = NULL;
    cipher->nonce = NULL;
}

void cipher_init(cipher_t* const cipher, const char* name, const char* pass){
    fill_cipher_info(name, &cipher->info);
    switch(cipher->info.type) {
        case STREAM_CIPHER:
            stream_cipher_malloc(cipher);
            crypto_derive_key(pass, cipher->key, cipher->info.key_len);
            memset_random_bytes(cipher->nonce, cipher->info.nonce_len);
            break;
        case AEAD_CIPHER:
            LOGE("Havent implemented");
            break;
        default:
            UNREACHABLE();
    }
}
void cipher_release(cipher_t* const cipher) {
    stream_cipher_free(cipher);
}

//size is the oringe size without nonce
size_t ss_encrypt_buf(cipher_t* cipher, uint8_t* buf, size_t size) {
    switch(cipher->info.type){
        case STREAM_CIPHER:
            uint8_t* tmpbuf = new_buf(size);
            ss_stream_xor(tmpbuf, buf, size, cipher->nonce, cipher->key, cipher->info.id);
            memcpy(buf, cipher->nonce, cipher->info.nonce_len);
            memcpy(buf + cipher->info.nonce_len, tmpbuf, size);
            memset_random_bytes(cipher->nonce, cipher->info.nonce_len);
            return size + cipher->info.nonce_len;
            break;
        case AEAD_CIPHER:
            LOGE("Havent implemented");
            break;
        default:
            UNREACHABLE();
    }
}

size_t ss_decrypt_buf(cipher_t* cipher, uint8_t* buf, size_t size) {
    switch(cipher->info.type){
        case STREAM_CIPHER:
            ss_stream_xor(buf + cipher->info.nonce_len, buf+ cipher->info.nonce_len, size - cipher->info.nonce_len, buf, cipher->key, cipher->info.id);
            SHIFT_BYTE_ARRAY_TO_LEFT(buf, cipher->info.nonce_len, size);
            return size - cipher->info.nonce_len;
            break;
        case AEAD_CIPHER:
            LOGE("Havent implemented");
            break;
        default:
            UNREACHABLE();
    }
}
