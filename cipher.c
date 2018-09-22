#include "cipher.h"
#include "string.h"
#include "utils.h"
#define supported_aead_cipher_num 3
#define SUPPORTED_AEAD_CIPHERS \
/*               name,                          key_len,                                    nonce_len,                                   tag_len*/\
    AEAD_CIPHER_INFO("aes-256-gcm",             crypto_aead_aes256gcm_KEYBYTES,             crypto_aead_aes256gcm_NPUBBYTES,             crypto_aead_aes256gcm_ABYTES)\
    AEAD_CIPHER_INFO("chacha20-ietf-poly1305",  crypto_aead_chacha20poly1305_KEYBYTES,      crypto_aead_chacha20poly1305_NPUBBYTES,      crypto_aead_chacha20poly1305_ABYTES)\
    AEAD_CIPHER_INFO("xchacha20-ietf-poly1305", crypto_aead_chacha20poly1305_IETF_KEYBYTES, crypto_aead_chacha20poly1305_IETF_NPUBBYTES, crypto_aead_chacha20poly1305_IETF_ABYTES)
    
#define supported_stream_cipher_num 3
#define SUPPORTED_STREAM_CIPHERS \
    /*                name                     key_len,                                     nonce_len */\
    STREAM_CIPHER_INFO("salsa20",               crypto_stream_salsa20_KEYBYTES  ,            crypto_stream_salsa20_NONCEBYTES)\
    STREAM_CIPHER_INFO("chacha20",              crypto_stream_chacha20_KEYBYTES,             crypto_stream_chacha20_NONCEBYTES)\
    STREAM_CIPHER_INFO("chacha20-ietf",         crypto_stream_chacha20_ietf_KEYBYTES,        crypto_stream_chacha20_ietf_NONCEBYTES)
    
static const char* stream_cipher_names[] = {
#define STREAM_CIPHER_INFO(name, kl, nl) name,
SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
};
static const int stream_cipher_key_len[] = {
#define STREAM_CIPHER_INFO(name, kl, nl) kl,
SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
};
static const int stream_cipher_nonce_len[] = {
#define STREAM_CIPHER_INFO(name, kl, nl) nl,
SUPPORTED_STREAM_CIPHERS
#undef STREAM_CIPHER_INFO
};

static const char* aead_cipher_names[] = {
#define AEAD_CIPHER_INFO(name, kl, nl, tl) name,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};

static const int aead_cipher_key_len[] = {
#define AEAD_CIPHER_INFO(name, kl, nl, tl) kl,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};
static const int aead_cipher_nonce_len[] = {
#define AEAD_CIPHER_INFO(name, kl, nl, tl) nl,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};
static const int aead_cipher_tag_len[] = {
#define AEAD_CIPHER_INFO(name, kl, nl, tl) tl,
    SUPPORTED_AEAD_CIPHERS
#undef AEAD_CIPHER_INFO
};

void fill_cipher_info(const char* name, cipher_info_t* info){
    int i;
    for(i = 0; i < supported_aead_cipher_num; i++){
        if(strcmp(name, aead_cipher_names[i]) == 0){
            info->type = AEAD_CIPHER;
            info->id   = i;
            info->key_len = aead_cipher_key_len[i];
            info->nonce_len = aead_cipher_nonce_len[i];
            info->tag_len = aead_cipher_tag_len[i];
            return;
        }
    }
    for(i = 0; i < supported_stream_cipher_num; i++){
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
