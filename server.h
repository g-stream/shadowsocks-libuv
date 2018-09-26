// Copyright (c) 2012 dndx (idndx.com)

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef SERVER_H_
#define SERVER_H_

#include <stdint.h>
#include "cipher.h"
#include "encrypt.h"

#define ADDRTYPE_IPV4 1
#define ADDRTYPE_DOMAIN 3
#define ADDRTYPE_IPV6 4


typedef struct
{
	uv_tcp_t client;
	uv_tcp_t remote;
	uint8_t remote_ip[16];   // Network order
    uint8_t remote_ip_type;
	uint16_t remote_port; // Network order
    struct encryptor encoder; // En/decoder
    cipher_t* cipher;
	unsigned char *handshake_buffer;
	size_t buffer_len; // Also use as pending cound after handshake
} server_ctx;

typedef struct statistic_info_s {
} statistic_info_t;


typedef struct tunnel_s{
    const char* listen_ip;
    const char* tunnel_name;
    cipher_t cipher;
    uint16_t    port;
    struct tunnel_s* prev;
    struct tunnel_s* next;
    statistic_info_t* statistic_info;
} tunnel_t;

typedef struct {
    tunnel_t*    tunnels_head;
    uint16_t     tunnels_num;
    uint16_t     comm_port;
} G;

void       init_G(G* g);
tunnel_t*  new_tunnel(G* g, const char* tunnel_name, const char* server_listen, uint16_t port, const char* cipher_name, const char* pass);
void       release_tunnel(G* g, tunnel_t* tunnel);

int        tunnel_establish(uv_loop_t* loop, tunnel_t* tunnel);

#endif /* !SERVER_H_ */
