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

#include "config.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <uv.h>
#include "encrypt.h"
#include "utils.h"
#include "cipher.h"
#include "server.h"

struct encryptor crypto;


static void printbuf(uv_buf_t* buf, int len){
  buf->base[buf->len] = 0;
  int i;
  for(i = 0; i < len; ++i){
      printf("%c", (&buf->base[i]));
  }
  printf("\n");
  for(i = 0; i < len; ++i){
      printf("%x ", *(uint8_t*)(&buf->base[i]));
  }
  printf("\n");
}
static void established_free_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	if (!ctx->encoder.encrypt_table)
		destroy_encryptor(&ctx->encoder);
	free(ctx);
}

// Close remote and free ctx
static void client_established_shutdown_complete(uv_shutdown_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->data;
	uv_close((uv_handle_t*)(void *)&ctx->client, established_free_cb);
	free(req);
}

// Close client and free ctx
static void remote_established_shutdown_complete(uv_shutdown_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->data;
	uv_close((uv_handle_t*)(void *)&ctx->remote, established_free_cb);
	free(req);
}

// Shutdown client
static void remote_established_close_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	uv_read_stop((uv_stream_t *)(void *)&ctx->client);
	uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
	req->data = ctx;

	int err = uv_shutdown(req, (uv_stream_t *)(void *)&ctx->client, client_established_shutdown_complete);
	if (err) {
		LOGE("Shutdown client side write stream failed!");
		uv_close((uv_handle_t*)(void *)&ctx->client, established_free_cb);
		free(req);
	}
}

// Close client then close remote
static void client_established_close_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	uv_read_stop((uv_stream_t *)(void *)&ctx->remote);
	uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
	req->data = ctx;

	int err = uv_shutdown(req, (uv_stream_t *)(void *)&ctx->remote, remote_established_shutdown_complete);
	if (err) {
		LOGE("Shutdown remote side write stream failed!");
		uv_close((uv_handle_t*)(void *)&ctx->remote, established_free_cb);
		free(req);
	}
}

static void remote_established_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    LOGI("Called remote_established_read_cb");
	int err = 1;
	server_ctx *ctx = (server_ctx *)stream->data;

	if (nread < 0) { // EOF
		if (buf->len) // If buf is set, we need to free it
			free(buf->base);
		LOGCONN(&ctx->remote, "Remote %s EOF, closing");
		HANDLE_CLOSE((uv_handle_t*)stream, remote_established_close_cb); // Then close the connection
		return;
	} else if (!nread) {
		free(buf->base);
		return;
	}
    LOGI("Have data in remote_established_read_cb");
	shadow_encrypt((uint8_t *)buf->base, &ctx->encoder, nread);

	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	if (!req) {
		HANDLE_CLOSE((uv_handle_t*)stream, remote_established_close_cb);
		FATAL("malloc() failed!");
	}
    
    uv_buf_t* write_buf = ss_malloc(sizeof(uv_buf_t));
    req->data = write_buf;
    write_buf->base = buf->base;
    write_buf->len = nread;
    
	err = uv_write(req, (uv_stream_t *)(void *)&ctx->client, write_buf, 1, after_write_cb);
	if (err) {
		LOGE("Write to client failed!");
		free(req);
		free(write_buf->base);
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->client, client_established_close_cb);
		return;
	}
	if (ctx->buffer_len == MAX_PENDING_PER_CONN - 1) { // buffer_len used as pending write request counter
		uv_read_stop(stream);
	}
	ctx->buffer_len++;
}

static void after_write_cb(uv_write_t* req, int status)
{
    LOGI("---Writed");
	server_ctx *ctx = (server_ctx *)req->handle->data;
	if (status) {
		if (status < 0) {
			if ((uv_tcp_t *)req->handle == &ctx->client) {
				HANDLE_CLOSE((uv_handle_t *)req->handle, client_established_close_cb);
			} else {
				HANDLE_CLOSE((uv_handle_t *)req->handle, remote_established_close_cb);
			}
		}
		free(((uv_buf_t*)req->data)->base); // Free buffer
        free(req->data);
		free(req);
		return;
	}
	if ((uv_tcp_t *)req->handle == &ctx->client && !uv_is_closing((uv_handle_t *)(void *)&ctx->remote)) {
        LOGI("write client!");
		if (ctx->buffer_len <= MAX_PENDING_PER_CONN) {
			int err = uv_read_start((uv_stream_t *)(void *)&ctx->remote, established_alloc_cb, remote_established_read_cb);
			if (err) {
				SHOW_UV_ERROR(err);
				HANDLE_CLOSE((uv_handle_t *)(void *)&ctx->remote, remote_established_close_cb);
				free(((uv_buf_t*)req->data)->base);// Free buf base
                free(req->data); //free buf
				free(req);
				return;
			}
		}
		ctx->buffer_len--;
	}
    free(((uv_buf_t*)(req->data))->base);
    free(req->data);
	free(req);
}

static void client_established_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    LOGI("Called client_extablished_read_cb");
	int err = 1;
	server_ctx *ctx = (server_ctx *)stream->data;

	if (nread < 0) { // EOF
        
		if (buf->len) // If buf is set, we need to free it
			free(buf->base);
		LOGCONN(&ctx->client, "Client %s EOF, closing");
		HANDLE_CLOSE((uv_handle_t*)stream, client_established_close_cb); // Then close the connection
		return;
	} else if (!nread) {
		free(buf->base);
		return;
	}
	LOGI("Have data in client_extablished_read_cb");
	shadow_decrypt((uint8_t *)buf->base, &ctx->encoder, nread);
    
	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	if (!req) {
		HANDLE_CLOSE((uv_handle_t*)stream, client_established_close_cb);
		FATAL("malloc() failed!");
	}
	
    uv_buf_t* write_buf = (uv_buf_t*) ss_malloc(sizeof(uv_buf_t));
    req->data = write_buf;
    write_buf->base = buf->base;
    write_buf->len = nread;
    
	err = uv_write(req, (uv_stream_t *)(void *)&ctx->remote, write_buf, 1, NULL);
	if (err) {
		LOGE("Write to remote failed!");
		free(req);
		free(buf->base);
		HANDLE_CLOSE((uv_handle_t*)(void *)&ctx->remote, remote_established_close_cb);
		return;
	}
}

static void established_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	#ifdef BUFFER_LIMIT
	buf->base = malloc(BUFFER_LIMIT);
	buf->len = BUFFER_LIMIT;
	#else
	buf->base = malloc(suggested_size);
	buf->len = suggested_size;
	#endif /* BUFFER_LIMIT */
	if (!buf->base) {
		FATAL("malloc() failed!");
	}
}

// Failed during handshake
static void handshake_client_close_cb(uv_handle_t* handle)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	if (ctx->handshake_buffer) {
		free(ctx->handshake_buffer);
		ctx->handshake_buffer = NULL;
	}
	if (!ctx->encoder.encrypt_table)
		destroy_encryptor(&ctx->encoder);
	free(ctx);
}

static void after_connect_to_remote_write_cb(uv_write_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->handle->data;
	if (status) {
		if (status < 0) {
			if ((uv_tcp_t *)req->handle == &ctx->client) {
				HANDLE_CLOSE((uv_handle_t *)req->handle, client_established_close_cb);
			} else {
				HANDLE_CLOSE((uv_handle_t *)req->handle, remote_established_close_cb);
			}
		}
        free(req->data);
		free(req);
		return;
	}
	if ((uv_tcp_t *)req->handle == &ctx->client && !uv_is_closing((uv_handle_t *)(void *)&ctx->remote)) {
        LOGI("write client!");
		if (ctx->buffer_len <= MAX_PENDING_PER_CONN) {
			int err = uv_read_start((uv_stream_t *)(void *)&ctx->remote, established_alloc_cb, remote_established_read_cb);
			if (err) {
				SHOW_UV_ERROR(err);
				HANDLE_CLOSE((uv_handle_t *)(void *)&ctx->remote, remote_established_close_cb);
                free(req->data); //free buf
				free(req);
				return;
			}
		}
		ctx->buffer_len--;
	}
    free(req->data);
	free(req);
}

static void connect_to_remote_cb(uv_connect_t* req, int status)
{
	server_ctx *ctx = (server_ctx *)req->data;

	if (status) {
		if (status < 0) {
			SHOW_UV_ERROR(status);
			uv_close((uv_handle_t*)(void *)&ctx->remote, remote_established_close_cb);
			free(ctx->handshake_buffer);
			free(req);
		}
		return;
	}
	free(req);

	LOGCONN(&ctx->remote, "Connected to %s");

	uv_buf_t buf;
	buf.base = (char *)ctx->handshake_buffer;
	buf.len = HANDSHAKE_BUFFER_SIZE;

	if (!ctx->buffer_len) {
		free(ctx->handshake_buffer);
	} else {
		uv_write_t *wreq = (uv_write_t *)malloc(sizeof(uv_write_t));
		if (!wreq) {
			uv_close((uv_handle_t*)(void *)&ctx->client, client_established_close_cb);
			FATAL("malloc() failed!");
		}
		wreq->data = buf.base;
		buf.len = ctx->buffer_len;
		int err = uv_write(wreq, (uv_stream_t *)(void *)&ctx->remote, &buf, 1, after_connect_to_remote_write_cb);
		if (err) {
			LOGE("Write to remote failed!");
			free(wreq);
			uv_close((uv_handle_t*)(void *)&ctx->remote, remote_established_close_cb);
			return;
		}
	}

	ctx->handshake_buffer = NULL;
	ctx->buffer_len = 0;
	
	int err = uv_read_start((uv_stream_t *)(void *)&ctx->client, established_alloc_cb, client_established_read_cb);
	if (err) {
		SHOW_UV_ERROR(err);
		uv_close((uv_handle_t*)(void *)&ctx->client, client_established_close_cb);
		return;
	}
	err = uv_read_start((uv_stream_t *)(void *)&ctx->remote, established_alloc_cb, remote_established_read_cb);
	if (err) {
		SHOW_UV_ERROR(err);
		uv_close((uv_handle_t*)(void *)&ctx->remote, remote_established_close_cb);
		return;
	}
}

static int do_handshake(uv_stream_t *stream)
{
	server_ctx *ctx = (server_ctx *)stream->data;
	int err = 1;

	if (!ctx->remote_ip_type) {
		if (ctx->buffer_len < 2) // Not interpretable
			return 1;
		uint8_t addrtype = ctx->handshake_buffer[0];
		if (addrtype == ADDRTYPE_IPV4) {
			if (ctx->buffer_len < 5)
				return 1;
			memcpy(ctx->remote_ip, ctx->handshake_buffer + 1, 4);
			ctx->remote_ip_type = ADDRTYPE_IPV4;
			SHIFT_BYTE_ARRAY_TO_LEFT(ctx->handshake_buffer, 5, HANDSHAKE_BUFFER_SIZE);
			ctx->buffer_len -= 5;
			// TODO: Print out
		} else if (addrtype == ADDRTYPE_DOMAIN) {
			uint8_t domain_len = ctx->handshake_buffer[1];
			if (!domain_len) { // Domain length is zero
				LOGE("Domain length is zero");
				uv_close((uv_handle_t*)stream, handshake_client_close_cb);
				return -1;
			}
			if (ctx->buffer_len < domain_len + 2)
				return 1;
			char domain[domain_len+1];
			domain[domain_len] = 0;
			memcpy(domain, ctx->handshake_buffer+2, domain_len);

			uv_getaddrinfo_t *resolver = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));
			if (!resolver) {
				uv_close((uv_handle_t*)stream, handshake_client_close_cb);
				FATAL("malloc() failed!");
			}
			resolver->data = ctx; // We need to locate back the stream
			LOGI("Domain is: %s", domain);
			err = uv_getaddrinfo(stream->loop, resolver, client_handshake_domain_resolved, domain, NULL, NULL);
			if (err) {
				SHOW_UV_ERROR(err);
				uv_close((uv_handle_t*)stream, handshake_client_close_cb);
				free(resolver);
				return -1;
			}
			SHIFT_BYTE_ARRAY_TO_LEFT(ctx->handshake_buffer, 2+domain_len, HANDSHAKE_BUFFER_SIZE);
			ctx->buffer_len -= 2 + domain_len;
			uv_read_stop(stream); // Pause the reading process, wait for resolve result
			return 1;
		} else { // Unsupported addrtype
			LOGI("addrtype unknown, closing");
			uv_close((uv_handle_t*)stream, handshake_client_close_cb);
			return -1;
		}
	} // !ctx->remote_ip

	if (!ctx->remote_port) {
		if (ctx->buffer_len < 2) // Not interpretable
			return 1;
		ctx->remote_port = *((uint16_t *)ctx->handshake_buffer);
		if (!ctx->remote_port) {
			LOGE("Remote port is zero");
			uv_close((uv_handle_t*)stream, handshake_client_close_cb);
			return -1;
		}
		SHIFT_BYTE_ARRAY_TO_LEFT(ctx->handshake_buffer, 2, HANDSHAKE_BUFFER_SIZE);
		ctx->buffer_len -= 2;
		// Try connect now
		err = uv_tcp_init(stream->loop, &ctx->remote);
		if (err)
			SHOW_UV_ERROR_AND_EXIT(err);
		uv_connect_t *req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		if (!req) {
			uv_close((uv_handle_t*)stream, handshake_client_close_cb);
			FATAL("malloc() failed!");
		}
		req->data = ctx;
		if (ctx->remote_ip_type == ADDRTYPE_IPV4) {
			struct sockaddr_in remote;
			memset(&remote, 0, sizeof(remote));
			remote.sin_family = AF_INET;
			memcpy(&remote.sin_addr.s_addr, ctx->remote_ip, 4);
			remote.sin_port = ctx->remote_port;
			err = uv_tcp_connect(req, &ctx->remote, ( const struct sockaddr* )&remote, connect_to_remote_cb);
		} else if (ctx->remote_ip_type == ADDRTYPE_IPV6) {
			struct sockaddr_in6 remote;
			memset(&remote, 0, sizeof(remote));
			remote.sin6_family = AF_INET6;
			memcpy(&remote.sin6_addr.s6_addr, ctx->remote_ip, 16);
			remote.sin6_port = ctx->remote_port;
			err = uv_tcp_connect(req, &ctx->remote, ( const struct sockaddr* )&remote, connect_to_remote_cb);
		} else {
			FATAL("addrtype unknown!");
		}
		
		if (err) {
			SHOW_UV_ERROR(err);
			uv_close((uv_handle_t*)stream, handshake_client_close_cb);
			free(req);
			return -1;
		}
	}

	uv_read_stop(stream);
	return 0;
}

static void client_handshake_domain_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res)
{
	server_ctx *ctx = (server_ctx *)resolver->data;
    if (status) {
		if (status < 0) {
			LOGI("Resolve error, NXDOMAIN");
		} else {
			SHOW_UV_ERROR(status);
		}
		uv_close((uv_handle_t*)(void *)&ctx->client, handshake_client_close_cb);
		uv_freeaddrinfo(res);
		free(resolver);
		return;
	}

	if (res->ai_family == AF_INET) { // IPv4
        LOGI("--Resolved! Get an ipv4 address");
		memcpy(ctx->remote_ip, &((struct sockaddr_in*)(res->ai_addr))->sin_addr.s_addr, 4);
		ctx->remote_ip_type = ADDRTYPE_IPV4;
	} else if (res->ai_family == AF_INET6) {
        LOGI("Resolved! Get an ipv6 address");
		memcpy(ctx->remote_ip, &((struct sockaddr_in6*)(res->ai_addr))->sin6_addr.s6_addr, 16);
		ctx->remote_ip_type = ADDRTYPE_IPV6;
	} else {
		FATAL("dns resolve failed!");
	}

	if (do_handshake((uv_stream_t *)(void *)&ctx->client) == 1) {
		int err = uv_read_start((uv_stream_t *)(void *)&ctx->client, client_handshake_alloc_cb, client_handshake_read_cb);
		if (err) {
			uv_close((uv_handle_t*)(void *)&ctx->client, handshake_client_close_cb);
			SHOW_UV_ERROR(err);
		}
	}

	uv_freeaddrinfo(res);
	free(resolver);
}

static void client_handshake_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	server_ctx *ctx = (server_ctx *)stream->data;

	if (nread < 0) {
		if (buf->len) // If buf is set, we need to free it
			free(buf->base);
		uv_close((uv_handle_t*)stream, handshake_client_close_cb); // Then close the connection
		return;
	} else if (!nread) {
		free(buf->base);
		return;
	}

	memcpy(ctx->handshake_buffer + ctx->buffer_len, buf->base, nread);
	shadow_decrypt(ctx->handshake_buffer + ctx->buffer_len, &ctx->encoder, nread);
	ctx->buffer_len += nread;
	if (!ctx->handshake_buffer) {
		FATAL("Should not call this anymore");
	}
	free(buf->base);
	
	do_handshake(stream);
}

static void client_handshake_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
	server_ctx *ctx = (server_ctx *)handle->data;
	buf->base = malloc(HANDSHAKE_BUFFER_SIZE - ctx->buffer_len);
	buf->len = HANDSHAKE_BUFFER_SIZE - ctx->buffer_len;
}

static void connect_cb(uv_stream_t* listener, int status)
{
	int err = 1;
    
	if (status) {
		SHOW_UV_ERROR(status);
		return;
	}

	server_ctx *ctx = calloc(1, sizeof(server_ctx));
	ctx->handshake_buffer = calloc(1, HANDSHAKE_BUFFER_SIZE);

	if (!ctx || !ctx->handshake_buffer)
		FATAL("malloc() failed!");

	ctx->client.data = ctx;
	ctx->remote.data = ctx;
	
	make_encryptor(&crypto, &ctx->encoder, 0, NULL);

	err = uv_tcp_init(listener->loop, &ctx->client);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);

	err = uv_accept(listener, (uv_stream_t *)(void *)&ctx->client);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);

	err = uv_tcp_nodelay(&ctx->client, 1);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);

	#ifdef KEEPALIVE_TIMEOUT
	err = uv_tcp_keepalive(&ctx->client, 1, KEEPALIVE_TIMEOUT);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);
	#endif /* KEEPALIVE_TIMEOUT */

	err = uv_read_start((uv_stream_t *)(void *)&ctx->client, client_handshake_alloc_cb, client_handshake_read_cb);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);

	LOGCONN(&ctx->client, "Accepted connection from %s");
}

int main(int argc, char *argv[])
{
  
	char **newargv = uv_setup_args(argc, argv);
	char *server_listen = SERVER_LISTEN;
	int server_port = SERVER_PORT;
	uint8_t *password = (uint8_t *)PASSWORD;
	uint8_t crypt_method = CRYPTO_METHOD;
	char *pid_path = PID_FILE;
    char cipher_name[20];
	char opt;
	while((opt = getopt(argc, newargv, "l:p:k:f:m:")) != -1) { // not portable to windows
		switch(opt) {
			case 'l':
			    server_listen = optarg;
			    break;
			case 'p':
			    server_port = atoi(optarg);
			    break;
			case 'k':
			    password = (uint8_t *)optarg;
			    break;
			case 'f':
			    pid_path = optarg;
			    break;
			case 'm':
			    if (!strcmp("rc4", optarg))
			    	crypt_method = METHOD_RC4;
			    else if (!strcmp("shadow", optarg))
			    	crypt_method = METHOD_SHADOWCRYPT;
                else {
                    crypt_method = -1;
                    memcpy(cipher_name, optarg, strlen(optarg) + 1);
                }
			    break;
			default:
				fprintf(stderr, USAGE, newargv[0]);
				abort();
		}
	}

	FILE *pid_file = fopen(pid_path, "wb");
	if (!pid_file)
		FATAL("fopen failed, %s", strerror(errno));
	fprintf(pid_file, "%d", getpid());
	fclose(pid_file);

	char *process_title = malloc(PROCESS_TITLE_LENGTH); // we do not like waste memory
	if (!process_title)
		FATAL("malloc() failed!");
	snprintf(process_title, PROCESS_TITLE_LENGTH, PROCESS_TITLE, server_port);
	uv_set_process_title(process_title);
	free(process_title);

	LOGI(WELCOME_MESSAGE);

	if (crypt_method == METHOD_SHADOWCRYPT)
		LOGI("Using shadowcrypt crypto");
	else if (crypt_method == METHOD_RC4)
		LOGI("Using RC4 crypto");
	else
		FATAL("Crypto unknown!");

	make_encryptor(NULL, &crypto, crypt_method, password);

	LOGI("Crypto ready");
	
	int err = 1;
	uv_loop_t *loop = uv_default_loop();
	uv_tcp_t listener;

	struct sockaddr_in6 addr;
	uv_ip6_addr(server_listen, server_port, &addr);

	err = uv_tcp_init(loop, &listener);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);

	err = uv_tcp_bind(&listener, (const struct sockaddr*) &addr, 0);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);

	err = uv_listen((uv_stream_t*)(void *)&listener, 5, connect_cb);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);
	LOGI("Listening on %s:%d", server_listen, server_port);

	#ifndef NDEBUG
	setup_signal_handler(loop);
	#endif /* !NDEBUG */

	return uv_run(loop, UV_RUN_DEFAULT);
}
