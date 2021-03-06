#include "config.h"
#include "utils.h"
#include <signal.h>
#include <uv.h>

// Convert IPv4 or IPv6 sockaddr to string, DO NOT forget to free the buffer after use!
char *sockaddr_to_str(struct sockaddr_storage *addr)
{
	char *result;
	if (addr->ss_family == AF_INET) { // IPv4
		result = (char *)malloc(INET_ADDRSTRLEN+8);
		if (!result)
			FATAL("malloc() failed!");
		int n = uv_ip4_name((struct sockaddr_in*)addr, result, INET_ADDRSTRLEN);
		if (n) {
			free(result);
			result = NULL;
		}
		int len = strlen(result);
        result[len]=':';
        uint8_t x1 = ((uint8_t*)&(((struct sockaddr_in*)addr)->sin_port))[0];
        uint8_t x2 = ((uint8_t*)&(((struct sockaddr_in*)addr)->sin_port))[1];
        snprintf(result+len+1, 8, "%d", x1*256 + x2);
	} else if (addr->ss_family == AF_INET6) { // IPv4
		result = (char *)malloc(INET6_ADDRSTRLEN);
		if (!result)
			FATAL("malloc() failed!");
		int n = uv_ip6_name((struct sockaddr_in6*)addr, result, INET6_ADDRSTRLEN);
		if (n) {
			free(result);
			result = NULL;
		}
		int len = strlen(result);
        result[len]=':';
        uint8_t x1 = ((uint8_t*)&(((struct sockaddr_in6*)addr)->sin6_port))[0];
        uint8_t x2 = ((uint8_t*)&(((struct sockaddr_in6*)addr)->sin6_port))[1];
        snprintf(result+len+1, 8, "%d", x1*256 + x2);
        
	} else {
		result =  NULL;
	}
	return result;
}



void signal_cb(uv_signal_t* handle, int signum)
{
	extern struct encryptor crypto;
	int err = uv_signal_stop(handle);
	if (err)
		SHOW_UV_ERROR_AND_EXIT(err);
	free(handle);
	LOGI("Ctrl+C Pressed");

	if (crypto.encrypt_table) {
		free(crypto.encrypt_table);
		free(crypto.decrypt_table);
	} else {
		free(crypto.key);
	}

	uv_loop_delete(uv_default_loop()); // Make Valgrind Happy

	exit(0);
}

void setup_signal_handler(uv_loop_t *loop)
{
	signal(SIGPIPE, SIG_IGN);
	
	uv_signal_t *hup = (uv_signal_t *)malloc(sizeof(uv_signal_t));
	if (!hup)
		FATAL("malloc() failed!");

	int n = uv_signal_init(loop, hup);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(n);

	n = uv_signal_start(hup, signal_cb, SIGINT);
	if (n)
		SHOW_UV_ERROR_AND_EXIT(n);
}

void *ss_realloc(void* pt, size_t nz) {
    if(pt){
        void* npt = realloc(pt, nz);
        if(!npt){
            LOGE("Realloc Error");
            return NULL;
        } else {
            return npt;
        }
    } else {
        void *npt = malloc(nz);
        if(!npt){
            LOGE("Malloc Error");
            return NULL;
        } else {
            return npt;
        }
    }
}

void *ss_malloc(size_t size){
    void *npt = malloc(size);
    if(!npt)
        LOGE("Malloc Error");
    return npt;
}
