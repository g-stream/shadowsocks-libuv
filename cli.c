#include "cli.h"
#include "utils.h"
#include "cipher.h"
#include <string.h>
#include "config.h"
#include "server.h"
#include <unistd.h>
#include <stdlib.h>
void show_usage(){
    printf(USAGE);
    fflush(stdout);
}

enum OPT {
    L = 0,
    P,
    K,
    M,
    C,
    OPT_MAX
};

static int opt_case(const char* opt_name){
    if(strcmp(opt_name, "-p") == 0) return P;
    if(strcmp(opt_name, "-k") == 0) return K;
    if(strcmp(opt_name, "-m") == 0) return M;
    if(strcmp(opt_name, "-l") == 0) return L;
    if(strcmp(opt_name, "-c") == 0) return C;
    LOGE("error option");
    return -1;
}

int parse_opt_file(const char* file_name, G* g){
    return 0;
}

int parse_opt(int argc, char** argv, G* g) {
    if(argc > 9 || argc <= 1) {
        LOGE("error option");
        show_usage();
        return -1;
    }
    int init_method = -1; //0 for -p xxx -l xxx -k xxx -m xxx; 1 for -c xxx
    
    const char* tunnel_port = NULL;
    const char* tunnel_cipher_method = NULL;
    const char* tunnel_cipher_pass = NULL;
    const char* tunnel_cipher_listen = NULL;
    
    for(int i = 1; i < argc; ++i){
        int o = opt_case(argv[i]);
        if( o == -1 ){
            show_usage();
        }
        if(init_method == -1){
            init_method = (o == C)? 1:0;
        }
        if((o != C && init_method == 1) || (o == C && init_method == 0)){
            LOGE("error option");
            show_usage();
            return -1;
        }
        if( ++i >= argc){
            LOGE("error option");
            show_usage();
            return -1;
        }
        switch(o){
            case C:
                LOGE("haven't implemented");
                parse_opt_file(argv[i], g);
                break;
            case P:
                tunnel_port = argv[i];
                break;
            case K:
                tunnel_cipher_pass = argv[i];
                break;
            case M:
                tunnel_cipher_method = argv[i];
                break;
            case L:
                tunnel_cipher_listen = argv[i];
                break;
        }
    }
    if(init_method == 0 && tunnel_port && tunnel_cipher_method && tunnel_cipher_pass){
        new_tunnel(g, NULL, tunnel_cipher_listen, atoi(tunnel_port), tunnel_cipher_method, tunnel_cipher_pass);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    G g;
    init_G(&g);
    parse_opt(argc, argv, &g);
#ifdef DEBUG
    
    if(g.tunnels_head){
        LOGI("have head");
        LOGI("%d:%d  port:%d", g.tunnels_head->cipher.info.type, g.tunnels_head->cipher.info.id, g.tunnels_head->port);
    } else {
        LOGI("have no head");
    }
#endif

    /*while(
	char **newargv = uv_setup_args(argc, argv);
	char *server_listen = SERVER_LISTEN;
	int server_port = SERVER_PORT;
	uint8_t *password = (uint8_t *)PASSWORD;
	uint8_t crypt_method = CRYPTO_METHOD;
	
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
*/
    char *pid_path = PID_FILE;
	FILE *pid_file = fopen(pid_path, "wb");
	if (!pid_file)
		FATAL("fopen failed, %s", strerror(errno));
	fprintf(pid_file, "%d", getpid());
	fclose(pid_file);

	char *process_title = malloc(PROCESS_TITLE_LENGTH); // we do not like waste memory
	if (!process_title)
		FATAL("malloc() failed!");
	snprintf(process_title, PROCESS_TITLE_LENGTH, PROCESS_TITLE);
	uv_set_process_title(process_title);
	free(process_title);

    
	LOGI(WELCOME_MESSAGE);
    uv_loop_t *loop = uv_default_loop();
    
    if(!g.tunnels_head){
        LOGE("No tunnel");
        abort();
    }
    tunnel_t* t = g.tunnels_head;
    while(t) {
        tunnel_establish(loop, t);
        t = t->next;
    }
    #ifndef NDEBUG
	setup_signal_handler(loop);
	#endif /* !NDEBUG */
	return uv_run(loop, UV_RUN_DEFAULT);
}
