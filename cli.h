#ifndef CLI_H_
#define CLI_H_
#include <uv.h>
#include "server.h"
#define SHADOW_MAJOR_VERSION 0
#define SHADOW_MINOR_VERSION 2
#define WELCOME_MESSAGE "Shadowsocks Version:" TOSTR(SHADOW_MAJOR_VERSION) "." TOSTR(SHADOW_MINOR_VERSION) \
                        " libuv(" TOSTR(UV_VERSION_MAJOR) "." TOSTR(UV_VERSION_MINOR) ")"\
                        " Written by Dndx(idndx.com)"
#define USAGE "Shadowsocks Version:" TOSTR(SHADOW_MAJOR_VERSION) "." TOSTR(SHADOW_MINOR_VERSION) \
                        " libuv(" TOSTR(UV_VERSION_MAJOR) "." TOSTR(UV_VERSION_MINOR) ")"\
                        " Written by Dndx(idndx.com)\n"\
                        "Usage: suv -p port -k password -m cipher_method\n"\
                        "       suv -c ss.config\n\n"\
                        "Options:\n"\
                        "  -p : listening port\n"\
                        "  -k : password\n"\
                        "  -m : encryption method\n\n"
#define PROCESS_TITLE "shadowsocks-libuv"
#define PROCESS_TITLE_LENGTH 20

                        

int parse_opt(int argc, char** argv, G* g);


#endif
