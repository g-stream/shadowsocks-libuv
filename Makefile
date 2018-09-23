UNAME := $(shell uname)

RTFLAGS=-lrt
ifeq ($(UNAME), Darwin)
RTFLAGS=-framework CoreServices
endif
OLEVEL=-O2 -DNDEBUG
CFLAGS=-Wall $(OLEVEL) -I libuv/include -std=gnu99 -luv -lsodium 
FILES=server.c utils.c encrypt.c md5.c rc4.c cipher.c
APP=server

all: $(FILES)
	$(CC) $(CFLAGS) -o \
	$(APP) $(FILES) \
	-luv -lpthread -lcrypto -lm $(RTFLAGS)

valgrind: OLEVEL=-O0 -g
valgrind: all
	valgrind --leak-check=full ./server

debug: OLEVEL=-O0 -g
debug: all

gprof: OLEVEL=-O0 -g -pg
gprof: all

test: OLEVEL=-O0 -g
test: FILES=tests.c encrypt.c md5.c rc4.c cipher.c utils.c
test: APP=test
test: all
	./test

clean:
	rm -f server
	rm -rf *.dSYM
	rm -rf test

	
