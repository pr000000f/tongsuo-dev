CC=gcc
CFLAGS=-I/Users/Paul/work/tmp/tongsuo/include
LDFLAGS=-L/Users/Paul/work/tmp/tongsuo/lib

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

perf: sm.o
	$(CC) -o sm sm.o -lcrypto $(LDFLAGS)

# ZYHW example.  Build the library first, from the Tongsuo root:
#   ./Configure darwin64-arm64-cc no-shared enable-paea && make -j8
# Then: make -C examples zyhw && ./examples/zyhw
zyhw: zyhw.c paea_zyhw_demo.c ../libcrypto.a
	$(CC) -I../include -o $@ zyhw.c ../libcrypto.a -lpthread

paea_evp: paea_evp.c ../libcrypto.a
	$(CC) -I../include -o $@ paea_evp.c ../libcrypto.a -lpthread

PAEA_DEMO_CFLAGS ?= -Wall -Wextra
PAEA_DEMO_LDLIBS ?= -lpthread

.PHONY: paea_demos test_paea_demos
paea_demos: paea_zyhw_demo paea_yzw_demo

paea_zyhw_demo paea_yzw_demo: %: %.c ../libcrypto.a ../include/openssl/paea.h
	$(CC) $(CPPFLAGS) -I../include $(PAEA_DEMO_CFLAGS) -o $@ $< ../libcrypto.a $(PAEA_DEMO_LDLIBS)

test_paea_demos: paea_demos
	./paea_zyhw_demo
	./paea_yzw_demo

clean:
	rm -rf *.o sm zyhw paea_evp paea_zyhw_demo paea_yzw_demo
