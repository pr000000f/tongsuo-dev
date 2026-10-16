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
zyhw: zyhw.c ../libcrypto.a
	$(CC) -I../include -o $@ zyhw.c ../libcrypto.a -lpthread

clean:
	rm -rf *.o sm zyhw
