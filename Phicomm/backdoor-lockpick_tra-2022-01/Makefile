export C_INCLUDE_PATH=/usr/lib/musl/include
LDFLAGS=-Llib/libcrypto.a -static 
DEBUG=-O0 -g
RELEASE=-Os
OPENSSL_DIR=openssl-1.0.2
CFLAGS=-I$(OPENSSL_DIR)/include -Wall $(DEBUG)
CC=musl-gcc
OUT=lockpick

$(OUT): lockpick.c lib/libcrypto.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	# strip $(OUT)

libs: lib/libcrypto.a lib/libtelnet.a

lib/libcrypto.a: openssl-1.0.2/libcrypto.a
	mkdir -p lib/
	cp $< lib/

lib/libtelnet.a: libtelnet-0.23/.libs/libtelnet.a
	mkdir -p lib/
	cp $< lib/

libtelnet-0.23/.libs/libtelnet.a:
	./mk-libtelnet.sh

openssl-1.0.2/libcrypto.a:
	./mk-libcrypto.sh

test: $(OUT)
	./$(OUT) test

run: $(OUT)
	./$(OUT) 192.168.98.1

clean: 
	rm -f lockpick libcrypto.a

distclean: clean
	make -C openssl-1.0.2 clean
