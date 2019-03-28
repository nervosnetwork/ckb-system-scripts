TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O2 -mcmodel=medlow -DSECP256K1_CUSTOM_FUNCS -I deps/flatcc/include -I deps/secp256k1/src -I deps/secp256k1 -I c
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_LIB := deps/secp256k1/.libs/libsecp256k1.a
FLATCC := deps/flatcc/bin/flatcc

all: build/secp256k1_blake2b_lock

build/secp256k1_blake2b_lock: c/secp256k1_blake2b_lock.c c/protocol_reader.h $(SECP256K1_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

c/protocol_reader.h: c/protocol.fbs $(FLATCC)
	$(FLATCC) -c --reader -o c $<

$(FLATCC):
	cd deps/flatcc && scripts/initbuild.sh make && scripts/build.sh

$(SECP256K1_LIB):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --host=$(TARGET) && \
		make libsecp256k1.la

update_schema: c/protocol_reader.h

clean:
	rm -rf build/secp256k1_blake2b_lock
	cd deps/flatcc && scripts/cleanall.sh
	cd deps/secp256k1 && make clean

dist: clean all

.PHONY: all update_schema clean dist
