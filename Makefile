TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O2 -mcmodel=medlow -DSECP256K1_CUSTOM_FUNCS -I deps/secp256k1/src -I deps/secp256k1 -I c
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_LIB := deps/secp256k1/.libs/libsecp256k1.a

all: build/secp256k1_blake160_sighash_all

build/secp256k1_blake160_sighash_all: c/secp256k1_blake160_sighash_all.c $(SECP256K1_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(SECP256K1_LIB):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --host=$(TARGET) && \
		make libsecp256k1.la

clean:
	rm -rf build/secp256k1_blake160_lock build/secp256k1_blake160_sighash_all
	cd deps/secp256k1 && make clean

dist: clean all

.PHONY: all update_schema clean dist
