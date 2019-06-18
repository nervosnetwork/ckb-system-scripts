TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O2 -mcmodel=medlow -DSECP256K1_CUSTOM_FUNCS -I deps/flatcc/include -I deps/secp256k1/src -I deps/secp256k1 -I c -Wall -Werror -Wno-nonnull-compare
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_LIB := deps/secp256k1/.libs/libsecp256k1.a
FLATCC := deps/flatcc/bin/flatcc

all: build/secp256k1_blake160_sighash_all

build/secp256k1_blake160_sighash_all: c/secp256k1_blake160_sighash_all.c c/protocol_reader.h $(SECP256K1_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(SECP256K1_LIB):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make libsecp256k1.la

c/protocol_reader.h: c/protocol.fbs $(FLATCC)
	$(FLATCC) -c --reader -o c $<


$(FLATCC):
	cd deps/flatcc && scripts/initbuild.sh make && scripts/build.sh

ci:
	docker run --rm -v `pwd`:/code xxuejie/riscv-gnu-toolchain-rv64imac:xenial-20190606 bash -c "cd /code && make"
	cp -f build/secp256k1_blake160_sighash_all specs/cells/
	git diff --exit-code
	cargo test --all

clean:
	rm -rf build/secp256k1_blake160_sighash_all
	cd deps/flatcc && scripts/cleanall.sh
	cd deps/secp256k1 && make clean

dist: clean all

.PHONY: all update_schema clean dist
