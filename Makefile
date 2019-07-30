TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O3 -Ideps/flatcc/include -I deps/secp256k1/src -I deps/secp256k1 -I c -Wall -Werror -Wno-nonnull-compare
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_LIB := deps/secp256k1/.libs/libsecp256k1.a
FLATCC := deps/flatcc/bin/flatcc

# docker pull xxuejie/riscv-gnu-toolchain-rv64imac:xenial-20190606
BUILDER_DOCKER := xxuejie/riscv-gnu-toolchain-rv64imac@sha256:4f71556b7ea8f450243e2b2483bca046da1c0d76c2d34d120aa0fbf1a0688ec0

all: specs/cells/secp256k1_blake160_sighash_all specs/cells/dao

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/secp256k1_blake160_sighash_all: c/secp256k1_blake160_sighash_all.c c/protocol_reader.h $(SECP256K1_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

specs/cells/dao: c/dao.c c/protocol_reader.h
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

publish:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo publish --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo package --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package-clean:
	git checkout Cargo.toml Cargo.lock
	rm -rf Cargo.toml.bak target/package/

clean:
	rm -rf build/secp256k1_blake160_sighash_all
	cd deps/flatcc && scripts/cleanall.sh
	cd deps/secp256k1 && make clean

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
