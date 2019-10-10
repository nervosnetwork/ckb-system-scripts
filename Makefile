TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
CFLAGS := -O3 -Ideps/molecule -I deps/secp256k1/src -I deps/secp256k1 -I c -I build -Wall -Werror -Wno-nonnull-compare -Wno-unused-function
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-s
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := 60c3f87e31f061e29fbe3e7d283245056d226c37
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:bionic-20190702
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:7b168b4b109a0f741078a71b7c4dddaf1d283a5244608f7851f5714fbad273ba

all: specs/cells/secp256k1_blake160_sighash_all specs/cells/dao specs/cells/secp256k1_ripemd160_sha256_sighash_all

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/secp256k1_blake160_sighash_all: c/secp256k1_blake160_sighash_all.c ${PROTOCOL_HEADER} build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

specs/cells/dao: c/dao.c ${PROTOCOL_HEADER}
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

specs/cells/secp256k1_ripemd160_sha256_sighash_all: c/secp256k1_ripemd160_sha256_sighash_all.c ${PROTOCOL_HEADER} build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc $(CFLAGS) -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

generate-protocol: check-moleculec-version ${PROTOCOL_HEADER}

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	wget -O $@ ${PROTOCOL_URL}

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

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
	rm -rf ${PROTOCOL_HEADER} ${PROTOCOL_SCHEMA}
	rm -rf specs/cells/secp256k1_blake160_sighash_all specs/cells/dao
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf specs/cells/secp256k1_data
	rm -rf spec/cells/secp256k1_ripemd160_sha256_sighash_all
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean
	cargo clean

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
