#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "ckb_syscalls.h"
#include "blake2b.h"
#include "protocol_reader.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(Ckb_Protocol, x)

#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -1
#define ERROR_WRONG_HEX_ENCODING -2
#define ERROR_SECP_ABORT -3
#define ERROR_LOAD_TX -4
#define ERROR_PARSE_TX -5
#define ERROR_SECP_INITIALIZE -6
#define ERROR_SECP_PARSE_PUBKEY -7
#define ERROR_SECP_PARSE_SIGNATURE -8
#define ERROR_PARSE_SIGHASH_TYPE -9
#define ERROR_LOAD_SELF_OUT_POINT -10
#define ERROR_PARSE_SELF_OUT_POINT -11
#define ERROR_LOAD_SELF_LOCK_HASH -12
#define ERROR_LOAD_LOCK_HASH -13
#define ERROR_INVALID_SIGHASH_TYPE -14
#define ERROR_SECP_VERIFICATION -15
#define ERROR_PARSE_SINGLE_INDEX -16
#define ERROR_SINGLE_INDEX_IS_INVALID -17
#define ERROR_PUBKEY_BLAKE160_HASH -18
#define ERROR_PUBKEY_BLAKE160_HASH_LENGTH -18

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20

#define CUSTOM_ABORT 1
#define CUSTOM_PRINT_ERR 1

void custom_abort()
{
  syscall(SYS_exit, ERROR_SECP_ABORT, 0, 0, 0, 0, 0);
}

int custom_print_err(const char * arg, ...)
{
  (void) arg;
  return 0;
}

#include <secp256k1_static.h>
/*
 * We are including secp256k1 implementation directly so gcc can strip
 * unused functions. For some unknown reasons, if we link in libsecp256k1.a
 * directly, the final binary will include all functions rather than those used.
 */
#include <secp256k1.c>

int char_to_int(char ch)
{
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  return ERROR_WRONG_HEX_ENCODING;
}

int hex_to_bin(char* buf, size_t buf_len, const char* hex)
{
  int i = 0;

  for (; i < buf_len && hex[i * 2] != '\0' && hex[i * 2 + 1] != '\0'; i++) {
    int a = char_to_int(hex[i * 2]);
    int b = char_to_int(hex[i * 2 + 1]);

    if (a < 0 || b < 0) {
      return ERROR_WRONG_HEX_ENCODING;
    }

    buf[i] = ((a & 0xF) << 4) | (b & 0xF);
  }

  if (i == buf_len && hex[i * 2] != '\0') {
    return ERROR_WRONG_HEX_ENCODING;
  }
  return i;
}

#define CHECK_LEN(x) if ((x) <= 0) { return x; }

#define TX_BUFFER_SIZE 1024 * 1024
#define TEMP_BUFFER_SIZE 256

void update_h256(blake2b_state *ctx, ns(H256_struct_t) h256)
{
  uint8_t buf[32];

  if (!h256) {
    return;
  }

  buf[0] = ns(H256_u0(h256));
  buf[1] = ns(H256_u1(h256));
  buf[2] = ns(H256_u2(h256));
  buf[3] = ns(H256_u3(h256));
  buf[4] = ns(H256_u4(h256));
  buf[5] = ns(H256_u5(h256));
  buf[6] = ns(H256_u6(h256));
  buf[7] = ns(H256_u7(h256));
  buf[8] = ns(H256_u8(h256));
  buf[9] = ns(H256_u9(h256));
  buf[10] = ns(H256_u10(h256));
  buf[11] = ns(H256_u11(h256));
  buf[12] = ns(H256_u12(h256));
  buf[13] = ns(H256_u13(h256));
  buf[14] = ns(H256_u14(h256));
  buf[15] = ns(H256_u15(h256));
  buf[16] = ns(H256_u16(h256));
  buf[17] = ns(H256_u17(h256));
  buf[18] = ns(H256_u18(h256));
  buf[19] = ns(H256_u19(h256));
  buf[20] = ns(H256_u20(h256));
  buf[21] = ns(H256_u21(h256));
  buf[22] = ns(H256_u22(h256));
  buf[23] = ns(H256_u23(h256));
  buf[24] = ns(H256_u24(h256));
  buf[25] = ns(H256_u25(h256));
  buf[26] = ns(H256_u26(h256));
  buf[27] = ns(H256_u27(h256));
  buf[28] = ns(H256_u28(h256));
  buf[29] = ns(H256_u29(h256));
  buf[30] = ns(H256_u30(h256));
  buf[31] = ns(H256_u31(h256));
  blake2b_update(ctx, buf, 32);
}

void update_uint32_t(blake2b_state *ctx, uint32_t v)
{
  char buf[32];
  snprintf(buf, 32, "%d", v);
  blake2b_update(ctx, buf, strlen(buf));
}

void update_uint64_t(blake2b_state *ctx, uint64_t v)
{
  char buf[32];
  snprintf(buf, 32, "%ld", v);
  blake2b_update(ctx, buf, strlen(buf));
}

void update_out_point(blake2b_state *ctx, ns(OutPoint_table_t) outpoint)
{
  update_h256(ctx, ns(OutPoint_tx_hash(outpoint)));
  update_uint32_t(ctx, ns(OutPoint_index(outpoint)));
}


/*
 * Arguments are listed in the following order:
 * 0. program name
 * 1. pubkey blake160 hash, blake2b hash of pubkey first 20 bytes, used to shield the real
 * pubkey in lock script.
 * 
 * Witness:
 * 2. pubkey, real pubkey used to identify token owner
 * 3. signature, signature used to present ownership
 */
int main(int argc, char* argv[])
{
  unsigned char hash[BLAKE2B_BLOCK_SIZE];
  char tx_buf[TX_BUFFER_SIZE];
  char buf[TEMP_BUFFER_SIZE];
  int ret, len;

  if (argc != 4) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  /* Check pubkey hash */
  len = hex_to_bin(buf, TEMP_BUFFER_SIZE, argv[argc - 2]);
  CHECK_LEN(len);
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, buf, len);
  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  /* tx_buf is not yet used, we can borrow it as a temp buffer */
  if (hex_to_bin(tx_buf, BLAKE160_SIZE, argv[1]) != BLAKE160_SIZE) {
    return ERROR_PUBKEY_BLAKE160_HASH_LENGTH;
  }
  if (memcmp(tx_buf, hash, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  secp256k1_context context;
  if (secp256k1_context_initialize(&context, SECP256K1_CONTEXT_VERIFY) == 0) {
    return ERROR_SECP_INITIALIZE;
  }

  secp256k1_pubkey pubkey;
  ret = secp256k1_ec_pubkey_parse(&context, &pubkey, buf, len);
  if (ret == 0) {
    return ERROR_SECP_PARSE_PUBKEY;
  }

  ret = hex_to_bin(buf, TEMP_BUFFER_SIZE, argv[argc - 1]);
  CHECK_LEN(ret);
  secp256k1_ecdsa_signature signature;
  ret = secp256k1_ecdsa_signature_parse_der(&context, &signature, buf, ret);
  if (ret == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  volatile uint64_t tx_size = TX_BUFFER_SIZE;
  if (ckb_load_tx(tx_buf, &tx_size, 0) != CKB_SUCCESS) {
    return ERROR_LOAD_TX;
  }

  ns(Transaction_table_t) tx;
  if (!(tx = ns(Transaction_as_root(tx_buf)))) {
    return ERROR_PARSE_TX;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);

  /* Hash all inputs */
  ns(CellInput_vec_t) inputs = ns(Transaction_inputs(tx));
  size_t inputs_len = ns(CellInput_vec_len(inputs));
  for (int i = 0; i < inputs_len; i++) {
    ns(CellInput_table_t) input = ns(CellInput_vec_at(inputs, i));
    update_h256(&blake2b_ctx, ns(CellInput_tx_hash(input)));
    update_uint32_t(&blake2b_ctx, ns(CellInput_index(input)));
  }

  /* Hash all outputs */
  ns(CellOutput_vec_t) outputs = ns(Transaction_outputs(tx));
  size_t outputs_len = ns(CellOutput_vec_len(outputs));
  for (int i = 0; i < outputs_len; i++) {
    ns(CellOutput_table_t) output = ns(CellOutput_vec_at(outputs, i));
    update_uint64_t(&blake2b_ctx, ns(CellOutput_capacity(output)));
    volatile uint64_t len = TEMP_BUFFER_SIZE;
    if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH) != CKB_SUCCESS) {
      return ERROR_LOAD_LOCK_HASH;
    }
    blake2b_update(&blake2b_ctx, buf, len);
    len = TEMP_BUFFER_SIZE;
    if (ckb_load_cell_by_field(buf, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH) == CKB_SUCCESS) {
      blake2b_update(&blake2b_ctx, buf, len);
    }
  }

  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  ret = secp256k1_ecdsa_verify(&context, &signature, hash, &pubkey);
  if (ret != 1) {
    return ERROR_SECP_VERIFICATION;
  }
  return 0;
}
