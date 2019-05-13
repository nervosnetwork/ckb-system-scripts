#include "ckb_syscalls.h"
#include "blake2b.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_PUBKEY_BLAKE160_HASH -3
#define ERROR_LOAD_TX_HASH -4
#define ERROR_SECP_ABORT -5
#define ERROR_SECP_INITIALIZE -6
#define ERROR_SECP_PARSE_PUBKEY -7
#define ERROR_SECP_PARSE_SIGNATURE -8
#define ERROR_SECP_VERIFICATION -9

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33

/* Stripping as much unneeded bytes from secp256k1 as possible */
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

/*
 * Arguments are listed in the following order:
 * 0. program name
 * 1. pubkey blake160 hash, blake2b hash of pubkey first 20 bytes, used to shield the real
 * pubkey in lock script.
 *
 * Witness:
 * 2. pubkey, real pubkey used to identify token owner
 * 3. signature, signature used to present ownership
 * 4. signature size, in little endian 64 bit unsigned integer
 */
int main(int argc, char* argv[])
{
  uint64_t signature_size = 0;
  if (argc != 5) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }
  signature_size = *((uint64_t *) argv[4]);

  const unsigned char* binary_pubkey_hash = argv[1];
  const unsigned char* binary_pubkey = argv[2];
  const unsigned char* binary_signature = argv[3];

  unsigned char hash[BLAKE2B_BLOCK_SIZE];

  /* Check pubkey hash */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, binary_pubkey, PUBKEY_SIZE);
  blake2b_final(&blake2b_ctx, hash, BLAKE2B_BLOCK_SIZE);

  if (memcmp(binary_pubkey_hash, hash, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  secp256k1_context context;
  if (secp256k1_context_initialize(&context, SECP256K1_CONTEXT_VERIFY) == 0) {
    return ERROR_SECP_INITIALIZE;
  }

  secp256k1_pubkey pubkey;
  if (secp256k1_ec_pubkey_parse(&context, &pubkey, binary_pubkey, PUBKEY_SIZE) == 0) {
    return ERROR_SECP_PARSE_PUBKEY;
  }

  secp256k1_ecdsa_signature signature;
  if (secp256k1_ecdsa_signature_parse_der(&context, &signature, binary_signature, signature_size) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  uint64_t size = BLAKE2B_BLOCK_SIZE;
  if (ckb_load_tx_hash(hash, &size, 0) != CKB_SUCCESS || size != BLAKE2B_BLOCK_SIZE) {
    return ERROR_LOAD_TX_HASH;
  }

  if (secp256k1_ecdsa_verify(&context, &signature, hash, &pubkey) != 1) {
    return ERROR_SECP_VERIFICATION;
  }
  return 0;
}
