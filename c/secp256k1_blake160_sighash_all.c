#include "blake2b.h"
#include "ckb_syscalls.h"
#include "protocol_reader.h"
#include "secp256k1_helper.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_PUBKEY_BLAKE160_HASH -3
#define ERROR_SYSCALL -4
#define ERROR_SECP_ABORT -5
#define ERROR_SECP_INITIALIZE -6
#define ERROR_SECP_RECOVER_PUBKEY -7
#define ERROR_SECP_PARSE_SIGNATURE -8
#define ERROR_SECP_SERIALIZE_PUBKEY -9
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_ENCODING -11
#define ERROR_WITNESS_TOO_LONG -12
#define ERROR_INVALID_THRESHOLD -13

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 1024
#define RECID_INDEX 64
/* 32 KB */
#define WITNESS_SIZE 32768

/*
 * Arguments are listed in the following order:
 * 0. program name
 * 1 ~ n. pubkey blake160 hash, blake2b hash of pubkey first 20 bytes, used to
 * shield the real pubkey in lock script, the lock is considered as a multisig
 * lock when the number of pubkeys is more than 1.
 * n + 1. multisig threshold (optional), used to indicate the threshold of a
 * multisig lock, must ignore this arg when only one pubkey is used.
 *
 * Witness:
 * 0 ~ m signature, signatures used to present ownership, the number of signatures
 * must be equals to the threshold if the lock is a multisig lock, otherwise must 
 * use only 1 signature.
 */
int main(int argc, char* argv[]) {
  int ret;
  int recid;
  size_t index = 0;
  uint64_t sigs_cnt = 0;
  uint64_t threshold = 0;
  volatile uint64_t len = 0;
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  unsigned char temp[TEMP_SIZE];
  unsigned char witness[WITNESS_SIZE];
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  mol_pos_t witness_pos;
  size_t witness_len;
  mol_read_res_t arg_res;
  mol_read_res_t bytes_res;

  if (argc < 2 || argc == 3) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  } else if (argc == 2) {
    sigs_cnt = 1;
    threshold = 1;
  } else {
    sigs_cnt = argc - 2;
    threshold = argv[argc - 1][0];
  }

  if (threshold < 1) {
    return ERROR_INVALID_THRESHOLD;
  }

  uint8_t used_signatures[sigs_cnt];

  secp256k1_context context;
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  while (1) {
    len = 0;
    /*
     * Actually we don't need this syscall, we are just making it to grab all
     * input indices for current group, from which we can load the actual
     * witness data we need. `since` field is chosen here since it has a fixed
     * size of 8 bytes, which is both predictable, and also provides minimal
     * cycle consumption.
     */
    ret = ckb_load_input_by_field(NULL, &len, 0, index, CKB_SOURCE_GROUP_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      return 0;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    /* Now we load actual witness data using the same input index above. */
    len = WITNESS_SIZE;
    ret = ckb_load_witness(witness, &len, 0, index, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > WITNESS_SIZE) {
      return ERROR_WITNESS_TOO_LONG;
    }

    witness_pos.ptr = (const uint8_t*)witness;
    witness_pos.size = len;

    /* verify threshold signatures */
    memset(used_signatures, 0, sigs_cnt);

    for (size_t i = 0; i < threshold; i++) {
      /* Load signature */
      arg_res = mol_cut(&witness_pos, MOL_Witness(i));
      if (arg_res.code != 0) {
        return ERROR_ENCODING;
      }

      witness_len = arg_res.attr;

      if (witness_len < threshold) {
        return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
      }

      bytes_res = mol_cut_bytes(&arg_res.pos);
      if (bytes_res.code != 0) {
        return ERROR_ENCODING;
      } else if (bytes_res.pos.size < 65) {
        return ERROR_ENCODING;
      }

      /* The 65th byte is recid according to contract spec.*/
      recid = bytes_res.pos.ptr[RECID_INDEX];
      /* Recover pubkey */
      secp256k1_ecdsa_recoverable_signature signature;
      if (secp256k1_ecdsa_recoverable_signature_parse_compact(
              &context, &signature, bytes_res.pos.ptr, recid) == 0) {
        return ERROR_SECP_PARSE_SIGNATURE;
      }
      blake2b_state blake2b_ctx;
      blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
      blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
      for (size_t i = threshold; i < witness_len; i++) {
        arg_res = mol_cut(&witness_pos, MOL_Witness(i));
        if (arg_res.code != 0) {
          return ERROR_ENCODING;
        }

        bytes_res = mol_cut_bytes(&arg_res.pos);
        if (bytes_res.code != 0) {
          return ERROR_ENCODING;
        }

        blake2b_update(&blake2b_ctx, bytes_res.pos.ptr, bytes_res.pos.size);
      }
      blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

      secp256k1_pubkey pubkey;

      if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, temp) != 1) {
        return ERROR_SECP_RECOVER_PUBKEY;
      }

      /* Check pubkey hash */
      size_t pubkey_size = PUBKEY_SIZE;
      if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                        SECP256K1_EC_COMPRESSED) != 1) {
        return ERROR_SECP_SERIALIZE_PUBKEY;
      }

      len = PUBKEY_SIZE;
      blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
      blake2b_update(&blake2b_ctx, temp, len);
      blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

      uint8_t valid = 0;
      /* compare with all pubkey hash */
      for (size_t i = 0; i < sigs_cnt; i++) {
        if (used_signatures[i] == 1) {
          continue;
        }
        if (memcmp(argv[i + 1], temp, BLAKE160_SIZE) != 0) {
          continue;
        }
        valid = 1;
        used_signatures[i] = 1;
        break;
      }

      if (valid != 1) {
          return ERROR_PUBKEY_BLAKE160_HASH;
      }
    }

    index += 1;
  }
  return ERROR_UNKNOWN;
}
