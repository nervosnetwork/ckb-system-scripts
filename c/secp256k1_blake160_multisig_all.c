#include "blake2b.h"
#include "ckb_syscalls.h"
#include "protocol_reader.h"
#include "secp256k1_helper.h"

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_PARSE_SIGNATURE -12
#define ERROR_SECP_SERIALIZE_PUBKEY -13
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_TOO_LONG -22
#define ERROR_WITNESS_TOO_SHORT -23
#define ERROR_INVALID_PUBKEYS_CNT -24
#define ERROR_INVALID_THRESHOLD -25
#define ERROR_INVALID_REQUIRE_FIRST_N -26
#define ERROR_MULTSIG_SCRIPT_HASH -31
#define ERROR_VERIFICATION -32

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 1024
#define RECID_INDEX 64
/* 32 KB */
#define WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65
#define FLAGS_SIZE 4

/*
 * Arguments:
 * multisig script blake160 hash, 20 bytes.
 *
 * Witness:
 * multisig_script | Signature1 | signature2 | ...
 * multisig_script: S | R | M | N | Pubkey1 | Pubkey2 | ...
 *
 * +------------+----------------------------------+-------+
 * |            |           Description            | Bytes |
 * +------------+----------------------------------+-------+
 * | S          | reserved for future use          |     1 |
 * | R          | first nth public keys must match |     1 |
 * | M          | threshold                        |     1 |
 * | N          | total public keys                |     1 |
 * | PubkeyN    | compressed pubkey                |    33 |
 * | SignatureN | recoverable signature            |    65 |
 * +------------+----------------------------------+-------+
 *
 */

int main() {
  int ret;
  volatile uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_pos_t script_pos;
  script_pos.ptr = (const uint8_t*)script;
  script_pos.size = len;

  mol_read_res_t args_res = mol_cut(&script_pos, MOL_Script_args());
  if (args_res.code != 0) {
    return ERROR_ENCODING;
  }
  mol_read_res_t args_bytes_res = mol_cut_bytes(&args_res.pos);
  if (args_bytes_res.code != 0) {
    return ERROR_ENCODING;
  } else if (args_bytes_res.pos.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  unsigned char witness[WITNESS_SIZE];
  len = WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > WITNESS_SIZE) {
    return ERROR_WITNESS_TOO_LONG;
  }
  if (len < FLAGS_SIZE) {
    return ERROR_WITNESS_TOO_SHORT;
  }

  /* Get flags */
  uint8_t pubkeys_cnt = witness[3];
  uint8_t threshold = witness[2];
  uint8_t require_first_n = witness[1];
  if (pubkeys_cnt == 0) {
    return ERROR_INVALID_PUBKEYS_CNT;
  }
  if (threshold > pubkeys_cnt) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (threshold == 0) {
    threshold = pubkeys_cnt;
  }
  if (require_first_n > threshold) {
    return ERROR_INVALID_REQUIRE_FIRST_N;
  }
  size_t multisig_script_len = FLAGS_SIZE + PUBKEY_SIZE * pubkeys_cnt;
  size_t required_witness_len = multisig_script_len + SIGNATURE_SIZE * threshold;
  if (len < required_witness_len) {
    return ERROR_WITNESS_TOO_SHORT;
  }
  size_t extra_witness_len = len - required_witness_len;

  /* Check multisig script hash */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, witness, multisig_script_len);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(args_bytes_res.pos.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_MULTSIG_SCRIPT_HASH;
  }

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Load extra witness of first input and all witnesses of other inputs */
  if (extra_witness_len > 0) {
    blake2b_update(&blake2b_ctx, &witness[required_witness_len], extra_witness_len);
  }
  size_t i = 1;
  while (1) {
    len = WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > WITNESS_SIZE) {
      return ERROR_WITNESS_TOO_LONG;
    }
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  /* Verify threshold signatures */
  uint8_t used_signatures[threshold];
  memset(used_signatures, 0, threshold);

  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  size_t signature_offset = multisig_script_len;
  for (size_t i = 0; i < threshold; i++) {
    /* Load signature */
    secp256k1_ecdsa_recoverable_signature signature;
    signature_offset += i * SIGNATURE_SIZE;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, &witness[signature_offset], witness[signature_offset + RECID_INDEX]) == 0) {
      return ERROR_SECP_PARSE_SIGNATURE;
    }

    /* Recover pubkey */
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
      return ERROR_SECP_RECOVER_PUBKEY;
    }

    size_t pubkey_size = PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                      SECP256K1_EC_COMPRESSED) != 1) {
      return ERROR_SECP_SERIALIZE_PUBKEY;
    }

    /* Check pubkeys */
    uint8_t matched = 0;
    for (size_t i = 0; i < pubkeys_cnt; i++) {
      if (used_signatures[i] == 1) {
        continue;
      }
      if (memcmp(&witness[FLAGS_SIZE + i * PUBKEY_SIZE], temp, PUBKEY_SIZE) != 0) {
        continue;
      }
      matched = 1;
      used_signatures[i] = 1;
      break;
    }

    if (matched != 1) {
      return ERROR_VERIFICATION;
    }
  }

  if (require_first_n > 0) {
    for (size_t i = 0; i < require_first_n; i++) {
      if (used_signatures[i] != 1) {
        return ERROR_VERIFICATION;
      }
    }
  }

  return 0;
}
