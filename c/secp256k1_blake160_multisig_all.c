// # secp256k1-blake160-multisig-all
//
// This is a lock script that serves multiple purposes:
//
// * It provides a multiple signature verification solution
// * It provides a way to enforce lock period to a cell.
//
// It uses a similar (but slightly different) way to prepare the signing message
// as the [single signing script](./secp256k1_blake160_sighash_all). What's different,
// is that the lock field of the first witness treated as WitnessArgs object, uses the
// following structure:
//
// multisig_script | Signature1 | Signature2 | ...
//
// Where the components are of the following format:
//
// multisig_script: S | R | M | N | PubKeyHash1 | PubKeyHash2 | ...
//
// +-------------+------------------------------------+-------+
// |             |           Description              | Bytes |
// +-------------+------------------------------------+-------+
// | S           | reserved field, must be zero       |     1 |
// | R           | first nth public keys must match   |     1 |
// | M           | threshold                          |     1 |
// | N           | total public keys                  |     1 |
// | PubkeyHashN | blake160 hash of compressed pubkey |    20 |
// | SignatureN  | recoverable signature              |    65 |
// +-------------+------------------------------------+-------+
//
// To preserve script size, this lock script also uses a scheme similar to Bitcoin's
// P2SH solution: the script args part only contains the blake160 hash of `multisig_script`
// part, this way no matter how many public keys we are including, and how many signatures
// we are testing, the lock script size remains a constant value. One implicit rule, is that
// `multisig_script` remains a constant since the hash is already fixed in script args part.

// First we will need to include a few headers here, for legacy reasons, this repository
// ships with those headers. We are now maintaining a new [repository](https://github.com/nervosnetwork/ckb-c-stdlib)
// with most of those headers included. If you are building a new script, we do recommend
// you to take a look at what's in the new repository, and use the code there directly.
#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"

// Script args validation errors
#define ERROR_INVALID_RESERVE_FIELD -41
#define ERROR_INVALID_PUBKEYS_CNT -42
#define ERROR_INVALID_THRESHOLD -43
#define ERROR_INVALID_REQUIRE_FIRST_N -44
// Multi-sigining validation errors
#define ERROR_MULTSIG_SCRIPT_HASH -51
#define ERROR_VERIFICATION -52

// Common definitions here, one important limitation, is that this lock script only works
// with scripts and witnesses that are no larger than 32KB. We believe this should be enough
// for most cases.
//
// Here we are also employing a common convention: we append the recovery ID to the end of
// the 64-byte compact recoverable signature.
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define MAX_SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65
#define FLAGS_SIZE 4

// Compile-time guard against buffer abuse
#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (MAX_SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

// To use this script, the script args part must contain the blake160 hash of the
// `multisig_script` part mentioned above. The blake160 hash is calculated as the
// first 20 bytes of the blake2b hash(with "ckb-default-hash" as personalization).
//
// The args part can store an optional 64-bit unsigned little endian value denoting
// a lock period. The format of the lock period value should confront to the
// [RFC specification](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md).
int main() {
  int ret;
  uint64_t len;
  unsigned char temp[TEMP_SIZE];

  // First let's load and extract script args part, which is also the blake160 hash of public
  // key from current running script.
  unsigned char script[MAX_SCRIPT_SIZE];
  len = MAX_SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > MAX_SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  // The script args part should either be 20 bytes(containing only the blake160 hash),
  // or 28 bytes(containing blake160 hash and since value).
  if (args_bytes_seg.size != BLAKE160_SIZE &&
      args_bytes_seg.size != BLAKE160_SIZE + sizeof(uint64_t)) {
    return ERROR_ARGUMENTS_LEN;
  }
  // Extract optional since value.
  if (args_bytes_seg.size == BLAKE160_SIZE + sizeof(uint64_t)) {
    uint64_t since = *(uint64_t *)&args_bytes_seg.ptr[BLAKE160_SIZE];
    // Check lock period logic, we have prepared a handy utility function for this.
    ret = check_since(since);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  // Load the first witness, or the witness of the same index as the first input using
  // current script.
  unsigned char witness[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // We will treat the first witness as WitnessArgs object, and extract the lock field
  // from the object.
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(witness, witness_len, &lock_bytes_seg);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (lock_bytes_seg.size < FLAGS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // This is more of a safe guard, since lock is a field in witness, it
  // cannot exceed the maximum size of the enclosing witness, this way
  // we should still be at the safe side even if any of the lock extracting
  // code has a bug.
  if (lock_bytes_seg.size > witness_len) {
    return ERROR_ENCODING;
  }
  // Keep the full lock field somewhere, since later we will modify this field in place.
  unsigned char lock_bytes[lock_bytes_seg.size];
  uint64_t lock_bytes_len = lock_bytes_seg.size;
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_len);

  // Extract multisig script flags.
  uint8_t pubkeys_cnt = lock_bytes[3];
  uint8_t threshold = lock_bytes[2];
  uint8_t require_first_n = lock_bytes[1];
  uint8_t reserved_field = lock_bytes[0];
  if (reserved_field != 0) {
    return ERROR_INVALID_RESERVE_FIELD;
  }
  if (pubkeys_cnt == 0) {
    return ERROR_INVALID_PUBKEYS_CNT;
  }
  if (threshold > pubkeys_cnt) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (threshold == 0) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (require_first_n > threshold) {
    return ERROR_INVALID_REQUIRE_FIRST_N;
  }
  // Based on the number of public keys and thresholds, we can calculate
  // the required length of the lock field.
  size_t multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * pubkeys_cnt;
  size_t signatures_len = SIGNATURE_SIZE * threshold;
  size_t required_lock_len = multisig_script_len + signatures_len;
  if (lock_bytes_len != required_lock_len) {
    return ERROR_WITNESS_SIZE;
  }

  // Perform hash check of the `multisig_script` part, notice the signature part
  // is not included here.
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, lock_bytes, multisig_script_len);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(args_bytes_seg.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_MULTSIG_SCRIPT_HASH;
  }

  // Load the current transaction hash.
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  // Erase the signature part to all zeros, so we can prepare the sining message.
  memset((void *)(lock_bytes_seg.ptr + multisig_script_len), 0, signatures_len);
  // Here we start to prepare the message used in signature verification. First, let's
  // hash the just loaded transaction hash.
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
  // Before hashing each witness, we need to hash the witness length first as a 64-bit
  // unsigned little endian integer.
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  // Like shown above, we will fill the signature section with all 0, then used the modified
  // first witness here as the value to hash.
  blake2b_update(&blake2b_ctx, witness, witness_len);

  // Let's loop and hash all witnesses with the same indices as the remaining input cells
  // using current running lock script.
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    // Using *CKB_SOURCE_GROUP_INPUT* as the source value provides us with a quick way to
    // loop through all input cells using current running lock script. We don't have to
    // loop and check each individual cell by ourselves.
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    // Before hashing each witness, we need to hash the witness length first as a 64-bit
    // unsigned little endian integer.
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }

  // For safety consideration, this lock script will also hash and guard all witnesses that
  // have index values equal to or larger than the number of input cells. It assumes all
  // witnesses that do have an input cell with the same index, will be guarded by the lock
  // script of the input cell.
  //
  // For convenience reason, we provide a utility function here to calculate the number of
  // input cells in a transaction.
  i = calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    // Here we are guarding input cells with any arbitrary lock script, hence we are using
    // the plain *CKB_SOURCE_INPUT* source to loop all witnesses.
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }
    // Before hashing each witness, we need to hash the witness length first as a 64-bit
    // unsigned little endian integer.
    blake2b_update(&blake2b_ctx, (char *)&len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, len);
    i += 1;
  }
  // Now the message preparation is completed.
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  // Verify threshold signatures, threshold is a uint8_t, at most it is
  // 255, meaning this array will definitely have a reasonable upper bound.
  // Also this code uses C99's new feature to allocate a variable length array.
  uint8_t used_signatures[pubkeys_cnt];
  memset(used_signatures, 0, pubkeys_cnt);

  // We are using bitcoin's [secp256k1 library](https://github.com/bitcoin-core/secp256k1)
  // for signature verification here. To the best of our knowledge, this is an unmatched
  // advantage of CKB: you can ship cryptographic algorithm within your smart contract,
  // you don't have to wait for the foundation to ship a new cryptographic algorithm. You
  // can just build and ship your own.
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  // We will perform *threshold* number of signature verifications here.
  for (size_t i = 0; i < threshold; i++) {
    // Load signature
    secp256k1_ecdsa_recoverable_signature signature;
    size_t signature_offset = multisig_script_len + i * SIGNATURE_SIZE;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, &lock_bytes[signature_offset],
            lock_bytes[signature_offset + RECID_INDEX]) == 0) {
      return ERROR_SECP_PARSE_SIGNATURE;
    }

    // verifiy signature and Recover pubkey
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
      return ERROR_SECP_RECOVER_PUBKEY;
    }

    // Calculate the blake160 hash of the derived public key
    size_t pubkey_size = PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                      SECP256K1_EC_COMPRESSED) != 1) {
      return ERROR_SECP_SERIALIZE_PUBKEY;
    }

    unsigned char calculated_pubkey_hash[BLAKE2B_BLOCK_SIZE];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, temp, PUBKEY_SIZE);
    blake2b_final(&blake2b_ctx, calculated_pubkey_hash, BLAKE2B_BLOCK_SIZE);

    // Check if this signature is signed with one of the provided public key.
    uint8_t matched = 0;
    for (size_t i = 0; i < pubkeys_cnt; i++) {
      if (used_signatures[i] == 1) {
        continue;
      }
      if (memcmp(&lock_bytes[FLAGS_SIZE + i * BLAKE160_SIZE],
                 calculated_pubkey_hash, BLAKE160_SIZE) != 0) {
        continue;
      }
      matched = 1;
      used_signatures[i] = 1;
      break;
    }

    // If the signature doesn't match any of the provided public key, the script
    // will exit with an error.
    if (matched != 1) {
      return ERROR_VERIFICATION;
    }
  }

  // The above scheme just ensures that a *threshold* number of signatures have
  // successfully been verified, and they all come from the provided public keys.
  // However, the multisig script might also require some numbers of public keys
  // to always be signed for the script to pass verification. This is indicated
  // via the *required_first_n* flag. Here we also checks to see that this rule
  // is also satisfied.
  for (size_t i = 0; i < require_first_n; i++) {
    if (used_signatures[i] != 1) {
      return ERROR_VERIFICATION;
    }
  }

  return 0;
}
