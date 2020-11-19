// # secp256k1-blake160-sighash-all
//
// This is a lock script code using the same secp256k1 signature verification algorithm
// as used in bitcoin. When executed, it performs the blake2b hash (with "ckb-default-hash"
// used as the personalization value) on the following concatenated components:
//
// * The current transaction hash;
// * Take the witness of the same index as the first input using current lock script,
// treat it as a [WitnessArgs](https://github.com/nervosnetwork/ckb/blob/1df5f2c1cbf07e04622fb8faa5b152c1af7ae341/util/types/schemas/blockchain.mol#L106)
// object using molecule serialization format, then fill in a 65-byte long value with all
// zeros in the lock field, the modified object is then serialized and used as the value to hash. Notice the
// length of the modified witness object is hashed first as a 64-bit unsigned little endian
// integer;
// * All the witnesses of the same indices as the remaining input cells with the same lock
// script as the current lock script to run. Notice the length of each witness is hashed
// before the corresponding witness as a 64-bit unsigned little endian integer;
// * All the witnesses which have index value exceeding the number of input cells. For
// example, if a transaction has 3 inputs, all witnesses with index equal to or larger than
// 3 will be hashed. Notice the length of each witness is hashed before the corresponding
// witness as a 64-bit unsigned little endian integer;
//
// The blake2b hash result is then used as a message to verify the recoverable signature
// provided in the lock field of the modified witness object mentioned above. From the
// recoverable signature, we can derive the public key, we then run another blake2b hash
// (with "ckb-default-hash" used as personalization), take the first 160 bit of the hashed
// result(hence the blake160 name), and compare those 160-bit values with what is stored in
// script args part of current running script. If they do match, the signature verification
// is succeeded.
//
// Note that we distinguish between lock script and lock script code here: when we say lock
// script code, we mean only the RISC-V binary compiled from the current C source file; when
// we say lock script, however, we mean the whole lock script including script args part. A
// consequence here, is that one transaction in CKB might contain input cells using the same
// lock script code here, but with different script args(hence different lock script), in
// those cases, this underlying lock script code will be executed multiple times when
// validating a single transaction, each time with a different lock script.

// First we will need to include a few headers here, for legacy reasons, this repository
// ships with those headers. We are now maintaining a new [repository](https://github.com/nervosnetwork/ckb-c-stdlib)
// with most of those headers included. If you are building a new script, we do recommend
// you to take a look at what's in the new repository, and use the code there directly.
#include "blake2b.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"

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
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

// Compile-time guard against buffer abuse
#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

// To use this script, some conventions are required:
//
// The script args part should contain the blake160 hash of a public key, which is the
// first 20 bytes of the blake2b hash(with "ckb-default-hash" as personalization) of the
// used public key. This is used to shield the real public key till the first spend.
//
// The first witness, or the first witness of the same index as the first input cell using
// current lock script, should be a [WitnessArgs](https://github.com/nervosnetwork/ckb/blob/1df5f2c1cbf07e04622fb8faa5b152c1af7ae341/util/types/schemas/blockchain.mol#L106)
// object in molecule serialization format. The lock field of said WitnessArgs object should
// contain a 65-byte recoverable signature to prove ownership.
int main() {
  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];

  // First let's load and extract script args part, which is also the blake160 hash of public
  // key from current running script.
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
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
  if (args_bytes_seg.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  // Load the first witness, or the witness of the same index as the first input using
  // current script.
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // We will treat the first witness as WitnessArgs object, and extract the lock field
  // from the object.
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  // The lock field must be 65 byte long to represent a (possibly) valid signature.
  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  // We keep the signature in the temporary location, since later we will modify the
  // WitnessArgs object in place for message hashing.
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

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

  // Here we start to prepare the message used in signature verification. First, let's
  // hash the just loaded transaction hash.
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  // We've already saved the signature above to a different location. We can then modify
  // the witness object in place to save both memory usage and runtime cycles. The message
  // requires us to use all zeros in the place where a signature should be presented.
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  // Before hashing each witness, we need to hash the witness length first as a 64-bit
  // unsigned little endian integer.
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  // Now let's hash the first modified witness.
  blake2b_update(&blake2b_ctx, temp, witness_len);

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

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  // From the recoverable signature, we can derive the public key used.
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  // Let's serialize the signature first, then generate the blake2b hash.
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  // As mentioned above, we are only using the first 160 bits(20 bytes), if they match
  // the value provided as the first 20 bytes of script args, the signature verification
  // is considered to be successful.
  if (memcmp(args_bytes_seg.ptr, temp, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}
