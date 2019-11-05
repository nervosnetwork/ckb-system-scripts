#include "ckb_syscalls.h"
#include "protocol.h"

/* Common errors */
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
#define ERROR_SECP_PARSE_PUBKEY -13
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_SERIALIZE_PUBKEY -15
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_SIZE -22
#define ERROR_INCORRECT_SINCE_FLAGS -23
#define ERROR_INCORRECT_SINCE_VALUE -24
#define ERROR_PUBKEY_BLAKE160_HASH -31

/* since */
#define SINCE_VALUE_BITS 56
#define SINCE_VALUE_MASK 0x00ffffffffffffff
#define SINCE_EPOCH_FRACTION_FLAG 0b00100000

/* calculate inputs length */
int calculate_inputs_len() {
  uint64_t len = 0;
  /* lower bound, at least tx has one input */
  int lo = 0;
  /* higher bound */
  int hi = 4;
  int ret;
  /* try to load input until failing to increase lo and hi */
  while (1) {
    ret = ckb_load_input_by_field(NULL, &len, 0, hi, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = hi;
      hi *= 2;
    } else {
      break;
    }
  }

  /* now we get our lower bound and higher bound,
   count number of inputs by binary search */
  int i;
  while (lo + 1 != hi) {
    i = (lo + hi) / 2;
    ret = ckb_load_input_by_field(NULL, &len, 0, i, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = i;
    } else {
      hi = i;
    }
  }
  /* now lo is last input index and hi is length of inputs */
  return hi;
}

/* Extract lock from WitnessArgs */
int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_ENCODING;
  }
  *lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
}

/* a and b are since value,
 return 0 if a is equals to b,
 return -1 if a is less than b,
 return 1 if a is greater than b */
int epoch_number_with_fraction_cmp(uint64_t a, uint64_t b) {
  static const size_t NUMBER_OFFSET = 0;
  static const size_t NUMBER_BITS = 24;
  static const uint64_t NUMBER_MAXIMUM_VALUE = (1 << NUMBER_BITS);
  static const uint64_t NUMBER_MASK = (NUMBER_MAXIMUM_VALUE - 1);
  static const size_t INDEX_OFFSET = NUMBER_BITS;
  static const size_t INDEX_BITS = 16;
  static const uint64_t INDEX_MAXIMUM_VALUE = (1 << INDEX_BITS);
  static const uint64_t INDEX_MASK = (INDEX_MAXIMUM_VALUE - 1);
  static const size_t LENGTH_OFFSET = NUMBER_BITS + INDEX_BITS;
  static const size_t LENGTH_BITS = 16;
  static const uint64_t LENGTH_MAXIMUM_VALUE = (1 << LENGTH_BITS);
  static const uint64_t LENGTH_MASK = (LENGTH_MAXIMUM_VALUE - 1);

  /* extract a epoch */
  uint64_t a_epoch = (a >> NUMBER_OFFSET) & NUMBER_MASK;
  uint64_t a_index = (a >> INDEX_OFFSET) & INDEX_MASK;
  uint64_t a_len = (a >> LENGTH_OFFSET) & LENGTH_MASK;

  /* extract b epoch */
  uint64_t b_epoch = (b >> NUMBER_OFFSET) & NUMBER_MASK;
  uint64_t b_index = (b >> INDEX_OFFSET) & INDEX_MASK;
  uint64_t b_len = (b >> LENGTH_OFFSET) & LENGTH_MASK;

  if (a_epoch < b_epoch) {
    return -1;
  } else if (a_epoch > b_epoch) {
    return 1;
  } else {
    /* a and b is in the same epoch */
    uint64_t a_block = a_index * a_len;
    uint64_t b_block = b_index * b_len;
    /* compare block */
    if (a_block < b_block) {
      return -1;
    } else if (a_block > b_block) {
      return 1;
    } else {
      return 0;
    }
  }
}

/* check since,
 for all inputs the since field must have the exactly same flags with the since
 constraint, and the value of since must greater or equals than the since
 contstaint */
int check_since(uint64_t since) {
  size_t i = 0, len;
  uint64_t input_since;
  /* the 8 msb is flag */
  uint8_t since_flags = since >> SINCE_VALUE_BITS;
  uint64_t since_value = since & SINCE_VALUE_MASK;
  int ret;
  while (1) {
    len = sizeof(uint64_t);
    ret =
        ckb_load_input_by_field(&input_since, &len, 0, i,
                                CKB_SOURCE_GROUP_INPUT, CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS || len != sizeof(uint64_t)) {
      return ERROR_SYSCALL;
    }
    uint8_t input_since_flags = input_since >> SINCE_VALUE_BITS;
    uint64_t input_since_value = input_since & SINCE_VALUE_MASK;
    if (since_flags != input_since_flags) {
      return ERROR_INCORRECT_SINCE_FLAGS;
    }
    if (input_since_flags == SINCE_EPOCH_FRACTION_FLAG) {
      ret = epoch_number_with_fraction_cmp(input_since_value, since_value);
      if (ret < 0) {
        return ERROR_INCORRECT_SINCE_VALUE;
      }
    } else if (input_since_value < since_value) {
      return ERROR_INCORRECT_SINCE_VALUE;
    }
    i += 1;
  }
  return CKB_SUCCESS;
}
