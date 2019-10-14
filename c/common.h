#include "ckb_syscalls.h"

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
#define ERROR_TOO_MANY_WITNESSES -23
#define ERROR_PUBKEY_BLAKE160_HASH -31
#define ERROR_PUBKEY_RIPEMD160_HASH -32

/* make sure witnesses is less or equals to inputs */
int check_witnesses_len() {
  uint64_t len = 0;
  uint8_t tmp[0];
  /* lower bound, at least tx has one input */
  int lo = 1;
  /* higher bound */
  int hi = 4;
  int ret;
  /* try loading input until failed to increase lo and hi */
  while (1) {
    ret = ckb_load_input_by_field(tmp, &len, 0, hi, CKB_SOURCE_INPUT,
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
    ret = ckb_load_input_by_field(tmp, &len, 0, i, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = i;
    } else {
      hi = i;
    }
  }
  /* try load witness */
  ret = ckb_load_witness(tmp, &len, 0, hi, CKB_SOURCE_INPUT);
  if (ret == CKB_SUCCESS) {
    return ERROR_TOO_MANY_WITNESSES;
  }
  return CKB_SUCCESS;
}
