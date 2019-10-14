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
  int i = 0;
  uint8_t tmp[0];
  int ret;
  /* count number of inputs */
  while (1) {
    ret = ckb_load_input_by_field(tmp, &len, 0, i, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret != CKB_SUCCESS) {
      break;
    }
    i++;
  }
  /* try load i-th witness */
  ret = ckb_load_witness(tmp, &len, 0, i, CKB_SOURCE_INPUT);
  if (ret == CKB_SUCCESS) {
    return ERROR_TOO_MANY_WITNESSES;
  }
  return CKB_SUCCESS;
}
