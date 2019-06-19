#include "ckb_syscalls.h"
#include "protocol_reader.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(Ckb_Protocol, x)

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_SYSCALL -4
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_ENCODING -11
#define ERROR_OVERFLOW -12
#define ERROR_INVALID_WITHDRAW_BLOCK -13
#define ERROR_INCORRECT_CAPACITY -14

#define HASH_SIZE 32
#define DAO_SIZE 32
#define HEADER_SIZE 4096
/* 32 KB */
#define WITNESS_SIZE 32768

#define LOCK_PERIOD_BLOCKS 10
#define MATURITY_BLOCKS 5

#define MIN(a, b) (((a) > (b)) ? (b) : (a))

static int extract_bytes(ns(Bytes_table_t) bytes, unsigned char *buffer,
                         volatile size_t *s) {
  flatbuffers_uint8_vec_t seq = ns(Bytes_seq(bytes));
  size_t len = flatbuffers_uint8_vec_len(seq);

  if (len > *s) {
    return ERROR_BUFFER_NOT_ENOUGH;
  }

  for (size_t i = 0; i < len; i++) {
    buffer[i] = flatbuffers_uint8_vec_at(seq, i);
  }
  *s = len;

  return CKB_SUCCESS;
}

/*
 * Fetch withdraw header hash from the 3rd(offset by 1) argument
 * of witness table. Kept as a separate function so witness buffer
 * can be cleaned as soon as it is not needed.
 */
static int extract_withdraw_header_index(size_t input_index, size_t *index) {
  int ret;
  volatile uint64_t len = 0;
  unsigned char witness[WITNESS_SIZE];

  len = WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, input_index, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  ns(Witness_table_t) witness_table = ns(Witness_as_root(witness));
  if (witness_table == NULL) {
    return ERROR_ENCODING;
  }
  ns(Bytes_vec_t) data = ns(Witness_data(witness_table));
  if (ns(Bytes_vec_len(data)) < 2) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  volatile uint64_t value = 0xFFFFFFFFFFFFFFFF;
  volatile size_t s = 8;
  ret = extract_bytes(ns(Bytes_vec_at(data, 1)), ((unsigned char *)&value), &s);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (s != 8) {
    return ERROR_ENCODING;
  }
  *index = value;
  return CKB_SUCCESS;
}

static int calculate_dao_input_capacity(size_t input_index,
                                        uint64_t original_capacity,
                                        uint64_t *calculated_capacity) {
  int ret;
  volatile uint64_t len = 0;
  size_t withdraw_index = 0;

  ret = extract_withdraw_header_index(input_index, &withdraw_index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  unsigned char deposit_header_buffer[HEADER_SIZE];
  len = HEADER_SIZE;
  ret = ckb_load_header(deposit_header_buffer, &len, 0, input_index,
                        CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  unsigned char withdraw_header_buffer[HEADER_SIZE];
  len = HEADER_SIZE;
  ret = ckb_load_header(withdraw_header_buffer, &len, 0, withdraw_index,
                        CKB_SOURCE_DEP);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  ns(Header_table_t) deposit_header = ns(Header_as_root(deposit_header_buffer));
  if (deposit_header == NULL) {
    return ERROR_ENCODING;
  }
  ns(Header_table_t) withdraw_header =
      ns(Header_as_root(withdraw_header_buffer));
  if (withdraw_header == NULL) {
    return ERROR_ENCODING;
  }

  uint64_t deposit_number = ns(Header_number(deposit_header));
  uint64_t withdraw_number = ns(Header_number(withdraw_header));

  if (withdraw_number <= deposit_number) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  uint64_t windowleft = LOCK_PERIOD_BLOCKS -
                        (withdraw_number - deposit_number) % LOCK_PERIOD_BLOCKS;
  uint64_t minimal_since =
      withdraw_number + MIN(MATURITY_BLOCKS, windowleft) + 1;

  volatile uint64_t input_since = 0;
  len = 8;
  ret = ckb_load_input_by_field(((unsigned char *)&input_since), &len, 0, input_index,
                                CKB_SOURCE_INPUT, CKB_INPUT_FIELD_SINCE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (input_since < minimal_since) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  unsigned char deposit_dao[DAO_SIZE];
  unsigned char withdraw_dao[DAO_SIZE];

  len = DAO_SIZE;
  ret = extract_bytes(ns(Header_dao(deposit_header)), deposit_dao, &len);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len < 8) {
    return ERROR_ENCODING;
  }
  len = DAO_SIZE;
  ret = extract_bytes(ns(Header_dao(withdraw_header)), withdraw_dao, &len);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len < 8) {
    return ERROR_ENCODING;
  }

  uint64_t deposit_accumulate_rate = *((uint64_t *)(&deposit_dao[8]));
  uint64_t withdraw_accumulate_rate = *((uint64_t *)(&withdraw_dao[8]));

  volatile uint64_t occupied_capacity = 0;
  len = 8;
  ret = ckb_load_cell_by_field(((unsigned char *)&occupied_capacity), &len, 0,
                               input_index, CKB_SOURCE_INPUT,
                               CKB_CELL_FIELD_OCCUPIED_CAPACITY);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  uint64_t counted_capacity = 0;
  if (__builtin_usubl_overflow(original_capacity, occupied_capacity,
                                &counted_capacity)) {
    return ERROR_OVERFLOW;
  }

  __int128 withdraw_counted_capacity = ((__int128)counted_capacity) *
                                       ((__int128)withdraw_accumulate_rate) /
                                       ((__int128)deposit_accumulate_rate);

  uint64_t withdraw_capacity = 0;
  if (__builtin_uaddl_overflow(occupied_capacity,
                                (uint64_t)withdraw_counted_capacity,
                                &withdraw_capacity)) {
    return ERROR_OVERFLOW;
  }

  *calculated_capacity = withdraw_capacity;
  return CKB_SUCCESS;
}

int main(int argc, char *argv[]) {
  int ret;
  unsigned char script_hash[HASH_SIZE];
  volatile uint64_t len = 0;

  /*
   * DAO has no arguments, this way we can ensure all DAO related scripts
   * in a transaction is mapped to the same group.
   */
  if (argc != 1) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  len = HASH_SIZE;
  ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  size_t index = 0;
  uint64_t input_capacities = 0;
  while (1) {
    int dao_input = 0;
    volatile uint64_t capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret == CKB_SUCCESS) {
      unsigned char current_script_hash[HASH_SIZE];
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                                   CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);
      if ((ret == CKB_SUCCESS) &&
          (memcmp(script_hash, current_script_hash, HASH_SIZE) == 0)) {
        dao_input = 1;
      }
    } else if (ret == CKB_ITEM_MISSING) {
      /* DAO Issuing input here, we can just skip it */
    } else {
      return ERROR_SYSCALL;
    }

    if (!dao_input) {
      /* Normal input, use its own capacity */
      if (__builtin_uaddl_overflow(input_capacities, capacity,
                                    &input_capacities)) {
        return ERROR_OVERFLOW;
      }
    } else {
      /* DAO input, calculate its capacity */
      uint64_t dao_capacity = 0;
      ret = calculate_dao_input_capacity(index, capacity, &dao_capacity);
      if (ret != CKB_SUCCESS) {
        return ret;
      }

      if (__builtin_uaddl_overflow(input_capacities, dao_capacity,
                                    &input_capacities)) {
        return ERROR_OVERFLOW;
      }
    }

    index += 1;
  }

  index = 0;
  uint64_t output_capacities = 0;
  while (1) {
    volatile uint64_t capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                 CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }

    if (__builtin_uaddl_overflow(output_capacities, capacity,
                                  &output_capacities)) {
      return ERROR_OVERFLOW;
    }

    index += 1;
  }

  if (output_capacities > input_capacities) {
    return ERROR_INCORRECT_CAPACITY;
  }

  return CKB_SUCCESS;
}
