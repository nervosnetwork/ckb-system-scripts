/*
 * This file provides the type script for NervosDAO logic. To deposit
 * to NervosDAO, one simply needs to create a new cell with this script
 * as the type script(for the exact code hash to use please refer to
 * the most current CKB version). While you can certainly used the official
 * secp256k1-blake160 lock script to guard your cell, you are also free
 * to use any other lock script, as long as the lock script satisfies the
 * following conditions:
 *
 * 1. The lock script won't use the witness argument at index 1(offset by 0,
 * so this is actually the 2nd argument in witness).
 * 2. The lock script ensures the witness argument at index 1 won't be tampered,
 * one example to ensure this, is that the lock script can include this argument
 * in signature calculation steps.
 *
 * No further actions are needed to keep your capacities locked in NervosDAO.
 *
 * To withdraw from NervosDAO, one needs to create a new transaction with
 * the NervosDAO cell as one of the inputs. The OutPoint used to reference
 * the NervosDAO cell should have block_hash correctly set, so this script
 * can load the header of the deposit block which contains the locked NervosDAO
 * cell. He/she should also specify an existing header denoted as the withdraw
 * block. This script will calculate the interest from the deposit block to
 * this withdraw block.
 * The withdraw block should be included in one of the transaction deps using
 * block_hash field. The index of the withdraw block in the deps field, should
 * be serialized into 64-bit unsigned little endian integer, and put as the
 * witness argument at index 1 in the corresponding witness for the locked
 * NervosDAO input.
 *
 * If the above steps feel confusing to you, you can also refer to one of our
 * official CKB SDK to learn how to deposit to and withdraw from NervosDAO.
 *
 * NervosDAO relies on a special field in the block header named dao to provide
 * needed statistic data to calculate NervosDAO interests. Specifically, 3 fields
 * will be kept in DAO field in the block header:
 *
 * * AR: accumulated rate of NervosDAO
 * * C: All issued capacities in CKB (not including current block)
 * * U: All occupied capacities in CKB (including current block)
 *
 * Please refer to CKB implementation for how to calculate AR, C and U.
 *
 * To calculate the interest of NervosDAO, we first separate the capacities in
 * the deposit cell as +free_capacity+ and +occupied_capacity+: Free capacity is
 * calculated as the total capacity minus occupied capacity. Then the maximum
 * capacity one can withdraw for the NervosDAO input is calculated as:
 *
 * occupied_capacity + free_capacity * AR_withdraw / AR_deposit
 *
 * Notice one is free to include normal inputs in a transaction containing
 * NervosDAO inputs, he/she is also free to include multiple NervosDAO inputs
 * in one transaction. This type script will calculate the correct total
 * capacities in all cases.
 */
#include "ckb_syscalls.h"
#include "protocol_reader.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_SYSCALL -4
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_ENCODING -11
#define ERROR_WITNESS_TOO_LONG -12
#define ERROR_OVERFLOW -13
#define ERROR_INVALID_WITHDRAW_BLOCK -14
#define ERROR_INCORRECT_CAPACITY -15

#define HASH_SIZE 32
#define DAO_SIZE 32
#define HEADER_SIZE 4096
/* 32 KB */
#define WITNESS_SIZE 32768

#define LOCK_PERIOD_BLOCKS 10
#define MATURITY_BLOCKS 5

#define MAX(a, b) (((a) < (b)) ? (b) : (a))

/*
 * Fetch withdraw header hash from the 3rd(offset by 1) argument
 * of witness table. Kept as a separate function so witness buffer
 * can be cleaned as soon as it is not needed.
 */
static int extract_withdraw_header_index(size_t input_index, size_t *index) {
  int ret;
  volatile uint64_t len = 0;
  unsigned char witness[WITNESS_SIZE];
  mol_pos_t witness_pos;
  mol_read_res_t arg_res;
  mol_read_res_t bytes_res;

  len = WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, input_index, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > WITNESS_SIZE) {
    return ERROR_WITNESS_TOO_LONG;
  }

  witness_pos.ptr = (const uint8_t*)witness;
  witness_pos.size = len;

  /* Load signature */
  arg_res = mol_cut(&witness_pos, MOL_Witness(1));
  if (arg_res.code != 0) {
    if (arg_res.attr < 2) {
      return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
    } else {
      return ERROR_ENCODING;
    }
  }
  if (arg_res.attr < 2) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  bytes_res = mol_cut_bytes(&arg_res.pos);
  if (bytes_res.code != 0) {
    return ERROR_ENCODING;
  }
  if (bytes_res.pos.size != 8) {
    return ERROR_ENCODING;
  }

  *index = *((size_t *)bytes_res.pos.ptr);
  return CKB_SUCCESS;
}

static int extract_header_number_and_dao(
        unsigned char *bytes, uint64_t len,
        uint64_t *number, mol_pos_t *dao_pos) {
  mol_pos_t header_pos;
  header_pos.ptr = (const uint8_t*)bytes;
  header_pos.size = len;
  mol_read_res_t raw_res;
  mol_read_res_t number_res;
  mol_read_res_t dao_res;
  mol_read_res_t bytes_res;

  raw_res = mol_cut(&header_pos, MOL_Header_raw());
  if (raw_res.code != 0) {
    return ERROR_ENCODING;
  }
  number_res = mol_cut(&raw_res.pos, MOL_RawHeader_number());
  if (number_res.code != 0) {
    return ERROR_ENCODING;
  }
  if (number_res.pos.size != 8) {
    return ERROR_ENCODING;
  }
  // we can do this, because we use little endian in both Serialization and VM
  *number = *((uint64_t*) number_res.pos.ptr);
  dao_res = mol_cut(&raw_res.pos, MOL_RawHeader_dao());
  if (dao_res.code != 0) {
    return ERROR_ENCODING;
  }
  bytes_res = mol_cut_bytes(&dao_res.pos);
  if (bytes_res.code != 0) {
    return ERROR_ENCODING;
  } else if (bytes_res.pos.size < DAO_SIZE) {
    return ERROR_ENCODING;
  }
  *dao_pos = bytes_res.pos;
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
  uint64_t deposit_number;
  mol_pos_t deposit_dao_pos;
  len = HEADER_SIZE;
  ret = ckb_load_header(deposit_header_buffer, &len, 0, input_index,
                        CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = extract_header_number_and_dao(deposit_header_buffer, len, &deposit_number, &deposit_dao_pos);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  unsigned char withdraw_header_buffer[HEADER_SIZE];
  uint64_t withdraw_number;
  mol_pos_t withdraw_dao_pos;
  len = HEADER_SIZE;
  ret = ckb_load_header(withdraw_header_buffer, &len, 0, withdraw_index,
                        CKB_SOURCE_HEADER_DEP);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = extract_header_number_and_dao(withdraw_header_buffer, len, &withdraw_number, &withdraw_dao_pos);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (withdraw_number <= deposit_number) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  uint64_t windowleft = LOCK_PERIOD_BLOCKS -
                        (withdraw_number - deposit_number) % LOCK_PERIOD_BLOCKS;
  uint64_t minimal_since =
      withdraw_number + MAX(MATURITY_BLOCKS, windowleft) + 1;

  volatile uint64_t input_since = 0;
  len = 8;
  ret = ckb_load_input_by_field(((unsigned char *)&input_since), &len, 0, input_index,
                                CKB_SOURCE_INPUT, CKB_INPUT_FIELD_SINCE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* Right now NervosDAO only supports absolute block number since */
  if (input_since >> 56 != 0) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }
  if (input_since < minimal_since) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  uint64_t deposit_accumulate_rate = *((uint64_t *)(&deposit_dao_pos.ptr[8]));
  uint64_t withdraw_accumulate_rate = *((uint64_t *)(&withdraw_dao_pos.ptr[8]));

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
