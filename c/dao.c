/*
 * This file provides the type script for NervosDAO logic. Please refer to the
 * Nervos DAO RFC on how to use this script.
 */
#include "ckb_syscalls.h"
#include "protocol.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_SYSCALL -4
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_ENCODING -11
#define ERROR_WITNESS_TOO_LONG -12
#define ERROR_OVERFLOW -13
#define ERROR_INVALID_WITHDRAW_BLOCK -14
#define ERROR_INCORRECT_CAPACITY -15
#define ERROR_INCORRECT_EPOCH -16
#define ERROR_INCORRECT_SINCE -17
#define ERROR_TOO_MANY_OUTPUT_CELLS -18
#define ERROR_NEWLY_CREATED_CELL -19
#define ERROR_INVALID_WITHDRAWING_CELL -20
#define ERROR_SCRIPT_TOO_LONG -21

#define HASH_SIZE 32
#define HEADER_SIZE 4096
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

/*
 * For simplicity, a transaction containing Nervos DAO script is limited to
 * 64 output cells so we can simplify processing. Later we might upgrade this
 * script to relax this limitation.
 */
#define MAX_OUTPUT_LENGTH 64

#define LOCK_PERIOD_EPOCHES 180

#define EPOCH_NUMBER_OFFSET 0
#define EPOCH_NUMBER_BITS 24
#define EPOCH_NUMBER_MASK ((1 << EPOCH_NUMBER_BITS) - 1)
#define EPOCH_INDEX_OFFSET EPOCH_NUMBER_BITS
#define EPOCH_INDEX_BITS 16
#define EPOCH_INDEX_MASK ((1 << EPOCH_INDEX_BITS) - 1)
#define EPOCH_LENGTH_OFFSET (EPOCH_NUMBER_BITS + EPOCH_INDEX_BITS)
#define EPOCH_LENGTH_BITS 16
#define EPOCH_LENGTH_MASK ((1 << EPOCH_LENGTH_BITS) - 1)

/*
 * Fetch deposit header hash from the input type part in witness, it should be
 * exactly 8 bytes long. Kept as a separate function so witness buffer
 * can be cleaned as soon as it is not needed.
 */
static int extract_deposit_header_index(size_t input_index, size_t *index) {
  int ret;
  uint64_t len = 0;
  unsigned char witness[MAX_WITNESS_SIZE];

  len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness, &len, 0, input_index, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_TOO_LONG;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = (uint8_t *)witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  /* Load type args */
  mol_seg_t type_seg = MolReader_WitnessArgs_get_input_type(&witness_seg);

  if (MolReader_BytesOpt_is_none(&type_seg)) {
    return ERROR_ENCODING;
  }

  mol_seg_t type_bytes_seg = MolReader_Bytes_raw_bytes(&type_seg);
  if (type_bytes_seg.size != 8) {
    return ERROR_ENCODING;
  }

  *index = *type_bytes_seg.ptr;
  return CKB_SUCCESS;
}

static int extract_epoch_info(uint64_t epoch, int allow_zero_epoch_length,
                              uint64_t *epoch_number, uint64_t *epoch_index,
                              uint64_t *epoch_length) {
  uint64_t index = (epoch >> EPOCH_INDEX_OFFSET) & EPOCH_INDEX_MASK;
  uint64_t length = (epoch >> EPOCH_LENGTH_OFFSET) & EPOCH_LENGTH_MASK;
  if (length == 0) {
    if (allow_zero_epoch_length) {
      index = 0;
      length = 1;
    } else {
      return ERROR_INCORRECT_EPOCH;
    }
  }
  if (index >= length) {
    return ERROR_INCORRECT_EPOCH;
  }
  *epoch_number = (epoch >> EPOCH_NUMBER_OFFSET) & EPOCH_NUMBER_MASK;
  *epoch_index = index;
  *epoch_length = length;
  return CKB_SUCCESS;
}

typedef struct {
  uint64_t block_number;
  uint64_t epoch_number;
  uint64_t epoch_index;
  uint64_t epoch_length;
  uint8_t dao[32];
} dao_header_data_t;

static int load_dao_header_data(size_t index, size_t source,
                                dao_header_data_t *data) {
  uint8_t buffer[HEADER_SIZE];
  uint64_t len = HEADER_SIZE;
  int ret = ckb_load_header(buffer, &len, 0, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len > HEADER_SIZE) {
    return ERROR_BUFFER_NOT_ENOUGH;
  }

  mol_seg_t header_seg;
  header_seg.ptr = (uint8_t *)buffer;
  header_seg.size = len;

  if (MolReader_Header_verify(&header_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t raw_seg = MolReader_Header_get_raw(&header_seg);
  mol_seg_t dao_seg = MolReader_RawHeader_get_dao(&raw_seg);
  mol_seg_t epoch_seg = MolReader_RawHeader_get_epoch(&raw_seg);
  mol_seg_t block_number_seg = MolReader_RawHeader_get_number(&raw_seg);

  data->block_number = *((uint64_t *)block_number_seg.ptr);
  memcpy(data->dao, dao_seg.ptr, 32);
  return extract_epoch_info(*((uint64_t *)epoch_seg.ptr), 0,
                            &(data->epoch_number), &(data->epoch_index),
                            &(data->epoch_length));
}

static int calculate_dao_input_capacity(size_t input_index,
                                        uint64_t deposited_block_number,
                                        uint64_t original_capacity,
                                        uint64_t *calculated_capacity) {
  uint64_t len = 0;
  size_t deposit_index = 0;

  int ret = extract_deposit_header_index(input_index, &deposit_index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  dao_header_data_t deposit_data;
  ret =
      load_dao_header_data(deposit_index, CKB_SOURCE_HEADER_DEP, &deposit_data);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  /* deposited_block_number must match actual deposit block */
  if (deposited_block_number != deposit_data.block_number) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  dao_header_data_t withdraw_data;
  ret = load_dao_header_data(input_index, CKB_SOURCE_INPUT, &withdraw_data);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  uint64_t withdraw_fraction =
      withdraw_data.epoch_index * deposit_data.epoch_length;
  uint64_t deposit_fraction =
      deposit_data.epoch_index * withdraw_data.epoch_length;
  if ((withdraw_data.epoch_number < deposit_data.epoch_number) ||
      ((withdraw_data.epoch_number == deposit_data.epoch_number) &&
       (withdraw_fraction <= deposit_fraction))) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  uint64_t deposited_epoches =
      withdraw_data.epoch_number - deposit_data.epoch_number;
  /*
   * This is essentially a round-up operation. Suppose withdraw epoch is
   * a + b / c, deposit epoch is d + e / f, the deposited epoches will be:
   *
   * (a - d) + (b / c - e / f) == (a - d) + (b * f - e * c) / (c * f)
   *
   * If (b * f - e * c) is larger than 0, we will have a fraction part in
   * the deposited epoches, we just add one full epoch to deposited_epoches
   * to round it up.
   * If (b * f - e * c) is no larger than 0, let's look back at (b / c - e / f),
   * by the definition of a fraction, we will know 0 <= b / c < 1, and
   * 0 <= e / f < 1, so we will have -1 < (b / c - e / f) <= 0, hence
   * (a - d) - 1 < (a - d) + (b / c - e / f) <= (a - d), we won't need to do
   * anything for a round-up operation.
   */
  if (withdraw_fraction > deposit_fraction) {
    deposited_epoches++;
  }
  uint64_t lock_epoches = (deposited_epoches + (LOCK_PERIOD_EPOCHES - 1)) /
                          LOCK_PERIOD_EPOCHES * LOCK_PERIOD_EPOCHES;
  /* Cell must at least be locked for one full lock period(180 epoches) */
  if (lock_epoches < LOCK_PERIOD_EPOCHES) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }
  /*
   * Since actually just stores an epoch integer with a fraction part, it is
   * not necessary a valid epoch number with fraction.
   */
  uint64_t minimal_since_epoch_number =
      deposit_data.epoch_number + lock_epoches;
  uint64_t minimal_since_epoch_index = deposit_data.epoch_index;
  uint64_t minimal_since_epoch_length = deposit_data.epoch_length;

  uint64_t input_since = 0;
  len = 8;
  ret = ckb_load_input_by_field(((unsigned char *)&input_since), &len, 0,
                                input_index, CKB_SOURCE_INPUT,
                                CKB_INPUT_FIELD_SINCE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }
  /*
   * NervosDAO requires DAO input field to have a since value represented
   * via absolute epoch number.
   */
  if (input_since >> 56 != 0x20) {
    return ERROR_INCORRECT_SINCE;
  }
  uint64_t input_since_epoch_number = 0;
  uint64_t input_since_epoch_index = 0;
  uint64_t input_since_epoch_length = 1;
  ret = extract_epoch_info(input_since, 1, &input_since_epoch_number,
                           &input_since_epoch_index, &input_since_epoch_length);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  uint64_t minimal_since_epoch_fraction =
      minimal_since_epoch_index * input_since_epoch_length;
  uint64_t input_since_epoch_fraction =
      input_since_epoch_index * minimal_since_epoch_length;
  if ((input_since_epoch_number < minimal_since_epoch_number) ||
      ((input_since_epoch_number == minimal_since_epoch_number) &&
       (input_since_epoch_fraction < minimal_since_epoch_fraction))) {
    return ERROR_INCORRECT_SINCE;
  }

  uint64_t deposit_accumulate_rate = *((uint64_t *)(&deposit_data.dao[8]));
  uint64_t withdraw_accumulate_rate = *((uint64_t *)(&withdraw_data.dao[8]));

  uint64_t occupied_capacity = 0;
  len = 8;
  ret = ckb_load_cell_by_field(((unsigned char *)&occupied_capacity), &len, 0,
                               input_index, CKB_SOURCE_INPUT,
                               CKB_CELL_FIELD_OCCUPIED_CAPACITY);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len != 8) {
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

/*
 * For a newly generated withdrawing cell, the following conditions should
 * be met:
 *
 * * withdrawing cell uses Nervos DAO type script
 * * withdrawing cell has the same capacity as the input deposited cell
 * * withdrawing cell has an 8-byte long cell data, the content is the
 * block number containing deposited cell in 64-bit little endian unsigned
 * integer format.
 *
 * Note the withdrawing cell is free to use any lock script as they wish.
 * Since this will be part of the transaction, an input lock script shall
 * validate the lock script cannot be tampered.
 */
static int validate_withdrawing_cell(size_t index, uint64_t input_capacity,
                                     unsigned char *dao_script_hash) {
  unsigned char hash1[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  /* Check type script */
  len = HASH_SIZE;
  int ret = ckb_load_cell_by_field(hash1, &len, 0, index, CKB_SOURCE_OUTPUT,
                               CKB_CELL_FIELD_TYPE_HASH);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }
  if (memcmp(hash1, dao_script_hash, HASH_SIZE) != 0) {
    return ERROR_INVALID_WITHDRAWING_CELL;
  }
  /* Check capacity */
  uint64_t output_capacity = 0;
  len = 8;
  ret =
      ckb_load_cell_by_field((unsigned char *)&output_capacity, &len, 0, index,
                             CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }
  if (output_capacity != input_capacity) {
    return ERROR_INVALID_WITHDRAWING_CELL;
  }
  /* Check cell data */
  dao_header_data_t deposit_header;
  ret = load_dao_header_data(index, CKB_SOURCE_INPUT, &deposit_header);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  uint64_t stored_block_number = 0;
  len = 8;
  ret = ckb_load_cell_data((unsigned char *)&stored_block_number, &len, 0,
                           index, CKB_SOURCE_OUTPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }
  if (stored_block_number != deposit_header.block_number) {
    return ERROR_INVALID_WITHDRAWING_CELL;
  }
  return CKB_SUCCESS;
}

int main() {
  int ret;
  unsigned char script_hash[HASH_SIZE];
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = 0;
  mol_seg_t script_seg;
  mol_seg_t args_seg;
  mol_seg_t bytes_seg;

  /*
   * DAO has no arguments, this way we can ensure all DAO related scripts
   * in a transaction is mapped to the same group.
   */
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  args_seg = MolReader_Script_get_args(&script_seg);
  bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (bytes_seg.size != 0) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  len = HASH_SIZE;
  ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }

  size_t index = 0;
  uint64_t input_capacities = 0;
#if MAX_OUTPUT_LENGTH > 64
#error "Masking solutioin can only work with 64 outputs at most!"
#endif
  uint64_t output_withdrawing_mask = 0;
  while (1) {
    int dao_input = 0;
    uint64_t capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret == CKB_SUCCESS) {
      if (len != 8) {
        return ERROR_SYSCALL;
      }
      unsigned char current_script_hash[HASH_SIZE];
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                                   CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);
      if ((ret == CKB_SUCCESS) && len == HASH_SIZE &&
          (memcmp(script_hash, current_script_hash, HASH_SIZE) == 0)) {
        dao_input = 1;
      }
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
      /*
       * First check whether current DAO input is deposited cell,
       * or withdrawing cell.
       */
      uint64_t block_number = 0;
      len = 8;
      ret = ckb_load_cell_data((unsigned char *)&block_number, &len, 0, index,
                               CKB_SOURCE_INPUT);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      if (len != 8) {
        return ERROR_SYSCALL;
      }

      if (block_number > 0) {
        /*
         * Withdrawing cell, this DAO cell is at phase 2, where we can calculate
         * and issue the extra tokens.
         */
        uint64_t dao_capacity = 0;
        ret = calculate_dao_input_capacity(index, block_number, capacity,
                                           &dao_capacity);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (__builtin_uaddl_overflow(input_capacities, dao_capacity,
                                     &input_capacities)) {
          return ERROR_OVERFLOW;
        }
      } else {
        /*
         * Deposited cell, this DAO cell is at phase 1, we only need to check
         * a withdrawing cell for current one is generated. For simplicity, we
         * are limiting the code so the withdrawing cell must at the same index
         * with the deposited cell. Due to the fact that one deposited cell is
         * mapped to exactly one withdrawing cell, this would work fine here.
         */
        ret = validate_withdrawing_cell(index, capacity, script_hash);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        output_withdrawing_mask |= (1 << index);
        if (__builtin_uaddl_overflow(input_capacities, capacity,
                                     &input_capacities)) {
          return ERROR_OVERFLOW;
        }
      }
    }

    index += 1;
  }

  index = 0;
  uint64_t output_capacities = 0;
  while (1) {
    uint64_t capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                 CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8) {
      return ERROR_SYSCALL;
    }
    if (index >= MAX_OUTPUT_LENGTH) {
      return ERROR_TOO_MANY_OUTPUT_CELLS;
    }
    if (__builtin_uaddl_overflow(output_capacities, capacity,
                                 &output_capacities)) {
      return ERROR_OVERFLOW;
    }

    unsigned char current_script_hash[HASH_SIZE];
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                                 CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
    if ((ret == CKB_SUCCESS) && len == HASH_SIZE &&
        (memcmp(script_hash, current_script_hash, HASH_SIZE) == 0)) {
      /*
       * There are 2 types of cells in the transaction output cells with
       * Nervos DAO type script:
       *
       * * Withdrawing DAO cells created in current transaction, those cells
       * are marked via output_withdrawing_mask, they have already passed all
       * validations, no further action is needed here.
       * * Newly deposited DAO cells, for those cells, we need to validate the
       * cell data part contains 8-byte data filled with 0.
       */
      if ((output_withdrawing_mask & (1 << index)) == 0) {
        uint64_t block_number = 0;
        len = 8;
        ret = ckb_load_cell_data((unsigned char *)&block_number, &len, 0, index,
                                 CKB_SOURCE_OUTPUT);
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (len != 8) {
          return ERROR_SYSCALL;
        }
        if (block_number != 0) {
          return ERROR_NEWLY_CREATED_CELL;
        }
      }
    }

    index += 1;
  }

  if (output_capacities > input_capacities) {
    return ERROR_INCORRECT_CAPACITY;
  }

  return CKB_SUCCESS;
}
