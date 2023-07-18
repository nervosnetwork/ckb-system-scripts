// # DAO
//
// This file provides NervosDAO on chain script implementation. It is designed
// to work as the type script of a cell. Please refer to [Nervos DAO
// RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0023-dao-deposit-withdraw/0023-dao-deposit-withdraw.md)
// on more details.

// Necessary headers. This script will need to perform syscalls to read current
// transaction structure, then parse WitnessArgs data structure in molecule
// format.
#include "ckb_syscalls.h"
#include "protocol.h"

// Error definitions
#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_SYSCALL -4
#define ERROR_BUFFER_NOT_ENOUGH -10
#define ERROR_ENCODING -11
#define ERROR_OVERFLOW -13
#define ERROR_INVALID_WITHDRAW_BLOCK -14
#define ERROR_INCORRECT_CAPACITY -15
#define ERROR_INCORRECT_EPOCH -16
#define ERROR_INCORRECT_SINCE -17
#define ERROR_NEWLY_CREATED_CELL -19
#define ERROR_INVALID_WITHDRAWING_CELL -20
#define ERROR_SCRIPT_TOO_LONG -21
// In case of missing deposit headers, load_dao_header_data would also return
// CKB_INDEX_OUT_OF_BOUND, so we cannot use CKB_INDEX_OUT_OF_BOUND as marker
// when all cells have been processed, we will need a different marker here.
#define ERROR_MARKER_EXHAUSTED -30

#if ERROR_MARKER_EXHAUSTED == CKB_INDEX_OUT_OF_BOUND
#error "Exhausted marker cannot be the same as CKB_INDEX_OUT_OF_BOUND!"
#endif

#define CWHR_DEBUG(...)
#define CWHR_ERROR_CODE -22
#include "witness_args_handwritten_reader.h"

#define HASH_SIZE 32
#define HEADER_SIZE 4096
// Note witness will be loaded via a reader that supports arbitrary length. The
// 32KB size here is merely the temporary buffer used to hold part of witness, it
// does not necessary limit the total witness size to 32KB.
#define WITNESS_BUF_SIZE 32768
// The only script that will be loaded by Nervos DAO contract, is Nervos DAO type
// script itself. This type script has empty args, which means the type script will
// never exceed 32K. We are safe keeping this value here.
#define SCRIPT_SIZE 32768

// One lock period of NervosDAO is set as 180 epochs, which is roughly 30 days.
#define LOCK_PERIOD_EPOCHS 180

// Common definitions to parse epoch value in block headers.
#define EPOCH_NUMBER_OFFSET 0
#define EPOCH_NUMBER_BITS 24
#define EPOCH_NUMBER_MASK ((1 << EPOCH_NUMBER_BITS) - 1)
#define EPOCH_INDEX_OFFSET EPOCH_NUMBER_BITS
#define EPOCH_INDEX_BITS 16
#define EPOCH_INDEX_MASK ((1 << EPOCH_INDEX_BITS) - 1)
#define EPOCH_LENGTH_OFFSET (EPOCH_NUMBER_BITS + EPOCH_INDEX_BITS)
#define EPOCH_LENGTH_BITS 16
#define EPOCH_LENGTH_MASK ((1 << EPOCH_LENGTH_BITS) - 1)

// Fetches deposit header index. The index is kept in the witness of the same
// index as the input cell. The witness is first treated as a WitnessArgs object
// in molecule format. Then we extract the value from the `input_type` field of
// WitnessArgs. The value is kept as a 64-bit unsigned little endian value.
static int extract_deposit_header_index(size_t input_index, size_t *index) {
  int ret;
  unsigned char witness[WITNESS_BUF_SIZE];

  cwhr_cursor_t cursor;
  ret = cwhr_cursor_initialize(
      &cursor, cwhr_witness_loader_create(input_index, CKB_SOURCE_INPUT),
      witness, WITNESS_BUF_SIZE);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  cwhr_witness_args_reader_t reader;
  ret = cwhr_witness_args_reader_create(&reader, &cursor);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = cwhr_witness_args_reader_verify(&reader, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_ENCODING;
  }

  if (!cwhr_witness_args_reader_has_input_type(&reader)) {
    return ERROR_ENCODING;
  }

  cwhr_bytes_reader_t input_type;
  ret = cwhr_witness_args_reader_input_type(&reader, &input_type);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  if (cwhr_bytes_reader_length(&input_type) != 8) {
    return ERROR_ENCODING;
  }

  return cwhr_bytes_reader_memcpy(&input_type, index);
}

// Parses epoch info from the epoch field in block header.
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

// All that information that will be needed from a block header by the NervosDAO
// script.
typedef struct {
  uint64_t block_number;
  uint64_t epoch_number;
  uint64_t epoch_index;
  uint64_t epoch_length;
  uint8_t dao[32];
} dao_header_data_t;

// Load a block header and extract all the useful data.
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

  // The header is also serialized in molecule format.
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

// Validates an input cell is indeed deposited to NervosDAO in
// `deposited_block_number`, then calculates the capacity one can withdraw from
// this deposited cell. The function will tries to first read an index value
// from the witness of the position as provided input cell index. Then use the
// read index value as an index into `header_deps` section of current
// transaction for a header. The header is then used as withdraw header to
// calculate deposit period.
static int calculate_dao_input_capacity(size_t input_index,
                                        uint64_t deposited_block_number,
                                        uint64_t deposited_occupied_capacity,
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
  // deposited_block_number must match actual deposited block
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
  // Withdraw header must be after deposit header.
  if ((withdraw_data.epoch_number < deposit_data.epoch_number) ||
      ((withdraw_data.epoch_number == deposit_data.epoch_number) &&
       (withdraw_fraction <= deposit_fraction))) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }

  // Full deposited epochs
  uint64_t deposited_epochs =
      withdraw_data.epoch_number - deposit_data.epoch_number;
  // This is essentially a round-up operation. Suppose withdraw epoch is
  // a + b / c, deposit epoch is d + e / f, the deposited epochs will be:
  //
  // (a - d) + (b / c - e / f) == (a - d) + (b * f - e * c) / (c * f)
  //
  // If (b * f - e * c) is larger than 0, we will have a fraction part in
  // the deposited epochs, we just add one full epoch to deposited_epochs
  // to round it up.
  // If (b * f - e * c) is no larger than 0, let's look back at (b / c - e / f),
  // by the definition of a fraction, we will know 0 <= b / c < 1, and
  // 0 <= e / f < 1, so we will have -1 < (b / c - e / f) <= 0, hence
  // (a - d) - 1 < (a - d) + (b / c - e / f) <= (a - d), we won't need to do
  // anything for a round-up operation.
  if (withdraw_fraction > deposit_fraction) {
    deposited_epochs++;
  }
  uint64_t lock_epochs = (deposited_epochs + (LOCK_PERIOD_EPOCHS - 1)) /
                         LOCK_PERIOD_EPOCHS * LOCK_PERIOD_EPOCHS;
  // Cell must at least be locked for one full lock period(180 epochs)
  if (lock_epochs < LOCK_PERIOD_EPOCHS) {
    return ERROR_INVALID_WITHDRAW_BLOCK;
  }
  // Since actually just stores an epoch integer with a fraction part, it is
  // not necessary a valid epoch number with fraction.
  uint64_t minimal_since_epoch_number = deposit_data.epoch_number + lock_epochs;
  uint64_t minimal_since_epoch_index = deposit_data.epoch_index;
  uint64_t minimal_since_epoch_length = deposit_data.epoch_length;

  // Loads since value from current input to make sure correct lock period is
  // set.
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
  // NervosDAO requires DAO input field to have a since value represented
  // via absolute epoch number.
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

  // Validates that correct since value is set to ensure 180 epochs lock period.
  uint64_t minimal_since_epoch_fraction =
      minimal_since_epoch_index * input_since_epoch_length;
  uint64_t input_since_epoch_fraction =
      input_since_epoch_index * minimal_since_epoch_length;
  if ((input_since_epoch_number < minimal_since_epoch_number) ||
      ((input_since_epoch_number == minimal_since_epoch_number) &&
       (input_since_epoch_fraction < minimal_since_epoch_fraction))) {
    return ERROR_INCORRECT_SINCE;
  }

  // Now we can calculate the maximum amount one can withdraw from this cell.
  // Please refer to Nervos DAO RFC for more details on the formula used here.
  uint64_t deposit_accumulate_rate = *((uint64_t *)(&deposit_data.dao[8]));
  uint64_t withdraw_accumulate_rate = *((uint64_t *)(&withdraw_data.dao[8]));

  // Like any serious smart contracts, we will perform overflow checks here.
  uint64_t counted_capacity = 0;
  if (__builtin_usubl_overflow(original_capacity, deposited_occupied_capacity,
                               &counted_capacity)) {
    return ERROR_OVERFLOW;
  }

  __int128 withdraw_counted_capacity = ((__int128)counted_capacity) *
                                       ((__int128)withdraw_accumulate_rate) /
                                       ((__int128)deposit_accumulate_rate);

  uint64_t withdraw_capacity = 0;
  if (__builtin_uaddl_overflow(deposited_occupied_capacity,
                               (uint64_t)withdraw_counted_capacity,
                               &withdraw_capacity)) {
    return ERROR_OVERFLOW;
  }

  *calculated_capacity = withdraw_capacity;
  return CKB_SUCCESS;
}

// In the phase 1 of NervosDAO script, we will consume a deposited cell, and
// create a withdrawing cell. The withdrawing cell must be put in the same index
// as the deposited cell. For a newly generated withdrawing cell, the following
// conditions should be met:
//
// * withdrawing cell uses Nervos DAO type script
// * withdrawing cell has the same capacity as the input deposited cell
// * withdrawing cell has an 8-byte long cell data, the content is the
// block number containing deposited cell in 64-bit little endian unsigned
// integer format.
//
// Note the withdrawing cell is free to use any lock script as they wish.
// Since this will be part of the transaction, an input lock script shall
// validate the lock script cannot be tampered.
static int validate_withdrawing_cell(size_t index, uint64_t input_capacity,
                                     unsigned char *dao_script_hash) {
  unsigned char hash1[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  // Check type script
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
  // Check capacity
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
  // Check cell data
  dao_header_data_t deposit_header;
  ret = load_dao_header_data(index, CKB_SOURCE_INPUT, &deposit_header);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  uint8_t output_data[16];
  len = 16;
  ret = ckb_load_cell_data(output_data, &len, 0, index, CKB_SOURCE_OUTPUT);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8 && len != 16) {
    return ERROR_SYSCALL;
  }
  uint64_t stored_block_number = *((uint64_t *)output_data);
  if (stored_block_number != deposit_header.block_number) {
    return ERROR_INVALID_WITHDRAWING_CELL;
  }
  if (len == 16) {
    uint64_t stored_occupied_capacity = *((uint64_t *)(&output_data[8]));
    uint64_t actual_occupied_capacity = 0;
    len = 8;
    ret = ckb_load_cell_by_field((unsigned char *)&actual_occupied_capacity,
                                 &len, 0, index, CKB_SOURCE_INPUT,
                                 CKB_CELL_FIELD_OCCUPIED_CAPACITY);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8) {
      return ERROR_SYSCALL;
    }
    if (stored_occupied_capacity != actual_occupied_capacity) {
      return ERROR_INVALID_WITHDRAWING_CELL;
    }
  } else {
    uint64_t input_lock_length = 0;
    ret = ckb_load_cell_by_field(NULL, &input_lock_length, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint64_t output_lock_length = 0;
    ret = ckb_load_cell_by_field(NULL, &output_lock_length, 0, index,
                                 CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (input_lock_length != output_lock_length) {
      return ERROR_INVALID_WITHDRAWING_CELL;
    }
  }
  return CKB_SUCCESS;
}

static int validate_input(size_t index, uint64_t *input_capacities,
                          uint64_t *output_withdrawing,
                          unsigned char *script_hash) {
  int dao_input = 0;
  uint64_t capacity = 0;
  uint64_t len = 8;
  int ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                   CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    return ERROR_MARKER_EXHAUSTED;
  } else if (ret == CKB_SUCCESS) {
    if (len != 8) {
      return ERROR_SYSCALL;
    }
    unsigned char current_script_hash[HASH_SIZE];
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                                 CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);
    // When an input cell has the same type script hash as current running
    // we know we are dealing with a script using NervosDAO script.
    if ((ret == CKB_SUCCESS) && len == HASH_SIZE &&
        (memcmp(script_hash, current_script_hash, HASH_SIZE) == 0)) {
      dao_input = 1;
    }
  } else {
    return ERROR_SYSCALL;
  }

  if (!dao_input) {
    // Normal input, use its own capacity
    if (__builtin_uaddl_overflow(*input_capacities, capacity,
                                 input_capacities)) {
      return ERROR_OVERFLOW;
    }
  } else {
    uint8_t data[16];
    len = 16;
    ret = ckb_load_cell_data(data, &len, 0, index, CKB_SOURCE_INPUT);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8 && len != 16) {
      return ERROR_SYSCALL;
    }
    // In a Nervos DAO transaction, we might have 2 types of input cells using
    // Nervos DAO type script:
    //
    // * A deposited cell
    // * A withdrawing cell
    //
    // If you are also looking at the Nervos DAO RFC, a deposited cell is
    // created in the initial deposit phase, and spent in withdraw phase 1; a
    // withdrawing cell is created in withdraw phase 1, then spent in withdraw
    // phase 2.
    //
    // The way to tell them apart, is that a deposited cell always contains 8
    // bytes of 0 as cell data, while a withdrawing cell would contain a
    // positive number denoting the original deposited block number.
    uint64_t block_number = *((uint64_t *)data);

    if (block_number > 0) {
      uint64_t occupied_capacity = 0xFFFFFFFFFFFFFFFF;
      if (len == 16) {
        occupied_capacity = *((uint64_t *)(&data[8]));
      } else {
        len = 8;
        ret = ckb_load_cell_by_field(((unsigned char *)&occupied_capacity),
                                     &len, 0, index, CKB_SOURCE_INPUT,
                                     CKB_CELL_FIELD_OCCUPIED_CAPACITY);
        if (ret != CKB_SUCCESS) {
          return ERROR_SYSCALL;
        }
        if (len != 8) {
          return ERROR_SYSCALL;
        }
      }

      // For a withdrawing cell, we can start calculate the maximum capacity
      // that one can withdraw from it.
      uint64_t dao_capacity = 0;
      ret = calculate_dao_input_capacity(index, block_number, occupied_capacity,
                                         capacity, &dao_capacity);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      // Like any serious smart contracts, we will perform overflow checks here.
      if (__builtin_uaddl_overflow(*input_capacities, dao_capacity,
                                   input_capacities)) {
        return ERROR_OVERFLOW;
      }
    } else {
      if (len != 8) {
        return ERROR_SYSCALL;
      }
      // For a deposited cell, we only need to check that a withdrawing cell for
      // current one is generated. For simplicity, we are limiting the code so
      // the withdrawing cell must at the same index with the deposited cell.
      // Due to the fact that one deposited cell is mapped to exactly one
      // withdrawing cell, this would work fine here.
      ret = validate_withdrawing_cell(index, capacity, script_hash);
      if (ret != CKB_SUCCESS) {
        return ret;
      }
      // Note that `validate_withdrawing_cell` above already verifies that an
      // output cell for the current input cell at the same location exists.
      *output_withdrawing = 1;
      // Like any serious smart contracts, we will perform overflow checks here.
      if (__builtin_uaddl_overflow(*input_capacities, capacity,
                                   input_capacities)) {
        return ERROR_OVERFLOW;
      }
    }
  }

  return 0;
}

static int validate_output(size_t index, uint64_t *output_capacities,
                           uint64_t output_withdrawing,
                           unsigned char *script_hash) {
  uint64_t capacity = 0;
  uint64_t len = 8;
  int ret = ckb_load_cell_by_field(((unsigned char *)&capacity), &len, 0, index,
                                   CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    return ERROR_MARKER_EXHAUSTED;
  }
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }

  // Like any serious smart contracts, we will perform overflow checks here.
  if (__builtin_uaddl_overflow(*output_capacities, capacity,
                               output_capacities)) {
    return ERROR_OVERFLOW;
  }

  unsigned char current_script_hash[HASH_SIZE];
  len = HASH_SIZE;
  ret = ckb_load_cell_by_field(current_script_hash, &len, 0, index,
                               CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
  if ((ret == CKB_SUCCESS) && len == HASH_SIZE &&
      (memcmp(script_hash, current_script_hash, HASH_SIZE) == 0)) {
    // Similarly to input, we also need to check if we are creating a
    // deposited cell, or a withdrawing cell here. This can be easily determined
    // using output_withdrawing here: in previous input_validation call
    // we have marked if the cell was a withdrawing cell.
    //
    // For withdrawing cells, we already perform all the necessary checks when
    // we are checking the corresponding deposited cells above. No further
    // action is needed here.
    //
    // For newly deposited cells, we need to validate that the cell data part
    // contains 8 bytes of data filled with 0.
    if (output_withdrawing == 0) {
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
  return 0;
}

int main() {
  int ret;
  unsigned char script_hash[HASH_SIZE];
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = 0;
  mol_seg_t script_seg;
  mol_seg_t args_seg;
  mol_seg_t bytes_seg;

  // NervosDAO script requires script args part to be empty, this way we can
  // ensure that all DAO related scripts in a transaction is mapped to the same
  // group, and processed together in one execution.
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

  // Load current script hash. Unlike a lock script which only cares for cells
  // using its own lock script. The NervosDAO script here will need to loop
  // through all cells to ensure the output cells contain a valid number of
  // capacities. Hence we need to manually check if a cell uses the NervosDAO
  // type script.
  len = HASH_SIZE;
  ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_SYSCALL;
  }

  // First, we will need to loop against all input cells in current transaction.
  // For a normal transaction, we will just add up its own capacity. For a
  // NervosDAO related cell, we will perform some checks first of course, then
  // we will calculate the maximum capacity one can withdraw from it, and add up
  // the maximum withdraw capacity here. After this loop we will have a value
  // containing the *true* capacities of all the input cells here.

  // Also let's loop through all output cells, and calculate the sum of output
  // capacities here.

  size_t index = 0;
  uint64_t input_capacities = 0;
  uint64_t output_capacities = 0;
  uint64_t output_withdrawing = 0;

  uint64_t input_exhausted = 0;
  uint64_t output_exhausted = 0;
  while (!(input_exhausted && output_exhausted)) {
    // Reset the flag to ensure that it does not retain the value from the last
    // iteration when inputs have been exhausted.
    output_withdrawing = 0;

    if (!input_exhausted) {
      ret = validate_input(index, &input_capacities, &output_withdrawing,
                           script_hash);
      if (ret == ERROR_MARKER_EXHAUSTED) {
        input_exhausted = 1;
      } else if (ret != CKB_SUCCESS) {
        return ret;
      }
    }

    if (!output_exhausted) {
      ret = validate_output(index, &output_capacities, output_withdrawing,
                            script_hash);
      if (ret == ERROR_MARKER_EXHAUSTED) {
        output_exhausted = 1;
      } else if (ret != CKB_SUCCESS) {
        return ret;
      }
    }

    index += 1;
  }

  // The final thing we need to check here, is that the sum of capacities in
  // output cells, cannot exceed the sum of capacities in all input cells with
  // Nervos DAO issuance considered.
  if (output_capacities > input_capacities) {
    return ERROR_INCORRECT_CAPACITY;
  }

  return CKB_SUCCESS;
}
