/*
 * This file provides a type script acting as a cell ID which stays
 * unchanged in case of cell transformations. Basically, it allows 3 types
 * of cell transformation:
 *
 * 1. A new cell with current type script is created
 * 2. An old cell with current type script is consumed to create a new
 * cell with the same type script
 * 3. A cell with current type script is destroyed
 *
 * In all cases, there should be at most one input cell and one output cell
 * which use current type script, this is validated in extract_cell.
 *
 * Case 1 also requires one additional rule: the script fetches all input
 * structure in current transaction, and run a blake2b hash on them. It then
 * validates that the resulting blake2b hash matches the first and only argument
 * of current script.
 *
 * Case 2 and 3 do not require any new validation rule.
 *
 * With those rules, we can ensure the existence of unique cell IDs(which is type
 * script hash) in CKB.
 */
#include "blake2b.h"
#include "ckb_syscalls.h"

#define ERROR_UNKNOWN -1
#define ERROR_WRONG_NUMBER_OF_ARGUMENTS -2
#define ERROR_LOAD_SCRIPT_HASH -18
#define ERROR_MORE_MATCHED_CELL_THAN_ALLOWED -19
#define ERROR_TOO_MANY_CELLS -20
#define ERROR_INPUT_TOO_LARGE -21
#define ERROR_LOAD_INPUT -22
#define ERROR_INVALID_INPUT_HASH -23

#define BLAKE2B_BLOCK_SIZE 32
#define INPUT_SIZE 4096

int extract_cell(const unsigned char* current_script_hash, size_t source,
                 size_t* index) {
  size_t matched_cell = SIZE_MAX, i = 0;
  int looping = 1;
  for (; looping && i < SIZE_MAX; i++) {
    volatile uint64_t len = BLAKE2B_BLOCK_SIZE;
    unsigned char hash[BLAKE2B_BLOCK_SIZE];
    int ret = ckb_load_cell_by_field(hash, &len, 0, i, source,
                                     CKB_CELL_FIELD_TYPE_HASH);

    switch (ret) {
      case CKB_SUCCESS:
        if (len != BLAKE2B_BLOCK_SIZE) {
          return ERROR_LOAD_SCRIPT_HASH;
        }
        if (memcmp(current_script_hash, hash, BLAKE2B_BLOCK_SIZE) == 0) {
          /* The first rule is ensured here */
          if (matched_cell != SIZE_MAX) {
            return ERROR_MORE_MATCHED_CELL_THAN_ALLOWED;
          }
          matched_cell = i;
        }
        break;
      case CKB_INDEX_OUT_OF_BOUND:
        looping = 0;
        break;
      case CKB_ITEM_MISSING:
        /* Current cell doesn't have type script, just continue */
        break;
      default:
        return ERROR_LOAD_SCRIPT_HASH;
    }
  }
  if (i == SIZE_MAX) {
    return ERROR_TOO_MANY_CELLS;
  }
  *index = matched_cell;
  return 0;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    return ERROR_WRONG_NUMBER_OF_ARGUMENTS;
  }

  volatile uint64_t len = BLAKE2B_BLOCK_SIZE;
  unsigned char current_script_hash[BLAKE2B_BLOCK_SIZE];

  int ret = ckb_load_script_hash(current_script_hash, &len, 0);
  if (ret != CKB_SUCCESS || len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_LOAD_SCRIPT_HASH;
  }

  size_t matched_input_cell = SIZE_MAX;
  ret =
      extract_cell(current_script_hash, CKB_SOURCE_INPUT, &matched_input_cell);
  if (ret != 0) {
    return ret;
  }

  size_t matched_output_cell = SIZE_MAX;
  ret = extract_cell(current_script_hash, CKB_SOURCE_OUTPUT,
                     &matched_output_cell);
  if (ret != 0) {
    return ret;
  }

  if (matched_input_cell == SIZE_MAX && matched_output_cell != SIZE_MAX) {
    /* We are at case 1 here, there's one additional hash validation needed */
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);

    size_t i = 0;
    int looping = 1;
    for (; looping && i < SIZE_MAX; i++) {
      len = INPUT_SIZE;
      unsigned char input[INPUT_SIZE];
      ret = ckb_load_input(input, &len, 0, i, CKB_SOURCE_INPUT);
      switch (ret) {
        case CKB_SUCCESS:
          if (len > INPUT_SIZE) {
            return ERROR_INPUT_TOO_LARGE;
          }
          blake2b_update(&blake2b_ctx, input, len);
          break;
        case CKB_INDEX_OUT_OF_BOUND:
          looping = 0;
          break;
        default:
          return ERROR_LOAD_INPUT;
      }
    }

    unsigned char input_hash[BLAKE2B_BLOCK_SIZE];
    blake2b_final(&blake2b_ctx, input_hash, BLAKE2B_BLOCK_SIZE);

    if ((ckb_argv_length(argv, 1) != 32) ||
        (memcmp(input_hash, argv[1], 32) != 0)) {
      return ERROR_INVALID_INPUT_HASH;
    }
  }
  return 0;
}
