/*
 * This file provides a type script acting as a cell ID which stays
 * unchanged in case of cell transformations. Basically, it guarentees the
 * following rules are met in a cell transformation:
 *
 * * If there's already an input cell existed in the transaction with current
 * script hash, there can only be one output cell containing the exact same
 * script hash.
 * * If there's no existing input cell containing current script hash, the
 * script would run a blake2b hash on all inputs in current transaction. If
 * the resulting hash and the first script argument are identical, the script
 * succeeds, otherwise, the script fails.
 *
 * With those 2 rules, we can view the type script hash of such a cell as the
 * cell ID. The first rule ensures that the cell ID can only be transferred to
 * one new cell by consuming the old cell, while the second rule ensures that
 * no one can forge IDs arbitrarily. When combined together, the two rules here
 * can ensure a cell has a unique ID within the running CKB system.
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

int extract_cell(unsigned char* current_script_hash, size_t source,
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
    /* We have a new cell creation here, test the second rule */
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);

    size_t i = 0;
    int looping = 1;
    for (; looping && i < SIZE_MAX; i++) {
      len = INPUT_SIZE;
      unsigned char input[INPUT_SIZE];
      ret = ckb_load_input(input, &len, 0, 0, CKB_SOURCE_INPUT);
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

    /*
     * TODO: there is a quirk right now: even though we test the first
     * 32 bytes of argv[1] to see if it matches input hash. An attacker
     * could still append bytes to argv[1] to create different hashes
     * hoping for a collision. The real problem here, is with argv there
     * is no way to know the correct length of an argument. Since we have
     * some revising work planning for CKB, we will defer to a later time
     * to see how we can tackle this problem. Some initial ideas right now:
     *
     * 1. Limit argv to only include null-terminated strings
     * 2. Use a different way(maybe a syscall) to pass script arguments
     * 3. Load the actual script into VM memory and deserialize the structure
     * ourselves. Notice with flatbuffer and slightly complicated logic we
     * can do this now, but I choose to leave it out for now to see if we
     * can find a better way.
     */
    if (memcmp(input_hash, argv[1], 32) != 0) {
      return ERROR_INVALID_INPUT_HASH;
    }
  }
  return 0;
}
