/*
utils.h

Defines basic utility functions.
*/

#ifndef CKB_UTILS_H_
#define CKB_UTILS_H_

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
    /* a and b is in the same epoch,
       compare a_index / a_len <=> b_index / b_len
     */
    uint64_t a_block = a_index * b_len;
    uint64_t b_block = b_index * a_len;
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

#endif /* CKB_UTILS_H_ */
