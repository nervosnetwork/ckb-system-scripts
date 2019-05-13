#ifndef CKB_CONSTS_H_
#define CKB_CONSTS_H_

#define SYS_exit 93
#define SYS_ckb_load_tx_hash 2061
#define SYS_ckb_load_script_hash 2062
#define SYS_ckb_load_cell 2071
#define SYS_ckb_load_header 2072
#define SYS_ckb_load_input 2073
#define SYS_ckb_load_cell_by_field 2081
#define SYS_ckb_load_input_by_field 2083
#define SYS_ckb_debug 2177

#define CKB_SUCCESS 0
#define CKB_INDEX_OUT_OF_BOUND 1
#define CKB_ITEM_MISSING 2

#define CKB_SOURCE_INPUT 1
#define CKB_SOURCE_OUTPUT 2
#define CKB_SOURCE_DEP 3

#define CKB_CELL_FIELD_CAPACITY 0
#define CKB_CELL_FIELD_DATA 1
#define CKB_CELL_FIELD_DATA_HASH 2
#define CKB_CELL_FIELD_LOCK 3
#define CKB_CELL_FIELD_LOCK_HASH 4
#define CKB_CELL_FIELD_TYPE 5
#define CKB_CELL_FIELD_TYPE_HASH 6

#define CKB_INPUT_FIELD_ARGS 0
#define CKB_INPUT_FIELD_OUT_POINT 1
#define CKB_INPUT_FIELD_SINCE 2

#endif  /* CKB_CONSTS_H_ */
