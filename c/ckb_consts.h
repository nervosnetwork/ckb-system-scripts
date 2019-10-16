#ifndef CKB_CONSTS_H_
#define CKB_CONSTS_H_

#define SYS_exit 93
#define SYS_ckb_load_script 2052
#define SYS_ckb_load_tx_hash 2061
#define SYS_ckb_load_script_hash 2062
#define SYS_ckb_load_cell 2071
#define SYS_ckb_load_header 2072
#define SYS_ckb_load_input 2073
#define SYS_ckb_load_witness 2074
#define SYS_ckb_load_cell_by_field 2081
#define SYS_ckb_load_header_by_field 2082
#define SYS_ckb_load_input_by_field 2083
#define SYS_ckb_load_cell_data_as_code 2091
#define SYS_ckb_load_cell_data 2092
#define SYS_ckb_debug 2177

#define CKB_SUCCESS 0
#define CKB_INDEX_OUT_OF_BOUND 1
#define CKB_ITEM_MISSING 2

#define CKB_SOURCE_INPUT 1
#define CKB_SOURCE_OUTPUT 2
#define CKB_SOURCE_CELL_DEP 3
#define CKB_SOURCE_HEADER_DEP 4
#define CKB_SOURCE_GROUP_INPUT 0x0100000000000001
#define CKB_SOURCE_GROUP_OUTPUT 0x0100000000000002

#define CKB_CELL_FIELD_CAPACITY 0
#define CKB_CELL_FIELD_DATA_HASH 1
#define CKB_CELL_FIELD_LOCK 2
#define CKB_CELL_FIELD_LOCK_HASH 3
#define CKB_CELL_FIELD_TYPE 4
#define CKB_CELL_FIELD_TYPE_HASH 5
#define CKB_CELL_FIELD_OCCUPIED_CAPACITY 6

#define CKB_HEADER_FIELD_EPOCH_NUMBER 0
#define CKB_HEADER_FIELD_EPOCH_START_BLOCK_NUMBER 1
#define CKB_HEADER_FIELD_EPOCH_LENGTH 2

#define CKB_INPUT_FIELD_OUT_POINT 0
#define CKB_INPUT_FIELD_SINCE 1

#endif /* CKB_CONSTS_H_ */
