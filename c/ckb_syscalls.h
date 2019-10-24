#ifndef CKB_SYSCALLS_H_
#define CKB_SYSCALLS_H_

#include <stddef.h>
#include <stdint.h>

#include "ckb_consts.h"

#define memory_barrier() asm volatile("fence" ::: "memory")

static inline long __internal_syscall(long n, long _a0, long _a1, long _a2,
                                      long _a3, long _a4, long _a5) {
  register long a0 asm("a0") = _a0;
  register long a1 asm("a1") = _a1;
  register long a2 asm("a2") = _a2;
  register long a3 asm("a3") = _a3;
  register long a4 asm("a4") = _a4;
  register long a5 asm("a5") = _a5;

#ifdef __riscv_32e
  register long syscall_id asm("t0") = n;
#else
  register long syscall_id asm("a7") = n;
#endif

  asm volatile("scall"
               : "+r"(a0)
               : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(syscall_id));
  /*
   * Syscalls might modify memory sent as pointer, adding a barrier here ensures
   * gcc won't do incorrect optimization.
   */
  memory_barrier();

  return a0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_exit(int8_t code) { return syscall(SYS_exit, code, 0, 0, 0, 0, 0); }

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_tx_hash, addr, &inner_len, offset, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_script_hash, addr, &inner_len, offset, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_cell, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_input, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_header, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  volatile uint64_t inner_len = *len;
  int ret =
      syscall(SYS_ckb_load_witness, addr, &inner_len, offset, index, source, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_script, addr, &inner_len, offset, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_cell_by_field, addr, &inner_len, offset, index,
                    source, field);
  *len = inner_len;
  return ret;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_header_by_field, addr, &inner_len, offset,
                    index, source, field);
  *len = inner_len;
  return ret;
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_input_by_field, addr, &inner_len, offset,
                    index, source, field);
  *len = inner_len;
  return ret;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source) {
  return syscall(SYS_ckb_load_cell_data_as_code, addr, memory_size,
                 content_offset, content_size, index, source);
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(SYS_ckb_load_cell_data, addr, &inner_len, offset, index,
                    source, 0);
  *len = inner_len;
  return ret;
}

int ckb_debug(const char* s) {
  return syscall(SYS_ckb_debug, s, 0, 0, 0, 0, 0);
}

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify input/output.
 */
int load_actual_type_witness(uint8_t *buf, uint64_t *len, size_t index,
                             size_t *type_source) {
  *type_source = CKB_SOURCE_GROUP_INPUT;
  uint64_t tmp_len = 0;
  if (ckb_load_cell_by_field(NULL, &tmp_len, 0, 0, CKB_SOURCE_GROUP_INPUT,
                             CKB_CELL_FIELD_CAPACITY) ==
      CKB_INDEX_OUT_OF_BOUND) {
    *type_source = CKB_SOURCE_GROUP_OUTPUT;
  }

  return ckb_load_witness(buf, len, 0, index, *type_source);
}

#endif /* CKB_SYSCALLS_H_ */
