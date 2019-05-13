#ifndef CKB_SYSCALLS_H_
#define CKB_SYSCALLS_H_

#include <stdint.h>
#include <stdlib.h>

#include "ckb_consts.h"

static inline long
__internal_syscall(long n, long _a0, long _a1, long _a2, long _a3, long _a4, long _a5)
{
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

  asm volatile ("scall"
		: "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(syscall_id));

  return a0;
}

#define syscall(n, a, b, c, d, e, f) \
        __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

int ckb_load_tx_hash(void* addr, volatile uint64_t* len, size_t offset)
{
  return syscall(SYS_ckb_load_tx_hash, addr, len, offset, 0, 0, 0);
}

int ckb_load_script_hash(void* addr, volatile uint64_t* len, size_t offset)
{
  return syscall(SYS_ckb_load_script_hash, addr, len, offset, 0, 0, 0);
}

int ckb_load_cell(void* addr, volatile uint64_t* len, size_t offset, size_t index, size_t source)
{
  return syscall(SYS_ckb_load_cell, addr, len, offset, index, source, 0);
}

int ckb_load_input(void* addr, volatile uint64_t* len, size_t offset,
                           size_t index, size_t source)
{
  return syscall(SYS_ckb_load_input, addr, len, offset, index, source, 0);
}

int ckb_load_header(void* addr, volatile uint64_t* len, size_t offset,
                    size_t index, size_t source)
{
  return syscall(SYS_ckb_load_header, addr, len, offset, index, source, 0);
}

int ckb_load_cell_by_field(void* addr, volatile uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field)
{
  return syscall(SYS_ckb_load_cell_by_field, addr, len, offset, index, source, field);
}

int ckb_load_input_by_field(void* addr, volatile uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field)
{
  return syscall(SYS_ckb_load_input_by_field, addr, len, offset, index, source, field);
}

int ckb_debug(const char* s)
{
  return syscall(SYS_ckb_debug, s, 0, 0, 0, 0, 0);
}

#endif  /* CKB_SYSCALLS_H_ */
