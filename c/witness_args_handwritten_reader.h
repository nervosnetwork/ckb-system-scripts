// This file is taken from:
// https://github.com/xxuejie/ckb-witness-args-handwritten-reader/blob/ac2008fc0c04e0bb44938ca58b7647e03aa90752/c/witness_args_handwritten_reader.h

// This is a handwritten WitnessArgs validator & reader supporting
// witnesses of arbitrary length. It employs a cursor based design
// that dynamically loads data when necessary. For now, this is
// handwritten which only deals with WitnessArgs data structure,
// later we might expand the same idea into molecule, so we can generate
// similar reader on any molecule schema.

#ifndef CKB_WITNESS_ARGS_HANDWRITTEN_READER_
#define CKB_WITNESS_ARGS_HANDWRITTEN_READER_

#include "ckb_syscalls.h"

#ifndef CWHR_DEBUG
/*
 * This is a poor-man's debugging function, ideally one would want to
 * Use ckb_printf from ckb-c-stdlib
 */
int _cwhr_printf(const char *format, ...);
#define CWHR_DEBUG(...) _cwhr_printf(__VA_ARGS__)
#endif

#ifndef CWHR_ERROR_CODE
#define CWHR_ERROR_CODE -40
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int (*cwhr_data_accessor_f)(const uint8_t *data, size_t length,
                                    void *context);

typedef struct {
  uint8_t *buf;
  size_t offset;
} cwhr_memcpy_accessor_context;

int cwhr_memcpy_accessor_context_initialize(
    cwhr_memcpy_accessor_context *context, void *buf) {
  context->buf = (uint8_t *)buf;
  context->offset = 0;
  return CKB_SUCCESS;
}

int cwhr_memcpy_accessor(const uint8_t *data, size_t length, void *context) {
  cwhr_memcpy_accessor_context *c = (cwhr_memcpy_accessor_context *)context;
  memcpy(&c->buf[c->offset], data, length);
  c->offset += length;
  return CKB_SUCCESS;
}

typedef struct {
  size_t syscall;
  size_t payload3;
  size_t payload4;
  size_t payload5;
} cwhr_loader_t;

cwhr_loader_t cwhr_witness_loader_create(size_t index, size_t source) {
  cwhr_loader_t result;
  result.syscall = SYS_ckb_load_witness;
  result.payload3 = index;
  result.payload4 = source;
  result.payload5 = 0;
  return result;
}

int cwhr_loader_load(const cwhr_loader_t *loader, void *addr, uint64_t *len,
                     size_t offset) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(loader->syscall, addr, &inner_len, offset, loader->payload3,
                    loader->payload4, loader->payload5);
  *len = inner_len;
  return ret;
}

typedef struct {
  uint8_t *buf;
  size_t length;

  size_t loaded_offset;
  size_t loaded_length;
  size_t total_length;

  cwhr_loader_t loader;
} cwhr_cursor_t;

#define CWHR_MINIMAL_BUFFER_LENGTH 32

int cwhr_cursor_initialize(cwhr_cursor_t *cursor, cwhr_loader_t loader,
                           uint8_t *buf, size_t length) {
  if (length < CWHR_MINIMAL_BUFFER_LENGTH) {
    CWHR_DEBUG("Provided buffer is too small for cursor!\n");
    return CWHR_ERROR_CODE;
  }

  size_t total_length = length;
  int ret = cwhr_loader_load(&loader, buf, &total_length, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  cursor->buf = buf;
  cursor->length = length;
  cursor->loaded_offset = 0;
  cursor->loaded_length = total_length;
  if (cursor->loaded_length > length) {
    cursor->loaded_length = length;
  }
  cursor->total_length = total_length;
  cursor->loader = loader;

  return CKB_SUCCESS;
}

int cwhr_cursor_shift(cwhr_cursor_t *cursor, size_t offset) {
  cursor->loaded_length = cursor->length;
  int ret = cwhr_loader_load(&cursor->loader, cursor->buf,
                             &cursor->loaded_length, offset);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (cursor->loaded_length > cursor->length) {
    cursor->loaded_length = cursor->length;
  }
  return CKB_SUCCESS;
}

const uint8_t *cwhr_cursor_read_available(cwhr_cursor_t *cursor, size_t offset,
                                          size_t minimal_length,
                                          size_t *available_length) {
  size_t loaded_end = cursor->loaded_offset + cursor->loaded_length;
  if (offset >= cursor->loaded_offset && offset <= loaded_end &&
      (offset + minimal_length) <= loaded_end) {
    size_t start = offset - cursor->loaded_offset;
    *available_length = cursor->loaded_length - start;
    return &cursor->buf[start];
  }
  if (minimal_length > cursor->length) {
    CWHR_DEBUG("Requesting length is larger than buffer length!\n");
    return NULL;
  }
  int ret = cwhr_cursor_shift(cursor, offset);
  if (ret != CKB_SUCCESS) {
    CWHR_DEBUG("Cursor shift error: %d\n", ret);
    return NULL;
  }
  *available_length = cursor->loaded_length;
  return cursor->buf;
}

int cwhr_cursor_read_u32(cwhr_cursor_t *cursor, size_t offset,
                         uint32_t *result) {
  size_t available_length = 0;
  const uint8_t *p =
      cwhr_cursor_read_available(cursor, offset, 4, &available_length);
  if (p == NULL) {
    return CWHR_ERROR_CODE;
  }
  if (available_length < 4) {
    CWHR_DEBUG("Cursor does not have enough data for a u32!\n");
    return CWHR_ERROR_CODE;
  }
  *result = *((const uint32_t *)p);
  return CKB_SUCCESS;
}

int cwhr_cursor_read(cwhr_cursor_t *cursor, cwhr_data_accessor_f accessor,
                     void *context) {
  size_t read = 0;
  while (read < cursor->total_length) {
    size_t available_length = 0;
    const uint8_t *p =
        cwhr_cursor_read_available(cursor, read, 1, &available_length);
    int ret = accessor(p, available_length, context);
    if (ret != CKB_SUCCESS) {
      CWHR_DEBUG("User-level accessor failure!\n");
      return ret;
    }
    read += available_length;
  }
  return CKB_SUCCESS;
}

int cwhr_cursor_memcpy(cwhr_cursor_t *cursor, void *buf) {
  cwhr_memcpy_accessor_context context;
  cwhr_memcpy_accessor_context_initialize(&context, buf);
  return cwhr_cursor_read(cursor, cwhr_memcpy_accessor, &context);
}

typedef struct {
  cwhr_cursor_t *cursor;

  /*
   * When working with a WitnessArgs, we never directly instantiate a
   * Bytes structure, we always create a Bytes structure when accessing
   * the lock, input_type, or output_type field off the upper level struct.
   * Using lock field as an example, given a WitnessArgs structure, the lock
   * field can always be read at a certain offset of the WitnessArgs structure.
   * Hence we can leverage an optimization here: when accessing the lock field
   * in a WitnessArgs structure, a Bytes structure would then created that
   * shares the same cursor as the upper-level WitnessArgs, however, the Bytes
   * structure would maintain a particular *base_offset* that indicates the
   * offset within WitnessArgs, where we can start reading the Bytes structure.
   * This way we can reduce syscalls as much as possible: when the cursor for
   * WitnessArgs already contains the same data, Bytes can reuse the same data.
   * What's more, given a relatively large cursor buffer(32K for example), a
   * majority of witnesses can be loaded via a single syscall, while maintaining
   * a unified API for dealing with larger witnesses.
   */
  size_t base_offset;
  size_t length;
} cwhr_bytes_reader_t;

/*
 * Note the different between create and initialize:
 * * Create builds a top-level structure, such as Transaction orWitnessArgs.
 * It is typically combined with a fresh cursor directly, *base_offset* is
 * assumed to be zero, *length* would contain the total length of a cursor;
 * * Initialize builds a structure when accessing a field from a upper-level
 * structure. For instance, we initialize a Bytes structure when accessing
 * the lock field of a WitnessArgs structure, or we initialize a WitnessArgs
 * structure when accessing the witness for a particular transaction. The
 * *base_offset* here typically has a non-zero value, the *length* field
 * is also likely not the full length of the cursor.
 */
int cwhr_bytes_reader_initialize(cwhr_bytes_reader_t *reader,
                                 cwhr_cursor_t *cursor, size_t base_offset,
                                 size_t length) {
  reader->cursor = cursor;
  reader->base_offset = base_offset;
  reader->length = length;

  return CKB_SUCCESS;
}

int cwhr_bytes_reader_create(cwhr_bytes_reader_t *reader,
                             cwhr_cursor_t *cursor) {
  return cwhr_bytes_reader_initialize(reader, cursor, 0, cursor->total_length);
}

int cwhr_bytes_reader_verify(cwhr_bytes_reader_t *reader, int compatible) {
  (void)compatible;
  if (reader->length < 4) {
    CWHR_DEBUG("Bytes must have room for length!\n");
    return CWHR_ERROR_CODE;
  }
  uint32_t count = 0xFFFFFFFF;
  int ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset, &count);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  size_t expected_length = 4 + (size_t)count;
  if (reader->length != expected_length) {
    CWHR_DEBUG("Bytes has incorrect length! Expected: %ld, actual: %ld\n",
               expected_length, reader->length);
    return CWHR_ERROR_CODE;
  }
  return CKB_SUCCESS;
}

uint32_t cwhr_bytes_reader_length(cwhr_bytes_reader_t *reader) {
  return reader->length - 4;
}

int cwhr_bytes_reader_read(cwhr_bytes_reader_t *reader,
                           cwhr_data_accessor_f accessor, void *context) {
  uint32_t read = 0;
  uint32_t length = cwhr_bytes_reader_length(reader);
  while (read < length) {
    size_t available_length = 0;
    const uint8_t *p = cwhr_cursor_read_available(
        reader->cursor, reader->base_offset + 4 + read, 1, &available_length);
    uint32_t left = length - read;
    uint32_t available = (uint32_t)available_length;
    if (available > left) {
      available = left;
    }
    int ret = accessor(p, available, context);
    if (ret != CKB_SUCCESS) {
      CWHR_DEBUG("User-level accessor failure!\n");
      return ret;
    }
    read += available;
  }
  return CKB_SUCCESS;
}

int cwhr_bytes_reader_memcpy(cwhr_bytes_reader_t *reader, void *buf) {
  cwhr_memcpy_accessor_context context;
  cwhr_memcpy_accessor_context_initialize(&context, buf);
  return cwhr_bytes_reader_read(reader, cwhr_memcpy_accessor, &context);
}

typedef struct {
  cwhr_cursor_t *cursor;

  size_t base_offset;
  size_t length;

  // WitnessArgs would pre-load some offsets to speed-up accessors.
  uint32_t lock_offset;
  uint32_t input_type_offset;
  uint32_t output_type_offset;
} cwhr_witness_args_reader_t;

int cwhr_witness_args_reader_initialize(cwhr_witness_args_reader_t *reader,
                                        cwhr_cursor_t *cursor,
                                        size_t base_offset, size_t length) {
  reader->cursor = cursor;
  reader->base_offset = base_offset;
  reader->length = length;

  if (reader->length < 16) {
    CWHR_DEBUG("WitnessArgs must have room for length and offsets!\n");
    return CWHR_ERROR_CODE;
  }
  int ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset + 4,
                                 &reader->lock_offset);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset + 8,
                             &reader->input_type_offset);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset + 12,
                             &reader->output_type_offset);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  return CKB_SUCCESS;
}

int cwhr_witness_args_reader_create(cwhr_witness_args_reader_t *reader,
                                    cwhr_cursor_t *cursor) {
  return cwhr_witness_args_reader_initialize(reader, cursor, 0,
                                             cursor->total_length);
}

int cwhr_witness_args_reader_has_lock(cwhr_witness_args_reader_t *reader) {
  return reader->input_type_offset > reader->lock_offset;
}

int cwhr_witness_args_reader_lock(cwhr_witness_args_reader_t *reader,
                                  cwhr_bytes_reader_t *lock) {
  return cwhr_bytes_reader_initialize(
      lock, reader->cursor, reader->base_offset + (size_t)reader->lock_offset,
      (size_t)(reader->input_type_offset - reader->lock_offset));
}

int cwhr_witness_args_reader_has_input_type(
    cwhr_witness_args_reader_t *reader) {
  return reader->output_type_offset > reader->input_type_offset;
}

int cwhr_witness_args_reader_input_type(cwhr_witness_args_reader_t *reader,
                                        cwhr_bytes_reader_t *input_type) {
  return cwhr_bytes_reader_initialize(
      input_type, reader->cursor,
      reader->base_offset + (size_t)reader->input_type_offset,
      (size_t)(reader->output_type_offset - reader->input_type_offset));
}

int cwhr_witness_args_reader_has_output_type(
    cwhr_witness_args_reader_t *reader) {
  return reader->length > (size_t)reader->output_type_offset;
}

int cwhr_witness_args_reader_output_type(cwhr_witness_args_reader_t *reader,
                                         cwhr_bytes_reader_t *output_type) {
  return cwhr_bytes_reader_initialize(
      output_type, reader->cursor,
      reader->base_offset + (size_t)reader->output_type_offset,
      reader->length - (size_t)reader->output_type_offset);
}

int cwhr_witness_args_reader_verify(cwhr_witness_args_reader_t *reader,
                                    int compatible) {
  uint32_t size = 0xFFFFFFFF;
  int ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset, &size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (((size_t)size) != reader->length) {
    CWHR_DEBUG("WitnessArgs has incorrect length! Expected: %u, actual: %ld\n",
               size, reader->length);
    return CWHR_ERROR_CODE;
  }

  if (reader->lock_offset % 4 != 0) {
    CWHR_DEBUG("Offset field is not aligned to 4 bytes!\n");
    return CWHR_ERROR_CODE;
  }
  uint32_t field_count = reader->lock_offset / 4 - 1;
  if (field_count < 3) {
    CWHR_DEBUG("WitnessArgs must have at least 3 fields!\n");
    return CWHR_ERROR_CODE;
  }
  if ((!compatible) && (field_count > 3)) {
    CWHR_DEBUG(
        "WitnessArgs has remaining field but compatible flag is turned off!\n");
    return CWHR_ERROR_CODE;
  }

  uint32_t previous_offset = 0xFFFFFFFF;
  ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset + 4,
                             &previous_offset);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  for (uint32_t i = 1; i < field_count; i++) {
    uint32_t offset = 0xFFFFFFFF;
    ret = cwhr_cursor_read_u32(reader->cursor, reader->base_offset + 4 + 4 * i,
                               &offset);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (previous_offset > offset) {
      CWHR_DEBUG("Offset %u is bigger than offset %u in WitnessArgs!\n", i - 1,
                 i);
      return CWHR_ERROR_CODE;
    }
    previous_offset = offset;
  }
  if (((size_t)previous_offset) > reader->length) {
    CWHR_DEBUG("The last offset is bigger than total length!\n");
    return CWHR_ERROR_CODE;
  }

  if (cwhr_witness_args_reader_has_lock(reader)) {
    cwhr_bytes_reader_t lock;
    ret = cwhr_witness_args_reader_lock(reader, &lock);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = cwhr_bytes_reader_verify(&lock, compatible);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  if (cwhr_witness_args_reader_has_input_type(reader)) {
    cwhr_bytes_reader_t input_type;
    ret = cwhr_witness_args_reader_input_type(reader, &input_type);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = cwhr_bytes_reader_verify(&input_type, compatible);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }
  if (cwhr_witness_args_reader_has_output_type(reader)) {
    cwhr_bytes_reader_t output_type;
    ret = cwhr_witness_args_reader_output_type(reader, &output_type);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    ret = cwhr_bytes_reader_verify(&output_type, compatible);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  return CKB_SUCCESS;
}

#endif /* CKB_WITNESS_ARGS_HANDWRITTEN_READER_ */
