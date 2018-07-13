/*
 * Copyright (c) 2012-2016, Juniper Networks, Inc.
 * All rights reserved.
 *
 * You may distribute under the terms of :
 *
 * the BSD 2-Clause license
 *
 * Any patches released for this software are to be released under these
 * same license terms.
 *
 * BSD 2-Clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "macros.h"

const char util_hex[] = "0123456789abcdef";

extern FILE *fp_log;

void util_print_buffer(FILE *fd, size_t current, size_t total,
                       unsigned char *buffer) {
  if (total > current) {
    size_t i = 0;
    size_t bc = 0;
    size_t bc_max = total - current;
    size_t bc_leftover = bc_max - ((bc_max / 16) * 16);
    unsigned char *p = &buffer[current];

    fprintf(fd, "%zd %zd %p\n", current, total, buffer);

    for (bc = 0; bc < bc_max / 16; bc++) {
      fprintf(fd, "%8.8zx: ", bc * 16);
      for (i = 0; i < 16; i++) {
        fprintf(fd, "%2.2x ", p[i]);
      }
      fprintf(fd, " -- ");
      for (i = 0; i < 16; i++) {
        fprintf(fd, "%c", PRINTABLE(p[i]));
      }
      fprintf(fd, "\n");
      p += 16;
    }
    if (0 != bc_leftover) {
      fprintf(fd, "%8.8zx: ", bc * 16);
      for (i = 0; i < bc_leftover; i++) {
        fprintf(fd, "%2.2x ", p[i]);
      }
      for (; i < 16; i++) {
        fprintf(fd, "   ");
      }
      fprintf(fd, " -- ");
      for (i = 0; i < bc_leftover; i++) {
        fprintf(fd, "%c", PRINTABLE(p[i]));
      }
      fprintf(fd, "\n");
    }
  }
}

void util_log(const char *fmt, ...) {
  if (NULL != fp_log) {
    va_list v;
    va_start(v, fmt);
    vfprintf(fp_log, fmt, v);
    va_end(v);
    fflush(fp_log);
  }
}

void util_encode_byte(unsigned int val, char *out) {
  ASSERT(val <= 0xff);
  ASSERT(out != NULL);
  if (out != NULL) {
    *(out + 0) = util_hex[(val >> 4) & 0xf];
    *(out + 1) = util_hex[val & 0xf];
  }
}

int util_hex_nibble(char in) {
  int c;

  c = in & 0xff;

  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  return -1;
}

/* Decode a single nibble */
bool util_decode_nibble(const char *in, uint8_t *nibble) {
  bool ret = false;
  int nib;

  nib = util_hex_nibble(*in);
  if (nib >= 0) {
    *nibble = nib;
    ret = true;
  }

  return ret;
}

/* Decode byte */
bool util_decode_byte(const char *in, uint8_t *byte_ptr) {
  bool ret = false;
  uint8_t ls_nibble;
  uint8_t ms_nibble;

  if (util_decode_nibble(in, &ms_nibble)) {
    if (util_decode_nibble(in + 1, &ls_nibble)) {
      *byte_ptr = (ms_nibble << 4) + ls_nibble;
      ret = true;
    }
  }
  return ret;
}

/* Convert an array of bytes into an array of characters */
int util_encode_data(const unsigned char *data, size_t data_len, char *out,
                     size_t out_size) {
  size_t i;
  int ret = 1;

  if (((data_len * 2) >= out_size) || (data == NULL) || (out == NULL) ||
      (data_len == 0)) {
    /* Error conditions, bail */
    goto end;
  }

  for (i = 0; i < data_len; i++, data++, out += 2)
    util_encode_byte(*data, out);

  *out = 0;

  ret = 0;
end:
  return ret;
}

/* Encode string into an array of characters, s must be null terminated */
int util_encode_string(const char *s, char *out, size_t out_size) {
  int i = 0;
  if (s != NULL && out != NULL && out_size > 0) {
    /* +1 for the null, x2 for the byte to 2 chars */
    if ((strlen(s) * 2) + 1 > out_size) {
      /* We do not have enough space to encode the data */
      goto end;
    }
    while (*s) {
      *out++ = util_hex[(*s >> 4) & 0x0f];
      *out++ = util_hex[*s & 0x0f];
      s++;
      i += 2;
    }
    *out = '\0';
    i++;
  }
end:
  return i;
}

/* Decode a hex string to an unsigned 32-bit value */
bool util_decode_uint32(char **in, uint32_t *val, char break_char) {
  bool ret = false;

  if (in != NULL && *in != NULL && val != NULL) {
    uint8_t nibble;
    uint32_t tmp;
    int count;

    if (**in == '\0') {
      /* We are expecting at least one character */
      goto end;
    }

    for (tmp = 0, count = 0; **in && count < 8; count++, (*in)++) {
      if (!util_decode_nibble(*in, &nibble))
        break;
      tmp = (tmp << 4) + nibble;
    }

    if (**in != break_char) {
      DBG_PRINT("ERROR wrong terminator expecting %d and got %d\n", break_char,
                **in);
      /* Wrong terminating character */
      goto end;
    }
    if (**in)
      (*in)++;
    *val = tmp;
    ret = true;
  }
end:
  return ret;
}

/* Decode a hex string to an unsigned 64-bit value */
bool util_decode_int64(char **in, int64_t *val, char break_char) {
  int ret = false;
  if (in != NULL && *in != NULL && val != NULL) {
    uint8_t nibble;
    int64_t tmp = 0;
    int count;
    int sign = 1;
    if (**in == '-') {
      sign = -1;
      (*in)++;
    }
    if (**in == '\0') {
      /* We are expecting at least one character */
      goto end;
    }
    for (count = 0; **in && count < 16; count++, (*in)++) {
      if (!util_decode_nibble(*in, &nibble))
        break;
      /* Overflow */
      if ((count == 0) && (sign == -1) && (nibble & 0x8))
        goto end;
      tmp = (tmp << 4) + nibble;
    }
    if (**in != break_char) {
      /* Wrong terminating character */
      goto end;
    }
    if (**in)
      (*in)++;
    *val = sign * tmp;
    ret = true;
  }
end:
  return ret;
}

/* Decode a hex string to an unsigned 64-bit value */
bool util_decode_uint64(char **in, uint64_t *val, char break_char) {
  bool ret = false;
  if (in != NULL && *in != NULL && val != NULL) {
    uint8_t nibble;
    uint64_t tmp;
    int count;

    if (**in == '\0') {
      /* We are expecting at least one character */
      goto end;
    }

    for (tmp = 0, count = 0; **in && count < 16; count++, (*in)++) {
      if (!util_decode_nibble(*in, &nibble))
        break;
      tmp = (tmp << 4) + nibble;
    }

    if (**in != break_char) {
      /* Wrong terminating character */
      goto end;
    }
    if (**in)
      (*in)++;
    *val = tmp;
    ret = true;
  }
end:
  return ret;
}

size_t util_escape_binary(uint8_t *dst, uint8_t *src, size_t size) {
  size_t i, j;
  for (i = 0, j = 0; i < size; i++) {
    uint8_t c = src[i];
    if ((0x23 == c) || (0x24 == c) || (0x2a == c) || (0x7d == c)) {
      dst[j++] = 0x7d;
      dst[j++] = c ^ 0x20;
    } else {
      dst[j++] = c;
    }
  }
  return j;
}

void util_usleep(unsigned int usecs)
{
    struct timespec t;
    t.tv_sec = usecs / (1000000);
    t.tv_nsec = (usecs % (1000000)) * 1000;
    nanosleep(&t, NULL);
}
