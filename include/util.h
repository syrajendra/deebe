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
#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

extern const char util_hex[];
void util_print_buffer(FILE *fd, size_t current, size_t total,
                       unsigned char *buffer);
void util_log(const char *fmt, ...);
void util_encode_byte(unsigned int val, char *out);
bool util_decode_byte(const char *in, uint8_t *byte_ptr);
bool util_decode_nibble(const char *in, uint8_t *nibble);
int util_hex_nibble(char in);
int util_encode_data(const unsigned char *data, size_t data_len, char *out,
                     size_t out_size);
int util_encode_string(const char *s, char *out, size_t out_size);
bool util_decode_int64(char **in, int64_t *val, char break_char);
bool util_decode_uint32(char **in, uint32_t *val, char break_char);
bool util_decode_uint64(char **in, uint64_t *val, char break_char);
size_t util_escape_binary(uint8_t *dst, uint8_t *src, size_t size);
void util_usleep(unsigned int usecs);

#define util_decode_reg(a, b) util_decode_uint32((a), (b), '\0')

#endif
