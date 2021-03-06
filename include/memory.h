/*
 * Copyright (c) 2016, Juniper Networks, Inc.
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
#ifndef DEEBE_MEMORY_H
#define DEEBE_MEMORY_H

int memory_read(pid_t tid, uint64_t addr, uint8_t *data, size_t size,
		size_t *read_size, bool breakpoint_check);
int memory_read_gdb(pid_t tid, uint64_t addr, uint8_t *data, size_t size,
                    size_t *read_size);
int memory_write(pid_t tid, uint64_t addr, uint8_t *data,
		 size_t size, bool breakpoint_check);
bool memory_region_info_gdb(uint64_t addr, char *out_buff, size_t out_buf_size);

int memory_write_gdb(pid_t tid, uint64_t addr, uint8_t *data, size_t size);
void memory_os_request_size(size_t *size);
bool memory_os_read(pid_t tid, void *addr, void *val);
bool memory_os_write(pid_t tid, void *addr, void *val);
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff, size_t out_buf_size);

#endif /* DEEBE_MEMORY_H */
