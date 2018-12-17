/*
 * Copyright (c) 2015, Juniper Networks, Inc.
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
#ifndef DEEBE_MACROS_H
#define DEEBE_MACROS_H

#include "util.h"

/* FreeBSD's assert throws warnings, rewrite here */
#define ASSERT(e)                                                              \
  ((e) ? (void)0 : fprintf(stderr, "Assertion failed at %s %s %d : %s\n",      \
                           __func__, __FILE__, __LINE__, #e))

#define WATCHDOG_ERROR()                                                       \
  do {                                                                         \
    fprintf(stderr, "Watchdog time expired, program exiting\n");               \
    exit(-1);                                                                  \
  } while (0)

#ifdef DEEBE_RELEASE
#define DBG_PRINT(fmt, args...)
#else
#define MY_PRINT(fmt, args...) util_log(fmt, ##args)
#define DBG_PRINT(fmt, args...) MY_PRINT("%s: "fmt, __func__, ##args)
#endif

#define PRINTABLE(c)                                                           \
  (((c) >= (__typeof__(c))0x20 && (c) < (__typeof__(c))127) ? (c) : '.')

#define GUARD_RLL(r) (((r).off == 0) && ((r).size == 0) && ((r).gdb == 0))

/*
 * Size of data buffer
 * lldb likes 0x20000
 * gdb likes   0x4000
 *
 * If you really want the full lldb ..
 *
 * #define GDB_INTERFACE_PARAM_DATABYTES_MAX (0x20000)
 */
#define GDB_INTERFACE_PARAM_DATABYTES_MAX (0x4000)

/* Size of input and out buffers */
#define INOUTBUF_SIZE (2 * GDB_INTERFACE_PARAM_DATABYTES_MAX + 32)

/* These must match the table of reasons the gdb_stop_string function */
#define LLDB_STOP_REASON_TRACE 0
#define LLDB_STOP_REASON_BREAKPOINT 1
#define LLDB_STOP_REASON_TRAP 2
#define LLDB_STOP_REASON_WATCHPOINT 3
#define LLDB_STOP_REASON_SIGNAL 4
#define LLDB_STOP_REASON_EXCEPTION 5 /* Not supported */
#define LLDB_STOP_REASON_MAX (LLDB_STOP_REASON_SIGNAL + 1)

#define PTRACE_ERROR_TRACEME 125
#define PTRACE_ERROR_RAISE_SIGSTOP 124
#define PTRACE_ERROR_EXECV 123
#define PTRACE_ERROR_ATTACH 122
#define PTRACE_ERROR_INTERNAL 121

/*
 * FreeBSD makes it a point to not define HOST_NAME_MAX
 * So if it isn't defined, use the linux value.
 */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif

/* Return values of gdb interface functions */
/* Success */
#define RET_OK (0)
/* Error */
#define RET_ERR (1)
 /* Operation is not supported */
#define RET_NOSUPP (2)
/* Repeat the last operation */
#define RET_IGNORE (3)
/* No body waiting.. skip resume and go back to waiting */
#define RET_CONTINUE_WAIT (4)

#endif
