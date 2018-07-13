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
#ifndef __DEEBE_GDB_AARCH64_H
#define __DEEBE_GDB_AARCH64_H

#define GDB_GREG_MAX 67 // fpsr & fpcr are not read

#define GDB_GPR0 0
#define GDB_GPR1 1
#define GDB_GPR2 2
#define GDB_GPR3 3
#define GDB_GPR4 4
#define GDB_GPR5 5
#define GDB_GPR6 6
#define GDB_GPR7 7
#define GDB_GPR8 8
#define GDB_GPR9 9
#define GDB_GPR10 10
#define GDB_GPR11 11
#define GDB_GPR12 12
#define GDB_GPR13 13
#define GDB_GPR14 14
#define GDB_GPR15 15
#define GDB_GPR16 16
#define GDB_GPR17 17
#define GDB_GPR18 18
#define GDB_GPR19 19
#define GDB_GPR20 20
#define GDB_GPR21 21
#define GDB_GPR22 22
#define GDB_GPR23 23
#define GDB_GPR24 24
#define GDB_GPR25 25
#define GDB_GPR26 26
#define GDB_GPR27 27
#define GDB_GPR28 28
#define GDB_FP 	  29 /* frame register */
#define GDB_LR 	  30 /* link register for return address */
#define GDB_SP 	  31 /* stack pointer */
#define GDB_PC    32 /* program counter */
#define GDB_CPSR  33 /* current program status register */

#define GDB_FPR0  34 /* first floating point register */
#define GDB_FPR31 (GDB_FPR0 + 31) /* last floating point register */
#define GDB_FPSR  66 /* floating point status register */
#define GDB_FPCR  67 /* floating point control register */

#endif
