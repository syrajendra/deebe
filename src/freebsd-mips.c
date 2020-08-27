/*
 * Copyright (c) 2012-2015, Juniper Networks, Inc.
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
#include <sys/cdefs.h>
#include <sys/procfs.h>
#include "target_ptrace.h"
#include "global.h"
#include "os.h"

#define GDB_GREG_MAX 37

int ptrace_arch_gdb_greg_max() { return GDB_GREG_MAX; }

#define GDB_ZERO 0
#define GDB_AST 1
#define GDB_V0 2
#define GDB_V1 3
#define GDB_A0 4
#define GDB_A1 5
#define GDB_A2 6
#define GDB_A3 7
#if defined(__mips_n32) || defined(__mips_n64)
#define GDB_A4 8
#define GDB_A5 9
#define GDB_A6 10
#define GDB_A7 11
#define GDB_T0 12
#define GDB_T1 13
#define GDB_T2 14
#define GDB_T3 15
#else
#define GDB_T0  8
#define GDB_T1  9
#define GDB_T2 10
#define GDB_T3 11
#define GDB_T4 12
#define GDB_T5 13
#define GDB_T6 14
#define GDB_T7 15
#endif
#define GDB_S0 16
#define GDB_S1 17
#define GDB_S2 18
#define GDB_S3 19
#define GDB_S4 20
#define GDB_S5 21
#define GDB_S6 22
#define GDB_S7 23
#define GDB_T8 24
#define GDB_T9 25
#define GDB_K0 26
#define GDB_K1 27
#define GDB_GP 28
#define GDB_SP 29
#define GDB_S8 30
#define GDB_RA 31
#define GDB_STATUS 32 /* ? */
#define GDB_LO 33
#define GDB_HI 34
#define GDB_BADVADDR 35
#define GDB_CAUSE 36
#define GDB_PC 37

#ifdef DEEBE_MIPS_64BIT_COMPAT
#define GDB_GREG_SIZE 8
#else
#define GDB_GREG_SIZE 0
#endif

#define DEEBE_REG_STRUCT reg
#include "regmacros.h"

/* General */
struct reg_location_list grll[] = {
    RLL(zero,     r_regs[0],  GDB_ZERO,     0, 0, 0, unit, hex,  0,  0, X, X),
    RLL(ast,      r_regs[1],  GDB_AST,      0, 0, 0, unit, hex,  1,  1, X, X),
    RLL(v0,       r_regs[2],  GDB_V0,       0, 0, 0, unit, hex,  2,  2, X, X),
    RLL(v1,       r_regs[3],  GDB_V1,       0, 0, 0, unit, hex,  3,  3, X, X),
    RLL(a0,       r_regs[4],  GDB_A0,       0, 0, 0, unit, hex,  4,  4, X, X),
    RLL(a1,       r_regs[5],  GDB_A1,       0, 0, 0, unit, hex,  5,  5, X, X),
    RLL(a2,       r_regs[6],  GDB_A2,       0, 0, 0, unit, hex,  6,  6, X, X),
    RLL(a3,       r_regs[7],  GDB_A3,       0, 0, 0, unit, hex,  7,  7, X, X),
#if defined(__mips_n32) || defined(__mips_n64)
    RLL(t0,       r_regs[8],  GDB_A4,       0, 0, 0, unit, hex,  8,  8, X, X),
    RLL(t1,       r_regs[9],  GDB_A5,       0, 0, 0, unit, hex,  9,  9, X, X),
    RLL(t2,       r_regs[10], GDB_A6,       0, 0, 0, unit, hex, 10, 10, X, X),
    RLL(t3,       r_regs[11], GDB_A7,       0, 0, 0, unit, hex, 11, 11, X, X),
    RLL(t4,       r_regs[12], GDB_T0,       0, 0, 0, unit, hex, 12, 12, X, X),
    RLL(t5,       r_regs[13], GDB_T1,       0, 0, 0, unit, hex, 13, 13, X, X),
    RLL(t6,       r_regs[14], GDB_T2,       0, 0, 0, unit, hex, 14, 14, X, X),
    RLL(t7,       r_regs[15], GDB_T3,       0, 0, 0, unit, hex, 15, 15, X, X),
#else
    RLL(t0,       r_regs[8],  GDB_T0,       0, 0, 0, unit, hex,  8,  8, X, X),
    RLL(t1,       r_regs[9],  GDB_T1,       0, 0, 0, unit, hex,  9,  9, X, X),
    RLL(t2,       r_regs[10], GDB_T2,       0, 0, 0, unit, hex, 10, 10, X, X),
    RLL(t3,       r_regs[11], GDB_T3,       0, 0, 0, unit, hex, 11, 11, X, X),
    RLL(t4,       r_regs[12], GDB_T4,       0, 0, 0, unit, hex, 12, 12, X, X),
    RLL(t5,       r_regs[13], GDB_T5,       0, 0, 0, unit, hex, 13, 13, X, X),
    RLL(t6,       r_regs[14], GDB_T6,       0, 0, 0, unit, hex, 14, 14, X, X),
    RLL(t7,       r_regs[15], GDB_T7,       0, 0, 0, unit, hex, 15, 15, X, X),
#endif
    RLL(s0,       r_regs[16], GDB_S0,       0, 0, 0, unit, hex, 16, 16, X, X),
    RLL(s1,       r_regs[17], GDB_S1,       0, 0, 0, unit, hex, 17, 17, X, X),
    RLL(s2,       r_regs[18], GDB_S2,       0, 0, 0, unit, hex, 18, 18, X, X),
    RLL(s3,       r_regs[19], GDB_S3,       0, 0, 0, unit, hex, 19, 19, X, X),
    RLL(s4,       r_regs[20], GDB_S4,       0, 0, 0, unit, hex, 20, 20, X, X),
    RLL(s5,       r_regs[21], GDB_S5,       0, 0, 0, unit, hex, 21, 21, X, X),
    RLL(s6,       r_regs[22], GDB_S6,       0, 0, 0, unit, hex, 22, 22, X, X),
    RLL(s7,       r_regs[23], GDB_S7,       0, 0, 0, unit, hex, 23, 23, X, X),
    RLL(t8,       r_regs[24], GDB_T8,       0, 0, 0, unit, hex, 24, 24, X, X),
    RLL(t9,       r_regs[25], GDB_T9,       0, 0, 0, unit, hex, 25, 25, X, X),
    RLL(k0,       r_regs[26], GDB_K0,       0, 0, 0, unit, hex, 26, 26, X, X),
    RLL(k1,       r_regs[27], GDB_K1,       0, 0, 0, unit, hex, 27, 27, X, X),
    RLL(gp,       r_regs[28], GDB_GP,       0, 0, 0, unit, hex, 28, 28, X, X),
    RLL(sp,       r_regs[29], GDB_SP,       0, 0, 0, unit, hex, 29, 29, X, X),
    RLL(s8,       r_regs[30], GDB_S8,       0, 0, 0, unit, hex, 30, 30, X, X),
    RLL(ra,       r_regs[31], GDB_RA,       0, 0, 0, unit, hex, 31, 31, X, X),
    RLL(status,   r_regs[32], GDB_STATUS,   0, 0, 0, unit, hex, 32, 32, X, X),
    RLL(lo,       r_regs[33], GDB_LO,       0, 0, 0, unit, hex, 33, 33, X, X),
    RLL(hi,       r_regs[34], GDB_HI,       0, 0, 0, unit, hex, 34, 34, X, X),
    RLL(badvaddr, r_regs[35], GDB_BADVADDR, 0, 0, 0, unit, hex, 35, 35, X, X),
    RLL(cause,    r_regs[36], GDB_CAUSE,    0, 0, 0, unit, hex, 36, 36, X, X),
    RLL(pc,       r_regs[37], GDB_PC,       0, 0, 0, unit, hex, 37, 37, X, X),
    {0},
};

#define GDB_FPR0 38
#define GDB_FPR1  (GDB_FPR0 + 0x01)
#define GDB_FPR2  (GDB_FPR0 + 0x02)
#define GDB_FPR3  (GDB_FPR0 + 0x03)
#define GDB_FPR4  (GDB_FPR0 + 0x04)
#define GDB_FPR5  (GDB_FPR0 + 0x05)
#define GDB_FPR6  (GDB_FPR0 + 0x06)
#define GDB_FPR7  (GDB_FPR0 + 0x07)
#define GDB_FPR8  (GDB_FPR0 + 0x08)
#define GDB_FPR9  (GDB_FPR0 + 0x09)
#define GDB_FPR10 (GDB_FPR0 + 0x0A)
#define GDB_FPR11 (GDB_FPR0 + 0x0B)
#define GDB_FPR12 (GDB_FPR0 + 0x0C)
#define GDB_FPR13 (GDB_FPR0 + 0x0D)
#define GDB_FPR14 (GDB_FPR0 + 0x0E)
#define GDB_FPR15 (GDB_FPR0 + 0x0F)
#define GDB_FPR16 (GDB_FPR0 + 0x10)
#define GDB_FPR17 (GDB_FPR0 + 0x11)
#define GDB_FPR18 (GDB_FPR0 + 0x12)
#define GDB_FPR19 (GDB_FPR0 + 0x13)
#define GDB_FPR20 (GDB_FPR0 + 0x14)
#define GDB_FPR21 (GDB_FPR0 + 0x15)
#define GDB_FPR22 (GDB_FPR0 + 0x16)
#define GDB_FPR23 (GDB_FPR0 + 0x17)
#define GDB_FPR24 (GDB_FPR0 + 0x18)
#define GDB_FPR25 (GDB_FPR0 + 0x19)
#define GDB_FPR26 (GDB_FPR0 + 0x1A)
#define GDB_FPR27 (GDB_FPR0 + 0x1B)
#define GDB_FPR28 (GDB_FPR0 + 0x1C)
#define GDB_FPR29 (GDB_FPR0 + 0x1D)
#define GDB_FPR30 (GDB_FPR0 + 0x1E)
#define GDB_FPR31 (GDB_FPR0 + 0x1F)

#define GDB_FCR31 (GDB_FPR0 + 0x20)
#define GDB_FCR0 (GDB_FPR0 + 0x21)

#define GDB_UNUSED_72 72
#define GDB_UNUSED_73 73
#define GDB_UNUSED_74 74
#define GDB_UNUSED_75 75
#define GDB_UNUSED_76 76
#define GDB_UNUSED_77 77
#define GDB_UNUSED_78 78
#define GDB_UNUSED_79 79
#define GDB_UNUSED_80 80
#define GDB_UNUSED_81 81
#define GDB_UNUSED_82 82
#define GDB_UNUSED_83 83
#define GDB_UNUSED_84 84
#define GDB_UNUSED_85 85
#define GDB_UNUSED_86 86
#define GDB_UNUSED_87 87
#define GDB_UNUSED_88 88
#define GDB_UNUSED_89 89

#define FP(NAME, n)                                                            \
  {                                                                            \
    .off = sizeof(f_register_t) * n, .size = sizeof(f_register_t),             \
    .gdb = GDB_FPR##n, .name = #NAME, .gdb_size = sizeof(f_register_t),        \
  }
/* Floating point */
struct reg_location_list frll[] = {
    FP(fp0, 0),
    FP(fp1, 1),
    FP(fp2, 2),
    FP(fp3, 3),
    FP(fp4, 4),
    FP(fp5, 5),
    FP(fp6, 6),
    FP(fp7, 7),
    FP(fp8, 8),
    FP(fp9, 9),
    FP(fp10, 10),
    FP(fp11, 11),
    FP(fp12, 12),
    FP(fp13, 13),
    FP(fp14, 14),
    FP(fp15, 15),
    FP(fp16, 16),
    FP(fp17, 17),
    FP(fp18, 18),
    FP(fp19, 19),
    FP(fp20, 20),
    FP(fp21, 21),
    FP(fp22, 22),
    FP(fp23, 23),
    FP(fp24, 24),
    FP(fp25, 25),
    FP(fp26, 26),
    FP(fp27, 27),
    FP(fp28, 28),
    FP(fp29, 29),
    FP(fp30, 30),
    FP(fp31, 31),
    {0},
};

/* Extended */
struct reg_location_list fxrll[] = {
    {0},
};

static uint8_t mips_break[4] = {0x00, 0x00, 0x00, 0x0d};

int ptrace_arch_swbreak_insn(void *bdata) {
  int ret = RET_ERR;
  /* Use bkpt */
  memcpy(bdata, &mips_break[0], 4);
  ret = RET_OK;

  return ret;
}

size_t ptrace_arch_swbreak_size() { return 4; }

size_t ptrace_arch_swbrk_rollback() { return 0; }

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc) {
  _read_greg(tid);
  memcpy(pc, _target.reg + 37 * sizeof(register_t), sizeof(register_t));
}

void ptrace_arch_set_pc(pid_t tid, unsigned long pc) {
  _read_greg(tid);
  memcpy(_target.reg + 37 * sizeof(register_t), &pc, sizeof(register_t));
  _write_greg(tid);
}

void ptrace_arch_set_singlestep(pid_t pid, long *request) {
  ptrace_os_set_singlestep(pid, request);
}

void ptrace_arch_clear_singlestep(pid_t pid) {
  ptrace_os_clear_singlestep(pid);
}

bool ptrace_arch_check_unrecognized_register(int reg, size_t *pad_size) {
  bool ret = false;

  /* XXX track this down */
  if ((GDB_FCR31 == reg) || (GDB_FCR0 == reg)) {
    *pad_size = 4;
    ret = true;
  }

  if ((GDB_UNUSED_72 == reg) || (GDB_UNUSED_73 == reg) ||
      (GDB_UNUSED_74 == reg) || (GDB_UNUSED_75 == reg) ||
      (GDB_UNUSED_76 == reg) || (GDB_UNUSED_77 == reg) ||
      (GDB_UNUSED_78 == reg) || (GDB_UNUSED_79 == reg) ||
      (GDB_UNUSED_80 == reg) || (GDB_UNUSED_81 == reg) ||
      (GDB_UNUSED_82 == reg) || (GDB_UNUSED_83 == reg) ||
      (GDB_UNUSED_84 == reg) || (GDB_UNUSED_85 == reg) ||
      (GDB_UNUSED_86 == reg) || (GDB_UNUSED_87 == reg) ||
      (GDB_UNUSED_88 == reg) || (GDB_UNUSED_89 == reg)) {
    *pad_size = 4;
    ret = true;
  }

  return ret;
}

int ptrace_arch_signal_to_gdb(int sig) { return host_signal_to_gdb(sig); }

int ptrace_arch_signal_from_gdb(int gdb) { return host_signal_from_gdb(gdb); }

bool ptrace_arch_support_watchpoint(pid_t tid, int type) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_add_watchpoint(pid_t pid, int type, unsigned long addr,
                                size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t pid, int type, unsigned long addr,
                                   size_t len) {
  bool ret = false;
  return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t pid, unsigned long *addr) {
  bool ret = false;
  return ret;
}

void ptrace_arch_read_fxreg(pid_t pid) { /* stub */ }

void ptrace_arch_write_fxreg(pid_t pid) { /* stub */ }

void ptrace_arch_option_set_syscall(pid_t pid) {
  ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig) { return false; }

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
                             void *arg3, void *arg4, void *ret) {
  _read_greg(tid);
}

bool ptrace_arch_support_hardware_breakpoints(pid_t tid) { return false; }
bool ptrace_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,
                                         size_t len) {
  return false;
}
bool ptrace_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr,
                                            size_t len) {
  return false;
}

bool ptrace_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc) {
  return false;
}

bool ptrace_arch_memory_region_info(uint64_t addr, char *out_buff,
                                    size_t out_buf_size) {
  //return ptrace_os_memory_region_info(addr, out_buff, out_buf_size);
  return false;
}

bool ptrace_arch_read_auxv(char *out_buff, size_t out_buf_size, size_t offset,
                           size_t *size) {
  return ptrace_os_read_auxv(out_buff, out_buf_size, offset, size);
}

const char *ptrace_arch_get_xml_register_string() {
  static char *str = "mips";
  return str;
}

void ptrace_arch_option_set_thread(pid_t pid) {
  ptrace_os_option_set_thread(pid);
}