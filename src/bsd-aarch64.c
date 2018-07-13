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
#include "os.h"
#include "gdb-aarch64.h"

int ptrace_arch_gdb_greg_max() { return GDB_GREG_MAX; }

/* General */
#define DEEBE_REG_STRUCT reg
#include "regmacros.h"
struct reg_location_list grll[] = {
    RLL(gp0, x[0], GDB_GPR0, 0, 0, 0, uint64_t, hex, 0, 0, arg1, r0),
    RLL(gp1, x[1], GDB_GPR1, 0, 0, 0, uint64_t, hex, 1, 1, arg2, r1),
    RLL(gp2, x[2], GDB_GPR2, 0, 0, 0, uint64_t, hex, 2, 2, arg3, r2),
    RLL(gp3, x[3], GDB_GPR3, 0, 0, 0, uint64_t, hex, 3, 3, arg4, r3),
    RLL(gp4, x[4], GDB_GPR4, 0, 0, 0, uint64_t, hex, 4, 4, arg5, r4),
    RLL(gp5, x[5], GDB_GPR5, 0, 0, 0, uint64_t, hex, 5, 5, arg6, r5),
    RLL(gp6, x[6], GDB_GPR6, 0, 0, 0, uint64_t, hex, 6, 6, arg7, r6),
    RLL(gp7, x[7], GDB_GPR7, 0, 0, 0, uint64_t, hex, 7, 7, arg8, r7),
    RLL(gp8, x[8], GDB_GPR8, 0, 0, 0, uint64_t, hex, 8, 8, X, r8),
    RLL(gp9, x[9], GDB_GPR9, 0, 0, 0, uint64_t, hex, 9, 9, X, r9),
    RLL(gp10, x[10], GDB_GPR10, 0, 0, 0, uint64_t, hex, 10, 10, X, r10),
    RLL(gp11, x[11], GDB_GPR11, 0, 0, 0, uint64_t, hex, 11, 11, X, r11),
    RLL(gp12, x[12], GDB_GPR12, 0, 0, 0, uint64_t, hex, 12, 12, X, r12),
    RLL(gp13, x[13], GDB_GPR13, 0, 0, 0, uint64_t, hex, 13, 13, X, r13),
    RLL(gp14, x[14], GDB_GPR14, 0, 0, 0, uint64_t, hex, 14, 14, X, r14),
    RLL(gp15, x[15], GDB_GPR15, 0, 0, 0, uint64_t, hex, 15, 15, X, r15),
    RLL(gp16, x[16], GDB_GPR16, 0, 0, 0, uint64_t, hex, 16, 16, X, r16),
    RLL(gp17, x[17], GDB_GPR17, 0, 0, 0, uint64_t, hex, 17, 17, X, r17),
    RLL(gp18, x[18], GDB_GPR18, 0, 0, 0, uint64_t, hex, 18, 18, X, r18),
    RLL(gp19, x[19], GDB_GPR19, 0, 0, 0, uint64_t, hex, 19, 19, X, r19),
    RLL(gp20, x[20], GDB_GPR20, 0, 0, 0, uint64_t, hex, 20, 20, X, r20),
    RLL(gp21, x[21], GDB_GPR21, 0, 0, 0, uint64_t, hex, 21, 21, X, r21),
    RLL(gp22, x[22], GDB_GPR22, 0, 0, 0, uint64_t, hex, 22, 22, X, r22),
    RLL(gp23, x[23], GDB_GPR23, 0, 0, 0, uint64_t, hex, 23, 23, X, r23),
    RLL(gp24, x[24], GDB_GPR24, 0, 0, 0, uint64_t, hex, 24, 24, X, r24),
    RLL(gp25, x[25], GDB_GPR25, 0, 0, 0, uint64_t, hex, 25, 25, X, r25),
    RLL(gp26, x[26], GDB_GPR26, 0, 0, 0, uint64_t, hex, 26, 26, X, r26),
    RLL(gp27, x[27], GDB_GPR27, 0, 0, 0, uint64_t, hex, 27, 27, X, r27),
    RLL(gp28, x[28], GDB_GPR28, 0, 0, 0, uint64_t, hex, 28, 28, X, r28),
    RLL(fp, x[29], GDB_FP, 0, 0, 0, uint64_t, hex, 29, 29, fp, r29),
    RLL(lr, lr, GDB_LR, 0, 0, 0, uint64_t, hex, 30, 30, lr, r30),
    RLL(sp, sp, GDB_SP, 0, 0, 0, uint64_t, hex, 31, 31, sp, r31),
    RLL(pc, elr, GDB_PC, 0, 0, 0, uint64_t, hex, 32, 32, pc, r32),
    RLL(cpsr, spsr, GDB_CPSR, 0, 0, 0, uint32_t, hex, 33, 33, X, psr),
    {0},
};

/* Floating point */
#undef DEEBE_REG_STRUCT
#define DEEBE_REG_STRUCT fpreg
#include "regmacros.h"
struct reg_location_list frll[] = {
    RLL(fp0, fp_q[0], GDB_FPR0, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp1, fp_q[1], GDB_FPR0 + 1, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp2, fp_q[2], GDB_FPR0 + 2, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp3, fp_q[3], GDB_FPR0 + 3, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp4, fp_q[4], GDB_FPR0 + 4, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp5, fp_q[5], GDB_FPR0 + 5, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp6, fp_q[6], GDB_FPR0 + 6, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp7, fp_q[7], GDB_FPR0 + 7, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp8, fp_q[8], GDB_FPR0 + 8, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp9, fp_q[9], GDB_FPR0 + 9, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp10, fp_q[10], GDB_FPR0 + 10, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp11, fp_q[11], GDB_FPR0 + 11, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp12, fp_q[12], GDB_FPR0 + 12, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp13, fp_q[13], GDB_FPR0 + 13, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp14, fp_q[14], GDB_FPR0 + 14, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp15, fp_q[15], GDB_FPR0 + 15, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp16, fp_q[16], GDB_FPR0 + 16, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp17, fp_q[17], GDB_FPR0 + 17, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp18, fp_q[18], GDB_FPR0 + 18, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp19, fp_q[19], GDB_FPR0 + 19, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp20, fp_q[20], GDB_FPR0 + 20, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp21, fp_q[21], GDB_FPR0 + 21, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp22, fp_q[22], GDB_FPR0 + 22, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp23, fp_q[23], GDB_FPR0 + 23, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp24, fp_q[24], GDB_FPR0 + 24, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp25, fp_q[25], GDB_FPR0 + 25, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp26, fp_q[26], GDB_FPR0 + 26, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp27, fp_q[27], GDB_FPR0 + 27, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp28, fp_q[28], GDB_FPR0 + 28, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp29, fp_q[29], GDB_FPR0 + 29, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp30, fp_q[30], GDB_FPR0 + 30, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fp31, fp_q[31], GDB_FPR31, 0, 0, 0, ieee754, __uint128_t, -1, -1, X, X),
    RLL(fpsr, fp_sr, GDB_FPSR, 0, 0, 0, uint32_t, hex, -1, -1, X, X),
    RLL(fpsr, fp_cr, GDB_FPCR, 0, 0, 0, uint32_t, hex, -1, -1, X, X),
    {0},
};

/* Defined in freebsd-arm.c or netbsd-arm.c */
extern struct reg_location_list frll[];

/* Extended */
struct reg_location_list fxrll[] = {
    {0},
};

static unsigned long bkpt[1] = {0xe6000011};

size_t ptrace_arch_swbreak_size() { return 8; }

int ptrace_arch_swbreak_insn(void *bdata) {
  int ret = RET_NOSUPP;
  /* Use bkpt */
  memcpy(bdata, &bkpt[0], 8);
  ret = RET_OK;
  return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc) {
  _read_greg(tid);
  memcpy(pc, _target.reg + 32 * sizeof(unsigned long), sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc) {
  _read_greg(tid);
  memcpy(_target.reg + 32 * sizeof(unsigned long), &pc, sizeof(unsigned long));
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
  return ret;
}

int ptrace_arch_signal_to_gdb(int sig) { return host_signal_to_gdb(sig); }

int ptrace_arch_signal_from_gdb(int gdb) { return host_signal_from_gdb(gdb); }

bool ptrace_arch_support_watchpoint(pid_t tid, int type) {
  bool ret = true;
  return ret;
}

bool ptrace_arch_add_watchpoint(pid_t pid, int type, unsigned long addr,
                                size_t len) {
  bool ret = true;
  return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t pid, int type, unsigned long addr,
                                   size_t len) {
  bool ret = true;
  return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t pid, unsigned long *addr) {
  bool ret = true;
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

void ptrace_arch_option_set_thread(pid_t pid) {
  ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid) {
  return ptrace_os_check_new_thread(pid, status, out_pid);
}

bool ptrace_arch_support_hardware_breakpoints(pid_t tid) { return true; }
bool ptrace_arch_add_hardware_breakpoint(pid_t tid, unsigned long addr,
                                         size_t len) {
  return true;
}
bool ptrace_arch_remove_hardware_breakpoint(pid_t tid, unsigned long addr,
                                            size_t len) {
  return true;
}

bool ptrace_arch_hit_hardware_breakpoint(pid_t tid, unsigned long pc) {
  return true;
}

void ptrace_arch_read_dbreg(pid_t tid) { /* noop */ }

void ptrace_arch_write_dbreg(pid_t tid) { /* noop */ }

const char *ptrace_arch_get_xml_register_string() {
  static char *str = "aarch64";
  return str;
}
