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
#include "gdb-arm.h"

int ptrace_arch_gdb_greg_max() { return GDB_GREG_MAX; }

/* General */
#define DEEBE_REG_STRUCT reg
#include "regmacros.h"
struct reg_location_list grll[] = {
    RLL(gp0, r[0], GDB_GPR0, 0, 0, 0, uint, hex, 0, 0, arg1, r0),
    RLL(gp1, r[1], GDB_GPR1, 0, 0, 0, uint, hex, 1, 1, arg2, r1),
    RLL(gp2, r[2], GDB_GPR2, 0, 0, 0, uint, hex, 2, 2, arg3, r2),
    RLL(gp3, r[3], GDB_GPR3, 0, 0, 0, uint, hex, 3, 3, arg4, r3),
    RLL(gp4, r[4], GDB_GPR4, 0, 0, 0, uint, hex, 4, 4, X, r4),
    RLL(gp5, r[5], GDB_GPR5, 0, 0, 0, uint, hex, 5, 5, X, r5),
    RLL(gp6, r[6], GDB_GPR6, 0, 0, 0, uint, hex, 6, 6, X, r6),
    RLL(gp7, r[7], GDB_GPR7, 0, 0, 0, uint, hex, 7, 7, X, r7),
    RLL(gp8, r[8], GDB_GPR8, 0, 0, 0, uint, hex, 8, 8, X, r8),
    RLL(gp9, r[9], GDB_GPR9, 0, 0, 0, uint, hex, 9, 9, X, r9),
    RLL(gp10, r[10], GDB_GPR10, 0, 0, 0, uint, hex, 10, 10, X, r10),
    RLL(gp11, r[11], GDB_GPR11, 0, 0, 0, uint, hex, 11, 11, X, r11),
    RLL(gp12, r[12], GDB_GPR12, 0, 0, 0, uint, hex, 12, 12, X, r12),
    RLL(sp, r_sp, GDB_SP, 0, 0, 0, uint, hex, 13, 13, sp, r13),
    RLL(lr, r_lr, GDB_LR, 0, 0, 0, uint, hex, 14, 14, lr, r14),
    RLL(pc, r_pc, GDB_PC, 0, 0, 0, uint, hex, 15, 15, pc, r15),
    RLL(cpsr, r_cpsr, GDB_CPSR, 0, 0, 0, uint, hex, 16, 16, X, psr),
    {0},
};

/* Floating point */
#undef DEEBE_REG_STRUCT
#define DEEBE_REG_STRUCT fpreg
#include "regmacros.h"
struct reg_location_list frll[] = {
    RLL(fp0, fpr[0], GDB_FPR0, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp1, fpr[1], GDB_FPR1, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp2, fpr[2], GDB_FPR2, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp3, fpr[3], GDB_FPR3, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp4, fpr[4], GDB_FPR4, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp5, fpr[5], GDB_FPR5, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp6, fpr[6], GDB_FPR6, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fp7, fpr[7], GDB_FPR7, 0, 0, 0, ieee754, float, -1, -1, X, X),
    RLL(fpsr, fpr_fpsr, GDB_FPSR, 0, 0, 0, uint, hex, -1, -1, X, X),
    {0},
};

/* Defined in freebsd-arm.c or netbsd-arm.c */
extern struct reg_location_list frll[];

/* Extended */
struct reg_location_list fxrll[] = {
    {0},
};

#ifndef __AARCH32__
static uint32_t bkpt[1] = {0xe6000011};
#else
static uint32_t bkpt[1] = {0xe7ffdefe};
#endif

size_t ptrace_arch_swbreak_size() { return 4; }

int ptrace_arch_swbreak_insn(void *bdata) {
  int ret = RET_NOSUPP;
  /* Use bkpt */
  memcpy(bdata, &bkpt[0], 4);
  ret = RET_OK;
  return ret;
}

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc) {
  _read_greg(tid);
  memcpy(pc, _target.reg + 15 * sizeof(unsigned int), sizeof(unsigned int));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc) {
  _read_greg(tid);
  memcpy(_target.reg + 15 * sizeof(unsigned int), &pc, sizeof(unsigned int));
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

void ptrace_arch_option_set_thread(pid_t pid) {
  ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid) {
  return ptrace_os_check_new_thread(pid, status, out_pid);
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

void ptrace_arch_read_dbreg(pid_t tid) { /* noop */ }

void ptrace_arch_write_dbreg(pid_t tid) { /* noop */ }

const char *ptrace_arch_get_xml_register_string() {
  static char *str = "arm";
  return str;
}
