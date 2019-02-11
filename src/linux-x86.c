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
#include "target_ptrace.h"
#include "global.h"
#include "os.h"
#include "gdb-x86.h"

union reg_dirty {
  struct {
    unsigned int gregs : 1;
    unsigned int fregs : 1;
    unsigned int fxregs : 1;
  } r;
  unsigned int u;
} dirt;

#define DEEBE_REG_STRUCT user
#include "regmacros.h"
struct reg_location_list grll[] = {
    RLL(ebx, regs.ebx, GDB_EBX, 0, 0, 0, uint, hex, 3, 3, X, X),
    RLL(ecx, regs.ecx, GDB_ECX, 0, 0, 0, uint, hex, 1, 1, X, X),
    RLL(edx, regs.edx, GDB_EDX, 0, 0, 0, uint, hex, 2, 2, X, X),
    RLL(esi, regs.esi, GDB_ESI, 0, 0, 0, uint, hex, 6, 6, X, X),
    RLL(edi, regs.edi, GDB_EDI, 0, 0, 0, uint, hex, 7, 7, X, X),
    RLL(ebp, regs.ebp, GDB_EBP, 0, 0, 0, uint, hex, 5, 5, fp, fp),
    RLL(eax, regs.eax, GDB_EAX, 0, 0, 0, uint, hex, 0, 0, X, X),
    RLL(ds, regs.xds, GDB_DS, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(es, regs.xes, GDB_ES, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(fs, regs.xfs, GDB_FS, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(gs, regs.xgs, GDB_GS, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(orig_eax, regs.orig_eax, GDB_ORIG_EAX, 0, 0, 0, uint, hex, -1, -1, X,
        X),
    RLL(eip, regs.eip, GDB_EIP, 0, 0, 0, uint, hex, 8, 8, pc, pc),
    RLL(cs, regs.xcs, GDB_CS, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(eflags, regs.eflags, GDB_EFLAGS, 0, 0, 0, uint, hex, 9, 9, flags,
        flags),
    RLL(esp, regs.esp, GDB_ESP, 0, 0, 0, uint, hex, 4, 4, sp, sp),
    RLL(ss, regs.xss, GDB_SS, 0, 4, 4, uint, hex, -1, -1, X, X),
    {0},
};

#undef DEEBE_REG_STRUCT
#define DEEBE_REG_STRUCT user_fpregs_struct
#include "regmacros.h"
struct reg_location_list frll[] = {
    RLL(ctrl, cwd, GDB_FCTRL, 0, 2, 4, uint, hex, -1, -1, X, X),
    RLL(stat, swd, GDB_FSTAT, 0, 2, 4, uint, hex, -1, -1, X, X),
    RLL(tag, twd, GDB_FTAG, 0, 2, 4, uint, hex, -1, -1, X, X),
    RLL(ioff, fip, GDB_FIOFF, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(iseg, fcs, GDB_FISEG, 0, 2, 4, uint, hex, -1, -1, X, X),
    RLL(op, fcs, GDB_FOP, 2, 2, 4, uint, hex, -1, -1, X, X),
    RLL(ooff, foo, GDB_FOOFF, 0, 4, 4, uint, hex, -1, -1, X, X),
    RLL(oseg, fos, GDB_FOSEG, 0, 2, 4, uint, hex, -1, -1, X, X),
    RLL(st0, st_space, GDB_FST0, 0, 10, 10, uint, hex, 11, 11, X, X),
    RLL(st1, st_space, GDB_FST1, 10, 10, 10, uint, hex, 12, 12, X, X),
    RLL(st2, st_space, GDB_FST2, 20, 10, 10, uint, hex, 13, 13, X, X),
    RLL(st3, st_space, GDB_FST3, 30, 10, 10, uint, hex, 14, 14, X, X),
    RLL(st4, st_space, GDB_FST4, 40, 10, 10, uint, hex, 15, 15, X, X),
    RLL(st5, st_space, GDB_FST5, 50, 10, 10, uint, hex, 16, 16, X, X),
    RLL(st6, st_space, GDB_FST6, 60, 10, 10, uint, hex, 17, 17, X, X),
    RLL(st7, st_space, GDB_FST7, 70, 10, 10, uint, hex, 18, 18, X, X),
    {0},
};

#define FXRLL(N, E, GDB, O, S, GDB_S)                                          \
  {                                                                            \
    .off = (O)+offsetof(struct user_fpxregs_struct, E),                        \
    .size = (0 != S) ? (S) : msizeof(struct user_fpxregs_struct, E),           \
    .gdb = (GDB), .name = #N,                                                  \
    .gdb_size =                                                                \
        (0 != GDB_S) ? (GDB_S) : msizeof(struct user_fpxregs_struct, E),       \
  }

struct reg_location_list fxrll[] = {
    FXRLL(mm0, xmm_space, GDB_XMM0, 0x00, 0x10, 0x10),
    FXRLL(mm1, xmm_space, GDB_XMM1, 0x10, 0x10, 0x10),
    FXRLL(mm2, xmm_space, GDB_XMM2, 0x20, 0x10, 0x10),
    FXRLL(mm3, xmm_space, GDB_XMM3, 0x30, 0x10, 0x10),
    FXRLL(mm4, xmm_space, GDB_XMM4, 0x40, 0x10, 0x10),
    FXRLL(mm5, xmm_space, GDB_XMM5, 0x50, 0x10, 0x10),
    FXRLL(mm6, xmm_space, GDB_XMM6, 0x60, 0x10, 0x10),
    FXRLL(mm7, xmm_space, GDB_XMM7, 0x70, 0x10, 0x10),
    FXRLL(csr, mxcsr, GDB_MXCSR, 0, 0, 0),
    {0},
};

#define GDB_GREG_MAX 16

int ptrace_arch_gdb_greg_max() { return GDB_GREG_MAX; }

void ptrace_arch_get_pc(pid_t tid, unsigned long *pc) {
  _read_greg(tid);
  memcpy(pc, _target.reg + offsetof(struct user, regs.eip),
         sizeof(unsigned long));
}
void ptrace_arch_set_pc(pid_t tid, unsigned long pc) {
  _read_greg(tid);
  memcpy(_target.reg + offsetof(struct user, regs.eip), &pc,
         sizeof(unsigned long));
  _write_greg(tid);
}

bool ptrace_arch_check_unrecognized_register(/*@unused@*/ int reg,
                                             /*@unused@*/ size_t *pad_size) {
  bool ret = false;
  return ret;
}

void ptrace_arch_read_fxreg(pid_t tid) { ptrace_os_read_fxreg(tid); }

void ptrace_arch_write_fxreg(pid_t tid) { ptrace_os_write_fxreg(tid); }

void ptrace_arch_option_set_syscall(pid_t pid) {
  ptrace_os_option_set_syscall(pid);
}

bool ptrace_arch_check_syscall(pid_t pid, int *in_out_sig) {
  return ptrace_os_check_syscall(pid, in_out_sig);
}

void ptrace_arch_get_syscall(pid_t tid, void *id, void *arg1, void *arg2,
                             void *arg3, void *arg4, void *ret) {
  _read_greg(tid);
  memcpy(id, _target.reg + offsetof(struct user, regs.orig_eax),
         sizeof(unsigned long));
  memcpy(arg1, _target.reg + offsetof(struct user, regs.ebx),
         sizeof(unsigned long));
  memcpy(arg2, _target.reg + offsetof(struct user, regs.ecx),
         sizeof(unsigned long));
  memcpy(arg3, _target.reg + offsetof(struct user, regs.edx),
         sizeof(unsigned long));
  memcpy(arg4, _target.reg + offsetof(struct user, regs.esi),
         sizeof(unsigned long));
  memcpy(ret, _target.reg + offsetof(struct user, regs.eax),
         sizeof(unsigned long));
}

void ptrace_arch_option_set_thread(pid_t pid) {
  ptrace_os_option_set_thread(pid);
}

bool ptrace_arch_wait_new_thread(pid_t *out_pid, int *out_status) {
  return ptrace_os_wait_new_thread(out_pid, out_status);
}

bool ptrace_arch_check_new_thread(pid_t pid, int status, pid_t *out_pid) {
  return ptrace_os_check_new_thread(pid, status, out_pid);
}

bool ptrace_arch_read_auxv(char *out_buff, size_t out_buf_size, size_t offset,
                           size_t *size) {
  return ptrace_os_read_auxv(out_buff, out_buf_size, offset, size);
}
