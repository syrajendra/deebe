/*
 * Copyright (c) 2013-2014 Juniper Networks, Inc.
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
#include "os.h"
#include "global.h"

/*
  Fetch user debug register type
  for i386 linux it is int
  for amd64 linux it is unsigned long int
*/
struct user g_udr;
typedef __typeof__(g_udr.u_debugreg[0]) udr_type_t;

void ptrace_arch_set_singlestep(/*@unused@*/ pid_t pid, long *request) {
  /* Let the kernel handle the heavy lifting */
  *request = PTRACE_SINGLESTEP;
}

void ptrace_arch_clear_singlestep(pid_t pid) { /* a noop */ }

int ptrace_arch_signal_to_gdb(int sig) { return host_signal_to_gdb(sig); }

int ptrace_arch_signal_from_gdb(int gdb) { return host_signal_from_gdb(gdb); }

bool x86_read_debug_reg(pid_t tid, size_t reg, void *val) {
  bool ret = false;
  if (reg < 8) {
    _read_single_dbreg(tid, reg);
    size_t addr = reg * sizeof(udr_type_t);
    if (addr + sizeof(udr_type_t) <= _target.dbreg_size) {
      memcpy(val, _target.dbreg + addr, sizeof(udr_type_t));
      ret = true;
    }
  }
  return ret;
}

bool x86_write_debug_reg(pid_t tid, size_t reg, void *val) {
  bool ret = false;
  if (reg < 8) {
    _read_single_dbreg(tid, reg);
    unsigned long addr = reg * sizeof(udr_type_t);
    if (addr + sizeof(udr_type_t) <= _target.dbreg_size) {
      if (_write_single_dbreg(tid, reg, val)){
        memcpy(_target.dbreg + addr, val, sizeof(udr_type_t));
        ret = true;
      } else {
        DBG_PRINT("ERROR : Writing addr %lu to debug-register:%d failed for tid :%d", (unsigned long *)val, reg, tid);
      }
    }
  }
  return ret;
}

void ptrace_arch_read_dbreg(pid_t tid) {
  _target.dbreg_size = 8 * sizeof(udr_type_t);
  if (NULL == _target.dbreg)
    _target.dbreg = calloc(8, sizeof(udr_type_t));

  if (NULL != _target.dbreg) {
    size_t r;
    udr_type_t *val = (udr_type_t *)_target.dbreg;
    for (r = 0; r < 8; r++) {
      long v;
      unsigned long addr = offsetof(struct user, u_debugreg[r]);
      errno = 0;
      v = PTRACE(PTRACE_PEEKUSER, tid, addr, 0);
      if (0 == errno)
        memcpy(&val[r], &v, sizeof(udr_type_t));
      else
        break;
    }
  }
}

void ptrace_arch_write_dbreg(pid_t tid) {
  if (NULL != _target.dbreg) {
    size_t r;
    udr_type_t *val = (udr_type_t *)_target.dbreg;
    for (r = 0; r < 8; r++) {
      if (val[r] != 0) {
        unsigned long addr = offsetof(struct user, u_debugreg[r]);
        if (0 != PTRACE(PTRACE_POKEUSER, tid, addr, val[r]))
          break;
      }
    }
  }
}

bool ptrace_arch_read_single_dbreg(pid_t tid, size_t reg) {
  bool ret = false;
  _target.dbreg_size = 8 * sizeof(udr_type_t);
  if (NULL == _target.dbreg)
    _target.dbreg = calloc(8, sizeof(udr_type_t));

  if (NULL != _target.dbreg) {
    long v;
    udr_type_t *val = (udr_type_t *)_target.dbreg;
    unsigned long addr = offsetof(struct user, u_debugreg[reg]);
    errno = 0;
    v = PTRACE(PTRACE_PEEKUSER, tid, addr, 0);
    if (0 == errno){
      memcpy(&val[reg], &v, sizeof(udr_type_t));
      ret = true;
    } else {
      ret = false;
    }
  }
  return ret;
}

bool ptrace_arch_write_single_dbreg(pid_t tid, size_t reg, void *val) {
  bool ret = false;
  if (NULL != _target.dbreg) {
    unsigned long addr = offsetof(struct user, u_debugreg[reg]);
    if (0 != PTRACE(PTRACE_POKEUSER, tid, addr, *(udr_type_t*)val))
      ret = false;
    else
      ret = true;
  }
  return ret;
}

void ptrace_cleanup()
{
  if (_target.dbreg)    free(_target.dbreg);
  if (_target.reg)      free(_target.reg);
  if (_target.freg)     free(_target.freg);
  if (_target.fxreg)    free(_target.fxreg);
  if (_target.reg_rw)   free(_target.reg_rw);
  if (_target.freg_rw)  free(_target.freg_rw);
  if (_target.fxreg_rw) free(_target.fxreg_rw);
  if (_target.dbreg_rw) free(_target.dbreg_rw);
  if (_target.bpl)      free(_target.bpl);
}
