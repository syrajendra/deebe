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
#include "target_ptrace.h"
#include "global.h"
#include "os.h"

static bool x86_verbose = false;
/*
  u_drs => User Debug Register Status
  u_drc -> User Debug Register Control

  The u_drs.b<n> is set if the conditions described by
  DR<n>, len<n> & rw<n> occurs

  Note: Processor sets u_drs.b<n> regardless of whether u_drc.g<n> or
        u_drc.l<n> is set
*/
union u_drc {
  /* DR7 control register
      rw<n> : 2 bits
         00 : Break on instruction execution only
         01 : Break on data writes only
         10 : undefined
         11 : Break on data reads or writes but not instruction fetches

      len<n>: 2 bits
         00 : one-byte length
         01 : two-byte length
         10 : undefined
         11 : four-byte length

      l<n>  : 1 bit
        tracer sets local enable bit & it gets automatically reset by processor at
        every  task switch

      g<n>  : 1 bit
        tracer sets global enable bit & it is not reset by processor on task switch

      Note: l<n> & g<n> bits are selectively enabled for the four address
            in DR0 - DR<3> breakpoint conditions.

      le<n>  : 1 bit
        Local enable for breakpoint at instruction that causes data breakpoint
        Proccessor clears this bit on task swtich

      ge<n>  : 1 bit
        Global enable for breakpoint at instruction that causes data breakpoint
        Processor does not clear this bit on task switch

      gd     : 1 bit
        General detect enbale flag is set to debug exception occurs when
        a program attempts to write any of the DR0-DR7 registers
  */
  struct {
    unsigned l0 : 1;
    unsigned g0 : 1;
    unsigned l1 : 1;
    unsigned g1 : 1;
    unsigned l2 : 1;
    unsigned g2 : 1;
    unsigned l3 : 1;
    unsigned g3 : 1;
    unsigned le : 1;
    unsigned ge : 1;
    unsigned pad0 : 3;
    unsigned gd : 1;
    unsigned pad1 : 2;
    unsigned rw0 : 2;
    unsigned len0 : 2;
    unsigned rw1 : 2;
    unsigned len1 : 2;
    unsigned rw2 : 2;
    unsigned len2 : 2;
    unsigned rw3 : 2;
    unsigned len3 : 2;
  } b;
  unsigned long v;
};

#define DBP_DEBUG_CONTROL(v)                  \
  DBG_PRINT("dbc.l0 %d\n", v.b.l0);           \
  DBG_PRINT("dbc.g0 %d\n", v.b.g0);           \
  DBG_PRINT("dbc.l1 %d\n", v.b.l1);           \
  DBG_PRINT("dbc.g1 %d\n", v.b.g1);           \
  DBG_PRINT("dbc.l2 %d\n", v.b.l2);           \
  DBG_PRINT("dbc.g2 %d\n", v.b.g2);           \
  DBG_PRINT("dbc.l3 %d\n", v.b.l3);           \
  DBG_PRINT("dbc.g3 %d\n", v.b.g3);           \
  DBG_PRINT("dbc.le %d\n", v.b.le);           \
  DBG_PRINT("dbc.ge %d\n", v.b.ge);           \
  DBG_PRINT("dbc.gd %d\n", v.b.gd);           \
  DBG_PRINT("dbc.rw0 %d\n", v.b.rw0);         \
  DBG_PRINT("dbc.len0 %d\n", v.b.len0);       \
  DBG_PRINT("dbc.rw1 %d\n", v.b.rw1);         \
  DBG_PRINT("dbc.len1 %d\n", v.b.len1);       \
  DBG_PRINT("dbc.rw2 %d\n", v.b.rw2);         \
  DBG_PRINT("dbc.len2 %d\n", v.b.len2);       \
  DBG_PRINT("dbc.rw3 %d\n", v.b.rw3);         \
  DBG_PRINT("dbc.len3 %d\n", v.b.len3)

/*
  When the processor detects an enabled debug exception
  it sets bits b0 thru b3 before entering debug exception
  handler
*/
union u_drs {
  /* DR6 status register
      b<n> : 1 bit
        Process sets this bit when associated breakpoint condition is
        met & debug excption was generated

      bd  : 1 bit
        Processor sets this bit when debug exception was triggered by
        single-step execution mode (enabled with trap flag bit in EFLAGS)

      bs  : 1 bit
        Processor set this bit when debug exception resulted from task swtich

      bt  : 1 bit
        Processor set this bit when debug exception occured inside RTM region
        RTM - Restricted Transactional Memory
  */
  struct {
    unsigned b0 : 1;
    unsigned b1 : 1;
    unsigned b2 : 1;
    unsigned b3 : 1;
    unsigned pad : 9;
    unsigned bd : 1;
    unsigned bs : 1;
    unsigned bt : 1;
  } b;
  unsigned long v;
};

#define DBP_DEBUG_STATUS(v)              \
  DBG_PRINT("drs.b0 %d\n", v.b.b0);      \
  DBG_PRINT("drs.b1 %d\n", v.b.b1);      \
  DBG_PRINT("drs.b2 %d\n", v.b.b2);      \
  DBG_PRINT("drs.b3 %d\n", v.b.b3);      \
  DBG_PRINT("drs.bd %d\n", v.b.bd);      \
  DBG_PRINT("drs.bs %d\n", v.b.bs);      \
  DBG_PRINT("drs.bt %d\n", v.b.bt)



#define DEBUG_ADDR_0 0
#define DEBUG_ADDR_1 1
#define DEBUG_ADDR_2 2
#define DEBUG_ADDR_3 3
#define DEBUG_STATUS 6
#define DEBUG_CONTROL 7

#define DEBUG_EXECUTE 0
#define DEBUG_WRITE 1
#define DEBUG_ACCESS 3

extern bool x86_read_debug_reg(pid_t pid, size_t reg, void *val);
extern bool x86_write_debug_reg(pid_t pid, size_t reg, void *val);

int ptrace_arch_swbreak_insn(void *bdata) {
  int ret = RET_ERR;
  /* Illegal instruction is 0xcc or 'int3' */
  memset(bdata, 0xcc, 1);
  ret = RET_OK;

  return ret;
}

size_t ptrace_arch_swbreak_size() { return 1; }

bool ptrace_arch_support_watchpoint(pid_t tid, int type) {
  bool ret = false;
  if ((GDB_INTERFACE_BP_WRITE_WATCH == type) ||
      (GDB_INTERFACE_BP_ACCESS_WATCH == type)) {
    ret = true;
  }
  return ret;
}

bool _supported_access(unsigned long addr, size_t len) {
  bool ret = false;
  if (1 == len) {
    ret = true;
  } else if (2 == len) {
    /* At least 2 byte aligned */
    if (0 == (addr & 0x1))
      ret = true;
  } else if (4 == len) {
    /* At least 4 byte aligned */
    if (0 == (addr & 0x3))
      ret = true;
  } else if ((8 == sizeof(void *)) && (8 == len)) {
    /* At least 8 byte aligned */
    if (0 == (addr & 0x7))
      ret = true;
  }
  return ret;
}

static bool _add_hw_debug(pid_t pid, int type, unsigned long addr,
                          size_t _len) {
  bool ret = false;
  DBG_PRINT("pid:%d addr:%lx\n", pid, addr);
  if (_supported_access(addr, _len)) {
    union u_drc drc;
    unsigned char len = _len - 1;
    unsigned char rw = DEBUG_EXECUTE;

    if (type == GDB_INTERFACE_BP_WRITE_WATCH)
      rw = DEBUG_WRITE;
    else if (type == GDB_INTERFACE_BP_ACCESS_WATCH)
      rw = DEBUG_ACCESS;

    if (x86_read_debug_reg(pid, DEBUG_CONTROL, &drc)) {
      if ((0 == drc.b.l0) && (0 == drc.b.g0)) {
        drc.b.l0 = 1;
        drc.b.g0 = 1;
        drc.b.rw0 = rw;
        drc.b.len0 = len;
        drc.b.le = 1;
        drc.b.ge = 1;
        if (x86_write_debug_reg(pid, DEBUG_ADDR_0, &addr)) {
          ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
        }
      } else if ((0 == drc.b.l1) && (0 == drc.b.g1)) {
        drc.b.l1 = 1;
        drc.b.rw1 = rw;
        drc.b.len1 = len;
        if (x86_write_debug_reg(pid, DEBUG_ADDR_1, &addr)) {
          ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
        }
      } else if ((0 == drc.b.l2) && (0 == drc.b.g2)) {
        drc.b.l2 = 1;
        drc.b.rw2 = rw;
        drc.b.len2 = len;
        if (x86_write_debug_reg(pid, DEBUG_ADDR_2, &addr)) {
          ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
        }
      } else if ((0 == drc.b.l3) && (0 == drc.b.g3)) {
        drc.b.l3 = 1;
        drc.b.rw3 = rw;
        drc.b.len3 = len;
        if (x86_write_debug_reg(pid, DEBUG_ADDR_3, &addr)) {
          ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
        }
      }
    }
    DBP_DEBUG_CONTROL(drc);
  }
  return ret;
}

bool ptrace_arch_add_watchpoint(pid_t tid, int type, unsigned long addr,
                                size_t len) {
  bool ret = false;
  if (ptrace_arch_support_watchpoint(tid, type))
    ret = _add_hw_debug(tid, type, addr, len);
  return ret;
}

bool ptrace_arch_add_hardware_breakpoint(pid_t pid, unsigned long addr,
                                         size_t len) {
  bool ret = false;
  ret = _add_hw_debug(pid, GDB_INTERFACE_BP_HARDWARE, addr, len);
  return ret;
}

bool static _remove_hw_debug(pid_t pid, unsigned long addr, size_t _len,
                             bool hwbrk) {
  bool ret = false;
  if (_supported_access(addr, _len)) {
    union u_drc drc;
    if (x86_read_debug_reg(pid, DEBUG_CONTROL, &drc)) {
      unsigned long r_addr = 0;
      bool ok = true;

      if (x86_read_debug_reg(pid, DEBUG_ADDR_0, &r_addr)) {
        if (r_addr == addr) {
          ok = true;
          if (hwbrk) {
            if (drc.b.rw0 != DEBUG_EXECUTE) {
              ok = false;
            }
          } else {
            if (drc.b.rw0 == DEBUG_EXECUTE) {
              ok = false;
            }
          }
          if (ok) {
            r_addr = 0;
            x86_write_debug_reg(pid, DEBUG_ADDR_0, &r_addr);
            drc.b.l0 = 0;
            ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
            goto end;
          }
        }
      }

      if (x86_read_debug_reg(pid, DEBUG_ADDR_1, &r_addr)) {
        if (r_addr == addr) {

          ok = true;
          if (hwbrk) {
            if (drc.b.rw1 != DEBUG_EXECUTE) {
              ok = false;
            }
          } else {
            if (drc.b.rw1 == DEBUG_EXECUTE) {
              ok = false;
            }
          }
          if (ok) {
            r_addr = 0;
            x86_write_debug_reg(pid, DEBUG_ADDR_1, &r_addr);
            drc.b.l1 = 0;
            ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
            goto end;
          }
        }
      }

      if (x86_read_debug_reg(pid, DEBUG_ADDR_2, &r_addr)) {
        if (r_addr == addr) {
          ok = true;
          if (hwbrk) {
            if (drc.b.rw2 != DEBUG_EXECUTE) {
              ok = false;
            }
          } else {
            if (drc.b.rw2 == DEBUG_EXECUTE) {
              ok = false;
            }
          }
          if (ok) {
            r_addr = 0;
            x86_write_debug_reg(pid, DEBUG_ADDR_2, &r_addr);
            drc.b.l2 = 0;
            ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
            goto end;
          }
        }
      }

      if (x86_read_debug_reg(pid, DEBUG_ADDR_3, &r_addr)) {
        if (r_addr == addr) {
          ok = true;
          if (hwbrk) {
            if (drc.b.rw3 != DEBUG_EXECUTE) {
              ok = false;
            }
          } else {
            if (drc.b.rw3 == DEBUG_EXECUTE) {
              ok = false;
            }
          }
          if (ok) {
            r_addr = 0;
            x86_write_debug_reg(pid, DEBUG_ADDR_3, &r_addr);
            drc.b.l3 = 0;
            ret = x86_write_debug_reg(pid, DEBUG_CONTROL, &drc);
            goto end;
          }
        }
      }
      DBP_DEBUG_CONTROL(drc);
    }
  }
end:
  return ret;
}

bool ptrace_arch_remove_watchpoint(pid_t tid, int type, unsigned long addr,
                                   size_t _len) {
  bool ret = false;
  if (ptrace_arch_support_watchpoint(tid, type))
    ret = _remove_hw_debug(tid, addr, _len, false);
  return ret;
}

bool ptrace_arch_remove_hardware_breakpoint(pid_t pid, unsigned long addr,
                                            size_t _len) {
  bool ret = false;
  ret = _remove_hw_debug(pid, addr, _len, true);
  return ret;
}

static int _hit_hw_debug(pid_t pid, unsigned long *addr, bool hwbrk) {
  int ret = -1;
  union u_drc drc;
  unsigned long r_addr = 0;
  if (x86_read_debug_reg(pid, DEBUG_CONTROL, &drc)) {

    if (x86_verbose)
      DBG_PRINT("drc %x\n", drc.v);
    union u_drs drs;
    if (x86_read_debug_reg(pid, DEBUG_STATUS, &drs)) {
      if (x86_verbose) {
        DBG_PRINT("drs %x\n", drs.v);
        DBP_DEBUG_STATUS(drs);
      }

      if (drs.b.b0 && ((1 == drc.b.l0) || (1 == drc.b.g0))) {
        ret = x86_read_debug_reg(pid, DEBUG_ADDR_0, &r_addr);
        if (hwbrk) {
          if (r_addr == *addr) {
            ret = drc.b.rw0;
            goto end;
          }
        } else {
          *addr = r_addr;
          ret = drc.b.rw0;
          goto end;
        }

      } else if (drs.b.b1 && ((1 == drc.b.l1) || (1 == drc.b.g1))) {
        ret = x86_read_debug_reg(pid, DEBUG_ADDR_1, &r_addr);
        if (hwbrk) {
          if (r_addr == *addr) {
            ret = drc.b.rw1;
            goto end;
          }
        } else {
          *addr = r_addr;
          ret = drc.b.rw1;
          goto end;
        }
      } else if (drs.b.b2 && ((1 == drc.b.l2) || (1 == drc.b.g2))) {
        ret = x86_read_debug_reg(pid, DEBUG_ADDR_2, &r_addr);
        if (hwbrk) {
          if (r_addr == *addr) {
            ret = drc.b.rw2;
            goto end;
          }
        } else {
          *addr = r_addr;
          ret = drc.b.rw2;
          goto end;
        }
      } else if (drs.b.b3 && ((1 == drc.b.l3) || (1 == drc.b.g3))) {
        ret = x86_read_debug_reg(pid, DEBUG_ADDR_3, &r_addr);
        if (hwbrk) {
          if (r_addr == *addr) {
            ret = drc.b.rw3;
            goto end;
          }
        } else {
          *addr = r_addr;
          ret = drc.b.rw3;
          goto end;
        }
      }
    }
  }
end:
  return ret;
}

bool ptrace_arch_hit_watchpoint(pid_t pid, unsigned long *addr) {
  bool ret = false;
  int status = _hit_hw_debug(pid, addr, false);
  if ((status == DEBUG_WRITE) || (status == DEBUG_ACCESS))
    ret = true;
  return ret;
}

bool ptrace_arch_hit_hardware_breakpoint(pid_t pid, unsigned long addr) {
  bool ret = false;
  int status = _hit_hw_debug(pid, &addr, true);
  if (status == DEBUG_EXECUTE)
    ret = true;
  return ret;
}

bool ptrace_arch_support_hardware_breakpoints(pid_t tid) { return true; }

const char *ptrace_arch_get_xml_register_string() {
  static char *str = "i386";
  return str;
}

size_t ptrace_arch_swbrk_rollback() { return ptrace_arch_swbreak_size(); }
