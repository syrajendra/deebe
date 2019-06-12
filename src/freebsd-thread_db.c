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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_THREAD_DB_H

#include <string.h>
#include "global.h"
#include "target.h"
#include "thread_db_priv.h"
#include <sys/ptrace.h>

#if  defined(__arm__) || defined(__i386__)
  #define LADDR unsigned int
#else
  #define LADDR unsigned long long
#endif


int read_thread_info;
LADDR  list_addr;
int off_tcb, off_tid, off_next, off_tlsindex, off_linkmap, off_dtv;


unsigned long read_segment_register()
{
  unsigned long addr = 0;
#if defined(__i386__)
  int ret = ptrace(PT_GETGSBASE, CURRENT_PROCESS_PID, (caddr_t)&addr, 0);
  if (-1 == ret) {
    printf("Error: Failed to ptrace PT_GETGSBASE\n");
  } else {
    DBG_PRINT("segment gs addr: 0x%lx\n", addr);
  }
#elif defined (__amd64__)
  int ret = ptrace(PT_GETFSBASE, CURRENT_PROCESS_PID, (caddr_t)&addr, 0);
  if (-1 == ret) {
    printf("Error: Failed to ptrace PT_GETFSBASE\n");
  } else {
    DBG_PRINT("segment fs addr: 0x%lx\n", addr);
  }
#else
  DBG_PRINT("Error: Platform not supported\n");
#endif
  return addr;
}

uintptr_t read_symbol(const char *sym)
{
  uintptr_t sym_addr = 0;

  if (symbol_lookup(sym, &sym_addr) == RET_ERR) {
    DBG_PRINT("Error: '%s' symbol not found\n", sym);
  } else {
    DBG_PRINT("Found: '%s' symbol addr %lx\n", sym, sym_addr);
  }
  return sym_addr;
}

static psaddr_t extract_value(uint8_t *buf, size_t size)
{
  psaddr_t val = 0;
  uint8_t *p;
  uint8_t *startaddr = buf;
  uint8_t *endaddr   = startaddr + size;
  p = endaddr - 1;
  for (; p>=startaddr; --p) {
    val = (val << 8) | *p;
  }
  return val;
}

int read_symbol_val(const char *sym)
{
  uintptr_t sym_addr = read_symbol(sym);
  uint8_t buf[64];
  size_t read_size = 0;
  if (_target.ph.target->read_mem(_target.ph.pid,
                                  (uint64_t) sym_addr,
                                  buf,
                                  sizeof(sym_addr),
                                  &read_size) == RET_ERR) {
    DBG_PRINT("Error: Failed to read sym_addr %lx\n", sym_addr);
    return RET_ERR;
  }
  int val = extract_value(buf, read_size);
  return val;
}

static void read_thread_vars()
{
  /* freebsd repo lib/libthread_db/libpthread_db.c */
  if (!read_thread_info) {
    list_addr = read_symbol("_thread_list");
    DBG_PRINT("list_addr: 0x%lx\n", (uintptr_t)list_addr);
    off_tcb   = read_symbol_val("_thread_off_tcb");
    DBG_PRINT("off_tcb: 0x%x\n", (unsigned int)off_tcb);
    off_tid   = read_symbol_val("_thread_off_tid");
    DBG_PRINT("off_tid: 0x%x\n", (unsigned int)off_tid);
    off_next  = read_symbol_val("_thread_off_next");
    DBG_PRINT("off_next: 0x%x\n", (unsigned int)off_next);
    off_tlsindex  = read_symbol_val("_thread_off_tlsindex");
    DBG_PRINT("off_tlsindex: 0x%x\n", (unsigned int)off_tlsindex);
    off_linkmap  = read_symbol_val("_thread_off_linkmap");
    DBG_PRINT("off_linkmap: 0x%x\n", (unsigned int)off_linkmap);
    off_dtv  = read_symbol_val("_thread_off_dtv");
    DBG_PRINT("off_dtv: 0x%x\n", (unsigned int)off_dtv);
    read_thread_info = 1;
  }
}

void thread_db_cleanup()
{
}

int initialize_thread_db(pid_t pid, struct gdb_target_s *t)
{
  int ret;
  ret = td_init ();
  if (ret != TD_OK)
    return RET_ERR;

  _target.ph.pid = pid;
  _target.ph.target = t;
  ret = td_ta_new (&_target.ph, &_target.thread_agent);
  switch (ret)
    {
    case TD_NOLIBTHREAD:
      /* Thread library not detected */
      _target.ph.pid = 0;
      _target.ph.target = NULL;
      return RET_ERR;

    case TD_OK:
      /* Thread library detected */
      read_thread_vars();
      return RET_OK;

    default:
      fprintf(stderr, "Error initializing thread_db library\n");
      _target.ph.pid = 0;
      _target.ph.target = NULL;
      return RET_ERR;
    }
  return RET_OK;
}

static int get_static_tls_address(uint64_t offset, uintptr_t *tlsaddr)
{
  uint8_t buf[64];
  size_t read_size;

  /* freebsd repo lib/libthread_db/libthr_db.c function pt_thr_tls_get_addr() */
  #define TARGET_READ_MEM(addr) \
      read_size = 0; \
      if (_target.ph.target->read_mem(_target.ph.pid, \
                                      (uint64_t) addr, \
                                      buf, \
                                      sizeof(addr), \
                                      &read_size) == RET_ERR) { \
        DBG_PRINT("Error: Failed to read addr 0x%x\n", (unsigned int)addr); \
        return RET_ERR; \
      }

  TARGET_READ_MEM(list_addr);
  LADDR thr_list = extract_value(buf, read_size);
  DBG_PRINT("thr_list: 0x%x\n", (unsigned int)thr_list);

  while (thr_list != 0) {
    LADDR raddr = thr_list + off_tid;
  	TARGET_READ_MEM(raddr);
	  int lwp = extract_value(buf, read_size);
  	DBG_PRINT("LWP : %d TID: %d\n", lwp, CURRENT_PROCESS_TID);
    if (lwp == CURRENT_PROCESS_TID)
      break;
    raddr = thr_list + off_next;
    TARGET_READ_MEM(raddr);
	  thr_list = extract_value(buf, read_size);
  }
  DBG_PRINT("Variable offset: 0x%lx\n", (unsigned long)offset);
  LADDR raddr = thr_list + off_tcb;
  TARGET_READ_MEM(raddr);
  LADDR tcb_addr = extract_value(buf, read_size);
  DBG_PRINT("tcb_addr: 0x%x\n", (unsigned int)tcb_addr);

#if  defined(__arm__)
  int tls_offset = 0x8;
  *tlsaddr = (psaddr_t) tcb_addr + offset + tls_offset;
#elif defined(__aarch64__)
  int tls_offset = 0x10;
  *tlsaddr = (psaddr_t) tcb_addr + offset + tls_offset;
#elif defined(__i386__) || defined(__amd64__)
  int    dtv_index  = 0x0;
  unsigned long seg_base = read_segment_register();
  DBG_PRINT("seg_base: 0x%x <equals> tcb_addr: 0x%x\n", seg_base, (unsigned int)tcb_addr);
  raddr = tcb_addr + off_dtv;
  TARGET_READ_MEM(raddr);
  LADDR dtv_addr = extract_value(buf, read_size);
  DBG_PRINT("dtv_addr: 0x%x\n", (unsigned int)dtv_addr);
#if defined(__amd64__)
  dtv_index = 0x10;
#elif defined(__i386__)
  dtv_index = 0x8;
#endif
  raddr = dtv_addr + dtv_index;
  TARGET_READ_MEM(raddr);
  LADDR tls_addr = extract_value(buf, read_size);
  DBG_PRINT("tls_addr: 0x%x\n", (unsigned int)tls_addr);
  *tlsaddr = (psaddr_t) tls_addr + offset;
#endif
  return RET_OK;
}

int thread_db_get_tls_address(int64_t thread, uint64_t lm, uint64_t offset,
			      uintptr_t *tlsaddr)
{
  td_err_e err;
  td_thrhandle_t th;
  psaddr_t addr = 0;

  if (_target.thread_agent == NULL)
    return RET_ERR;

  if (lm == 0x0) return get_static_tls_address(offset, tlsaddr);

  err = td_ta_map_id2thr(_target.thread_agent, thread, &th);
  if (err)
    return RET_ERR;

  err = td_thr_tls_get_addr(&th, lm, offset, &addr);
  if (err)
    return RET_ERR;
  *tlsaddr = (uintptr_t) addr;

  return RET_OK;
}

#endif /* HAVE_THREAD_DB_H */
