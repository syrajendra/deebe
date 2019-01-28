/*
 * Copyright (c) 2017, Juniper Networks, Inc.
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

#include "global.h"
#include "target.h"
#include "thread_db_priv.h"
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/elf.h>
#include <sys/stat.h>

#ifdef __x86_64__
#include <asm/ptrace-abi.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/reg.h>
#endif
/*
   libtrhread library helps to gather information about the threads
   in a running target process
*/
#ifdef __x86_64__
  char *lib_thread_db_paths[] = \
  { \
    "/usr/lib/libthread_db.so", \
    "/lib/x86_64-linux-gnu/libthread_db.so.1" \
  };
#else
  char *lib_thread_db_paths[] = \
  { \
    "/usr/lib/libthread_db.so", \
    "/lib/i386-linux-gnu/libthread_db.so.1" \
  };
#endif
static void *lib_handle;
static unsigned int lib_thread_db_count = sizeof(lib_thread_db_paths)/sizeof(lib_thread_db_paths[0]);

/* store symbol & its address in below LL */
typedef struct tdb_symbols {
  char               *name;
  uintptr_t          addr;
  struct tdb_symbols *next;
} tdb_symbols_t;
static tdb_symbols_t *t_symbols;

/* store thread id & its handle in below array */
typedef struct tid_to_thdinfo {
  lwpid_t        tid;
  td_thrhandle_t th;
} tid_to_thdinfo_t;
static tid_to_thdinfo_t tid_2_tinfo[MAX_TARGET_PROCESS];

/* variable stores number of threads attached to thread_db */
static unsigned int num_threads;

char *th_db_error_code_str(int td_err);

void *my_dlsym(void *handle, const char *sym_name)
{
  void *sym = dlsym(handle, sym_name);
  if (sym == NULL) {
    DBG_PRINT("ERROR: Failed to find symbol %s \n", sym_name);
  }
  return sym;
}

bool initialize_thread_db_funcs(void *handle)
{
  td_init_fptr   = my_dlsym(handle, "td_init");
  if (td_init_fptr) {
      td_ta_new_fptr = my_dlsym(handle, "td_ta_new");
      if (td_ta_new_fptr) {
        td_ta_map_lwp2thr_fptr = my_dlsym(handle, "td_ta_map_lwp2thr");
        if (td_ta_map_lwp2thr_fptr) {
          td_symbol_list_fptr = my_dlsym(handle, "td_symbol_list");
          if (td_symbol_list_fptr) {
            td_thr_tls_get_addr_fptr = my_dlsym(handle, "td_thr_tls_get_addr");
            if (td_thr_tls_get_addr_fptr) {
              td_thr_tlsbase_fptr = my_dlsym(handle, "td_thr_tlsbase");
              if (td_thr_tlsbase_fptr) {
                td_thr_get_info_fptr = my_dlsym(handle, "td_thr_get_info");
                if (td_thr_get_info_fptr) {
                  td_ta_delete_fptr = my_dlsym(handle, "td_ta_delete");
                  if (td_ta_delete_fptr) {
                    td_ta_thr_iter_fptr = my_dlsym(handle, "td_ta_thr_iter");
                    if (td_ta_thr_iter_fptr) {
                      DBG_PRINT("Success\n");
                      return true;
                    }
                  }
                }
              }
            }
          }
        }
      }
  }
  return false;
}

int search_symbol(const char *name, uintptr_t *addr)
{
  tdb_symbols_t *ptr = t_symbols;
  for (;ptr; ptr=ptr->next) {
    if (strcmp(ptr->name, name) == 0) {
      *addr = ptr->addr;
      return RET_OK;
    }
  }
  return RET_ERR;
}

void copy_symbol(const char *name, uintptr_t addr)
{
  uintptr_t tmp;
  if (search_symbol(name, &tmp) == RET_ERR) {
    tdb_symbols_t *ptr = t_symbols;
      if (!t_symbols) {
        t_symbols = ptr = (tdb_symbols_t *) malloc(sizeof(tdb_symbols_t));
        ptr->next = NULL;
        ptr->name = strdup(name);
        ptr->addr = addr;
      } else {
        /* move till end */
        for (; ptr->next; ptr=ptr->next);
        ptr->next = (tdb_symbols_t *) malloc(sizeof(tdb_symbols_t));
        ptr->next->next = NULL;
        ptr->next->name = strdup(name);
        ptr->next->addr = addr;
      }
    }
}

void find_threadb_symbols()
{
  const char **str = td_symbol_list_fptr();
  while (*str) {
    uintptr_t addr = 0;
    if (symbol_lookup(*str, &addr) == RET_ERR) {
      DBG_PRINT("ERROR: Symbol %s lookup failed\n", *str);
    } else {
      DBG_PRINT("Copying symbol %s addr : %x\n", *str, addr);
      copy_symbol(*str, addr);
    }
    str++;
  }
}

td_thrhandle_t *get_thread_info(lwpid_t tid)
{
  int index;
  for (index=0; index<num_threads; index++) {
    if (tid_2_tinfo[index].tid == tid) return &tid_2_tinfo[index].th;
  }
  return NULL;
}

bool thread_info_exists(lwpid_t tid)
{
  int index;
  for (index=0; index<num_threads; index++) {
    if (tid_2_tinfo[index].tid == tid) return true;
  }
  return false;
}


int verify_thread_state(lwpid_t tid)
{
  /* verifying thread state */
  td_thrinfo_t infop;
  td_err_e td_err;
  td_thrhandle_t *th_p = get_thread_info(tid);
  if (!th_p) {
    DBG_PRINT("ERROR: Failed to find thread info for tid %d\n", tid);
    return RET_ERR;
  }

  td_err = td_thr_get_info_fptr(th_p, &infop);
  if (td_err != TD_OK){
    DBG_PRINT("ERROR: Failed td_thr_get_info tid:%ld %s\n",
               tid,
               th_db_error_code_str(td_err));
    return RET_ERR;
  }

  if (infop.ti_lid == -1) {
    DBG_PRINT("Thread tid:%d exited\n", tid);
    return RET_ERR;
  }
  if (infop.ti_state == TD_THR_UNKNOWN || infop.ti_state == TD_THR_ZOMBIE) {
    DBG_PRINT("Thread tid:%d unknown or zombie\n", tid);
    return RET_ERR;
  }
  return RET_OK;
}

int read_thread_info(lwpid_t tid)
{
  td_err_e td_err;
  DBG_PRINT("tid:%d\n", tid);
  tid_2_tinfo[num_threads].tid = tid;
  td_err = td_ta_map_lwp2thr_fptr(_target.thread_agent, tid, &tid_2_tinfo[num_threads].th);
  if (td_err != TD_OK){
    DBG_PRINT("ERROR: Failed td_ta_map_lwp2thr tid:%ld : %s\n",
                tid,
                th_db_error_code_str(td_err));
    return RET_ERR;
  }
  num_threads++;
  if (verify_thread_state(tid) == RET_ERR) return RET_ERR;
  return RET_OK;
}

int find_thread_info()
{
  int index;
  if (_target.thread_agent == NULL)
    return RET_ERR;

  if (num_threads == _target.number_processes) return RET_OK;

  for (index=0; index < _target.number_processes; index++) {
    pid_t tid = PROCESS_TID(index);
    if (!thread_info_exists(tid)) {
      read_thread_info(tid);
    }
  }
  return RET_OK;
}

void cleanup_thread_db()
{
  DBG_PRINT("Called\n");
  td_ta_delete_fptr(_target.thread_agent);
  if (lib_handle) dlclose(lib_handle);
}

int initialize_thread_db(pid_t pid, struct gdb_target_s *t)
{
  int ret = RET_ERR, i;
  char *path = NULL;
  td_err_e td_err;

  _target.ph.pid = pid;
  _target.ph.target = t;

  DBG_PRINT("Number of libthread_db entries %d\n",
              lib_thread_db_count);
  for (i=0; i<lib_thread_db_count; i++) {
    if (access(lib_thread_db_paths[i], R_OK) != 0) {
      DBG_PRINT("ERROR: Failed to find library at %s location\n",
            lib_thread_db_paths[i]);
    } else {
      path = lib_thread_db_paths[i];
      DBG_PRINT("Success using host libthread_db library %s\n", path);
      printf("Using host libthread_db library %s\n", path);
      break;
    }
  }
  if (!path) return ret;

  /* open library */
  lib_handle = dlopen(path, RTLD_NOW);
  if (lib_handle == NULL) {
    DBG_PRINT("ERROR: Failed to open library %s\n", dlerror());
    return ret;
  }

  if(!initialize_thread_db_funcs(lib_handle)) return ret;

  /* init thread db library */
  td_err = td_init_fptr();
  if (td_err != TD_OK) {
    DBG_PRINT("ERROR: Failed to initialize thread db %s\n", th_db_error_code_str(td_err));
    switch(td_err) {
      case TD_NOLIBTHREAD:
        DBG_PRINT("Not linked with libthread\n");
      default:
        DBG_PRINT("Unknown error\n");
    }
    return ret;
  }

  /* create a new connection */
  td_err = td_ta_new_fptr(&_target.ph, &_target.thread_agent);
  if (td_err != TD_OK) {
    DBG_PRINT("ERROR: Failed to create new connection to thread db %s\n",
                th_db_error_code_str(td_err));
    return ret;
  }
  find_threadb_symbols();
  return RET_OK;
}

int thread_db_get_tls_address(int64_t thread, uint64_t lm, uint64_t offset,
            uintptr_t *tlsaddr)
{
  td_err_e td_err;
  td_thrhandle_t *th;
  psaddr_t addr = 0;

  /* search new threads first */
  find_thread_info();

  th = get_thread_info(thread);
  if (!th) {
    DBG_PRINT("Failed to get thread info of tid:%d\n", thread);
    return RET_ERR;
  }

  DBG_PRINT("lm:%ld offset:%ld\n", lm, offset);
  if (lm != 0) {
    td_err = td_thr_tls_get_addr_fptr(th, (psaddr_t)lm, (size_t)offset, &addr);
  } else {
    td_err = td_thr_tlsbase_fptr(th, 1, &addr);
    /* add offset for static executables */
    addr   = offset + (char *)addr;
  }

  if (td_err != TD_OK) {
    DBG_PRINT("ERROR: Failed td_thr_tls_get_addr/td_thr_tlsbase %s\n",
                th_db_error_code_str(td_err));
    return RET_ERR;
  }
  *tlsaddr = (uintptr_t) addr;
  DBG_PRINT("tlsaddr: 0x%x\n", addr);
  return RET_OK;
}

/*
On Ubuntu
1. Below are the function which are undefined in libthreaded.so library
$ ldd -r /usr/lib/x86_64-linux-gnu/libthread_db.so | grep undefined
undefined symbol: ps_pdwrite    (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_pglobal_lookup     (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_lsetregs   (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_getpid     (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_lgetfpregs (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_lsetfpregs (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_lgetregs   (/usr/lib/x86_64-linux-gnu/libthread_db.so)
undefined symbol: ps_pdread     (/usr/lib/x86_64-linux-gnu/libthread_db.so)

$ nm -D /usr/lib/x86_64-linux-gnu/libthread_db.so | grep ps_
                 w ps_get_thread_area
                 U ps_getpid
                 U ps_lgetfpregs
                 U ps_lgetregs
                 U ps_lsetfpregs
                 U ps_lsetregs
                 U ps_pdread
                 U ps_pdwrite
                 U ps_pglobal_lookup

The ps_get_thread_area is weak symbol hence not shown in ldd

2. See elibc version header proc_service.h for the above function prototypes
$ sudo aptitude show libc6
or
$ ldd --version
ldd (Ubuntu EGLIBC 2.15-0ubuntu10.18) 2.15
http://www.eglibc.org/cgi-bin/viewvc.cgi/branches/eglibc-2_15/libc/nptl_db/proc_service.h?view=markup

*/

ps_err_e ps_pdwrite (struct ps_prochandle *ph,
              psaddr_t addr,
              const void *buf,
              size_t buf_size)
{
  DBG_PRINT("Called\n");
  if (ph->target->write_mem(ph->pid, (uint64_t) addr,
                (uint8_t*) buf, buf_size) == RET_ERR) {
      return PS_ERR;
    }
  return PS_OK;
}

ps_err_e ps_pdread (struct ps_prochandle *ph,
            psaddr_t addr,
            void *buf,
            size_t buf_size)
{
  size_t read_size;
  if (ph->target->read_mem(ph->pid, (uint64_t) addr,
                (uint8_t*) buf, buf_size, &read_size) == RET_ERR) {
    DBG_PRINT("addr: 0x%llx failed\n", addr);
    return PS_ERR;
  }
  if (buf_size != read_size) {
    DBG_PRINT("addr: 0x%llx failed buf_size && read_size does not match\n", addr);
    return PS_ERR;
  }
  DBG_PRINT("addr: 0x%llx success\n", addr);
  return PS_OK;
}

ps_err_e ps_pglobal_lookup (struct ps_prochandle *ph,
                const char *object_name,
                const char *sym_name,
                psaddr_t *sym_addr)
{
  uintptr_t laddr, gaddr;
  if (search_symbol(sym_name, &laddr) == RET_ERR) {
    if (symbol_lookup(sym_name, &gaddr) == RET_ERR) {
      DBG_PRINT("ERROR: Symbol %s lookup failed\n", sym_name);
      return PS_NOSYM;
    } else {
      *sym_addr = (psaddr_t) gaddr;
    }
  } else {
    *sym_addr = (psaddr_t) laddr;
  }
  DBG_PRINT("Symbol:%s addr:%lx\n", sym_name, *((unsigned long*)sym_addr));
  return PS_OK;
}

ps_err_e ps_lsetregs (struct ps_prochandle *ph,
              lwpid_t lwpid, const prgregset_t gregset)
{
  DBG_PRINT("Called\n");
  return PS_ERR;
}

ps_err_e ps_lgetregs (struct ps_prochandle *ph,
              lwpid_t lwpid, prgregset_t gregset)
{
  DBG_PRINT("Called\n");
  return PS_ERR;
}

pid_t ps_getpid (struct ps_prochandle *ph)
{
  DBG_PRINT("Called\n");
  return CURRENT_PROCESS_PID;
}

ps_err_e ps_lgetfpregs (struct ps_prochandle *ph,
                lwpid_t lwpid, prfpregset_t *fregset)
{
  DBG_PRINT("Called\n");
  return PS_ERR;
}

ps_err_e ps_lsetfpregs (struct ps_prochandle *ph,
                lwpid_t lwpid, const prfpregset_t *fregset)
{
  DBG_PRINT("Called\n");
  return PS_ERR;
}

/* Error codes of thread_db library */
char *th_db_error_code_str(int td_err)
{
  switch (td_err) {
    case TD_OK:         return "No error";
    case TD_ERR:        return "No further specified error";
    case TD_NOTHR:      return "No matching thread found";
    case TD_NOSV:       return "No matching synchronization handle found";
    case TD_NOLWP:      return "No matching light-weighted process found";
    case TD_BADPH:      return "Invalid process handle";
    case TD_BADTH:      return "Invalid thread handle";
    case TD_BADSH:      return "Invalid synchronization handle";
    case TD_BADTA:      return "Invalid thread agent";
    case TD_BADKEY:     return "Invalid key";
    case TD_NOMSG:      return "No event available";
    case TD_NOFPREGS:   return "No floating-point register content available";
    case TD_NOLIBTHREAD:return "Application not linked with thread library";
    case TD_NOEVENT:    return "Requested event is not supported";
    case TD_NOCAPAB:    return "Capability not available";
    case TD_DBERR:      return "Internal debug library error";
    case TD_NOAPLIC:    return "Operation is not applicable";
    case TD_NOTSD:      return "No thread-specific data available";
    case TD_MALLOC:     return "Out of memory";
    case TD_PARTIALREG: return "Not entire register set was read or written";
    case TD_NOXREGS:    return "X register set not available for given thread";
    //case TD_TLSDEFER:   return "Thread has not yet allocated TLS for given module";
    case TD_NOTALLOC:   return "Thread has not yet allocated TLS for given module";
    case TD_VERSION:    return "Version if libpthread and libthread_db do not match";
    case TD_NOTLS:      return "There is no TLS segment in the given module";
    default :           return "Unhandle error code";
  }
}

/* The most important function which reads thread local area
   libthread_db calls this function when deebe calls lwp2thr function
   td_ta_map_lwp2thr -> __td_ta_lookup_th_unique()
   asm/ptrace-abi.h -> PTRACE_ARCH_PRCTL = 30
*/
ps_err_e
ps_get_thread_area (struct ps_prochandle *ph,
                      lwpid_t lwpid, int reg, void **base)
{
  DBG_PRINT("Called reg : %d\n", reg);
  #ifdef __x86_64__
    if (reg == FS) {
        if (0 == ptrace (PTRACE_ARCH_PRCTL, lwpid, base, ARCH_GET_FS))
          return PS_OK;
    } else if (reg == GS) {
        if (0 == ptrace (PTRACE_ARCH_PRCTL, lwpid, base, ARCH_GET_GS))
          return PS_OK;
    } else {
        return PS_BADADDR;
    }
  #else
    {
      unsigned int data[4];

      if (ptrace (PTRACE_GET_THREAD_AREA, lwpid,
            (void *) (intptr_t) reg,
            (unsigned long) &data) < 0)
        return PS_ERR;

      *base = (void *) (uintptr_t) data[1];
      return PS_OK;
    }
  #endif
  return PS_ERR;
}

#endif /* HAVE_THREAD_DB_H */
