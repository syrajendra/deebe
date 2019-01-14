/*
 * Copyright (c) 2013-2015, Juniper Networks, Inc.
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
#ifndef DEEBE_TARGET_H
#define DEEBE_TARGET_H

#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef HAVE_THREAD_DB_H
#include "thread_db_priv.h"
#endif

enum process_state {
  PRS_NULL = 0,
  PRS_PRE_START, /* The parent has created, but it has not shown up */
  PRS_START,     /* Initial state, process is just starting */
  PRS_RUN,       /* process is running */
  PRS_EXIT,      /* process has exited */
  PRS_SIG,
  PRS_SIG_PENDING,
  PRS_INTERNAL_SIG_PENDING,
  PRS_ERR,
  PRS_CONT, /* process needs to continue */
  PRS_STOP,
  PRS_SYSCALL_ENTER,
  PRS_SYSCALL_EXIT,
};

enum nonstop_state {
   NS_OFF = 0,
   NS_ON = 1,
};

typedef struct target_process_rec {
  pid_t pid;
  pid_t tid;
  enum process_state ps;
  int ws;       /* wait status */
  bool w;       /* waiting ? */
  int sig;      /* signal */
  long syscall; /* the most recent syscall */
  int stop;     /* why did we stop */
} target_process;

#define MAX_TARGET_PROCESS 2048

typedef struct target_state_rec {
  bool lldb;
  bool list_threads_in_stop_reply;
  bool ack;
  enum nonstop_state nonstop;
  int multiprocess;
  bool xml_register_reporting;
  bool syscall_enter;
  bool step;
  int flag_attached_existing_process;
  size_t reg_size;
  size_t freg_size;
  size_t fxreg_size;
  size_t dbreg_size;
  uint8_t *reg_rw;
  uint8_t *freg_rw;
  uint8_t *fxreg_rw;
  uint8_t *dbreg_rw;
  void *reg;
  void *freg;
  void *fxreg;
  void *dbreg;
  size_t number_processes;
  size_t current_process;
  target_process process[MAX_TARGET_PROCESS];
  struct breakpoint *bpl;
#ifdef HAVE_THREAD_DB_H
  struct ps_prochandle ph;
  td_thragent_t *thread_agent;
#endif
} target_state;

#define PROCESS_PID(n) _target.process[n].pid
#define PROCESS_TID(n) _target.process[n].tid
#define PROCESS_STATE(n) _target.process[n].ps
#define PROCESS_WAIT_STATUS(n) _target.process[n].ws
#define PROCESS_WAIT_FLAG(n) _target.process[n].w
#define PROCESS_SIG(n) _target.process[n].sig
#define PROCESS_SYSCALL(n) _target.process[n].syscall
#define PROCESS_STOP(n) _target.process[n].stop

#define CURRENT_PROCESS_PID PROCESS_PID(_target.current_process)
#define CURRENT_PROCESS_TID PROCESS_TID(_target.current_process)
#define CURRENT_PROCESS_STATE PROCESS_STATE(_target.current_process)
#define CURRENT_PROCESS_WAIT_STATUS PROCESS_WAIT_STATUS(_target.current_process)
#define CURRENT_PROCESS_WAIT_FLAG PROCESS_WAIT_FLAG(_target.current_process)
#define CURRENT_PROCESS_SIG PROCESS_SIG(_target.current_process)
#define CURRENT_PROCESS_SYSCALL PROCESS_SYSCALL(_target.current_process)
#define CURRENT_PROCESS_STOP PROCESS_STOP(_target.current_process)

#define STATE_STR(_ps) \
  ({ \
    char *_ret= NULL; \
    switch(_ps) { \
      case 0 : _ret = "PRS_NULL"; break; \
      case 1 : _ret = "PRS_PRE_START"; break; \
      case 2 : _ret = "PRS_START"; break; \
      case 3 : _ret = "PRS_RUN"; break; \
      case 4 : _ret = "PRS_EXIT"; break; \
      case 5 : _ret = "PRS_SIG"; break; \
      case 6 : _ret = "PRS_SIG_PENDING"; break; \
      case 7 : _ret = "PRS_INTERNAL_SIG_PENDING"; break; \
      case 8 : _ret = "PRS_ERR"; break; \
      case 9 : _ret = "PRS_CONT"; break; \
      case 10 : _ret = "PRS_STOP"; break; \
      case 11 : _ret = "PRS_SYSCALL_ENTER"; break; \
      case 12 : _ret = "PRS_SYSCALL_EXIT"; break; \
    } \
    _ret ? _ret : NULL; \
  })


#define PROCESS_STATE_STR(n) \
  ({ \
    int _ps  = PROCESS_STATE(n); \
    STATE_STR(_ps); \
  })

#define CURRENT_PROCESS_STATE_STR PROCESS_STATE_STR(_target.current_process)

#define RETURN_CODE_STR(n) \
  ({ \
    char *_ret = NULL; \
    switch(n) { \
      case 0: _ret = "RET_OK"; break; \
      case 1: _ret = "RET_ERR"; break; \
      case 2: _ret = "RET_NOSUPP"; break; \
      case 3: _ret = "RET_IGNORE"; break; \
      case 4: _ret = "RET_CONTINUE_WAIT"; break; \
    } \
    _ret ? _ret : NULL; \
  })

#define PRINT_ALL_PROCESS_INFO(msg) \
  ({ \
      int _my_index; \
      char * __attribute__((__unused__)) _current_msg = NULL; \
      for (_my_index = 0; _my_index < _target.number_processes; _my_index++) { \
        if (CURRENT_PROCESS_TID == PROCESS_TID(_my_index)) { \
          _current_msg = "current process"; \
        } else { \
          _current_msg = ""; \
        } \
        DBG_PRINT("%s %s pid:%d tid:%d wait_status:0x%x wait_flag:%d process_state:%s sig:%d\n", \
          msg, _current_msg, \
          PROCESS_PID(_my_index), \
          PROCESS_TID(_my_index), \
          PROCESS_WAIT_STATUS(_my_index), \
          PROCESS_WAIT_FLAG(_my_index), \
          PROCESS_STATE_STR(_my_index), \
          PROCESS_SIG(_my_index)); \
      } \
  })

#define PRINT_CURRENT_PROCESS_INFO(msg) \
  ({ \
      DBG_PRINT("%s current process pid:%d tid:%d wait_status:0x%x wait_flag:%d process_state:%s sig:%d\n", \
        msg, CURRENT_PROCESS_PID, \
        CURRENT_PROCESS_TID, CURRENT_PROCESS_WAIT_STATUS, \
        CURRENT_PROCESS_WAIT_FLAG, \
        CURRENT_PROCESS_STATE_STR, CURRENT_PROCESS_SIG); \
  })

/* below event codes defined here /usr/include/sys/ptrace.h */
#define PTRACE_EVENT_STR(_wait_status) \
  ({ \
    char *_ret = NULL; \
    int _event = (_wait_status >> 16) & 0xff; \
    switch(_event) { \
      case 1 : _ret  = "PTRACE_EVENT_FORK"; break; \
      case 2 : _ret  = "PTRACE_EVENT_VFORK"; break; \
      case 3 : _ret  = "PTRACE_EVENT_CLONE"; break; \
      case 4 : _ret  = "PTRACE_EVENT_EXEC"; break; \
      case 5 : _ret  = "PTRACE_EVENT_VFORK_DONE"; break; \
      case 6 : _ret  = "PTRACE_EVENT_EXIT"; break; \
      default : _ret = "PTRACE_NO_EVENT"; break; \
    } \
    _ret ? _ret : NULL; \
  })

#define PROCESS_WAIT_STATUS_DEFAULT -1

extern target_state _target;

bool target_new_thread(pid_t pid, pid_t tid, int wait_status, bool waiting,
                       int sig);
int target_number_threads();
pid_t target_get_pid();
bool target_dead_thread(pid_t tid);
void target_all_dead_thread();
bool target_is_alive_thread(pid_t tid);
bool target_is_alive_process(pid_t pid);
void target_mark_dead_threads(lwpid_t *lwpid_list, int num_lwps);
int target_index(pid_t tid);
bool target_is_tid(pid_t tid);
bool target_is_pid(pid_t pid);
bool target_thread_make_current(pid_t tid);
int target_current_index();
void target_attached(bool flag);
bool target_is_attached();

void _target_debug_print();

#define msizeof(TYPE, MEMBER) sizeof(((TYPE *)0)->MEMBER)

struct reg_location_list {
  size_t off;
  size_t size;
  int gdb;
  char *name;
  size_t gdb_size;
  char *encoding;
  char *format;
  int gcc;
  int dwarf;
  char *generic;
  char *altname;
};

/* The register lookup lists */
/* General */
extern struct reg_location_list grll[];
/* Floating point */
extern struct reg_location_list frll[];
/* Extended */
extern struct reg_location_list fxrll[];

bool target_is_gdb_reg(int gdb, int *g_index, struct reg_location_list *rl);

#endif
