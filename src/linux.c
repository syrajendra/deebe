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
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include "global.h"
#include "dptrace.h"
#include "breakpoint.h"
#include "memory.h"
#include "../os/linux.h"

int get_process_state(pid_t tid)
{
  int ret = PRS_ERR;
  int index;
  char proc_file[64];
  FILE *fd;
  int id;
  char comm[PATH_MAX];
  char state;
  int ppid;
  for (index = 0; index < _target.number_processes; index++) {
    if (PROCESS_TID(index) == tid) {
      sprintf(proc_file, "/proc/%d/stat", PROCESS_TID(index));
      fd = fopen(proc_file, "r");
      if (fd) {
        fscanf(fd, "%d %s %c %d", &id, comm, &state, &ppid);
        DBG_PRINT("ProcStat tid:%d state:%c\n", PROCESS_TID(index), state);
        switch(state) {
          case 'R' :
          {
            ret = PRS_RUN;
            break;
          }
          case 'S' :
          {
            ret = PRS_RUN;
            break;
          }
          case 'T' :
          case 't' :
          {
            ret = PRS_STOP;
            break;
          }
          case 'Z' :
          case 'X' :
          case 'x' :
          {
            ret = PRS_EXIT;
            break;
          }
          default  :
          {
            DBG_PRINT("ERROR: Unsupported process state:%d tid:%d ret:PRS_NULL\n", state, tid);
            ret = PRS_NULL;
            break;
          }
        } /* switch */
        fclose(fd);
      } else {
        DBG_PRINT("ERROR: Failed to get process state of tid:%d ret:PRS_ERR\n", tid);
        return PRS_ERR;
      }
    } /* if block */
  } /* for loop */
  return ret;
}

void ptrace_os_read_fxreg(pid_t tid) {
#ifdef PT_GETFPXREGS
  if (NULL != _target.fxreg) {
    _read_reg(tid, PT_GETFPXREGS, PT_SETFPXREGS, &_target.fxreg,
              &_target.fxreg_rw, &_target.fxreg_size);
  }
#endif
}

void ptrace_os_write_fxreg(pid_t tid) {
#ifdef PT_GETFPXREGS
  if (NULL != _target.fxreg) {
    _write_reg(tid, PT_SETFPXREGS, _target.fxreg);
  }
#endif
}

void ptrace_os_option_set_syscall(pid_t pid) {
#ifdef PTRACE_O_TRACESYSGOOD
  errno = 0;
  if (0 == PTRACE(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)) {
    /* Success */
    ;
  } else {
    /* Failure */
    char str[128];
    memset(&str[0], 0, 128);
    DBG_PRINT("Error in %s\n", __func__);
    if (0 == strerror_r(errno, &str[0], 128))
      DBG_PRINT("Error %d %s\n", errno, str);
    else
      DBG_PRINT("Error %d\n", errno);
  }
#endif
}

bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig) {
  bool ret = false;
  if (*in_out_sig == (SIGTRAP | 0x80)) {
    *in_out_sig = SIGTRAP;
    ret = true;
  }
  return ret;
}

void ptrace_os_option_set_thread(pid_t pid) {
#ifdef PTRACE_O_TRACEEXEC
  if (0 != PTRACE(PTRACE_SETOPTIONS, pid, NULL,
                  PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE)) {
    DBG_PRINT("Error setting PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE\n");
  }
#endif
}

bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status) {
  bool ret = false;
  pid_t tid;
  int status = 0;

  tid = waitpid(-1, &status, __WALL | WNOHANG);
  DBG_PRINT("tid:%llx\n", tid);
  if (tid > 0) {
    if (!target_is_tid(tid)) {
      pid_t tid2;
      int thread_status;
      int errs_max = 5;
      int errs = 0;
      for (errs = 0; errs < errs_max; errs++) {
        /* Sleep for a 1 msec */
        util_usleep(1000);
        tid2 = waitpid(tid, &thread_status, WNOHANG | __WCLONE);
        if (tid2 == tid) {
          break;
        } else {
          int other_index;
          other_index = target_index(tid2);
          if (other_index >= 0) {
            PROCESS_WAIT_STATUS(other_index) = status;
            PROCESS_WAIT_FLAG(other_index) = true;

            DBG_PRINT("strange.. %d %x\n", other_index, status);

          } else {
            DBG_PRINT("try %d %x vs %x status %d\n", errs, tid2,
                      tid, thread_status);
          }
        }
      }

      if (errs < errs_max) {
        if (WIFSTOPPED(thread_status) && (WSTOPSIG(thread_status) == SIGSTOP)) {
          if (target_new_thread(CURRENT_PROCESS_PID, tid, 0,
                                /* thread_status,*/ true, SIGSTOP)) {
            if (out_pid)
              *out_pid = tid;
            ret = true;

            DBG_PRINT("good.. %x\n", tid);

          } else {
            DBG_PRINT("ERROR: allocating new thread\n");
          }
        } else {
          DBG_PRINT("ERROR: with expected thread wait status %x\n",
                    thread_status);
        }
      } else {
        DBG_PRINT("ERROR: waiting for child thread : Error is %s\n",
                  strerror(errno));
      }

    } else {
      int index = target_index(tid);
      PROCESS_WAIT_STATUS(index) = status;
      PROCESS_WAIT_FLAG(index) = true;
    }
  }

  return ret;
}

bool is_pid_alive(pid_t pid)
{
  if (kill(pid, 0) == -1) {
      DBG_PRINT("ERROR: pid:%d is dead %s\n", pid, strerror(errno));
      return false;
  }
  return true;
}

bool ptrace_os_new_thread(int status) {
  bool ret = false;
  int e = (status >> 16) & 0xff;
  if (e == PTRACE_EVENT_CLONE) {
    ret = true;
  }
  return ret;
}

bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid) {
  bool ret = false;

	int s = WSTOPSIG(status);
  DBG_PRINT("signal:%d wait_status:%x ptrace_event:%s\n", s, status, PTRACE_EVENT_STR(status));
	if (s == SIGTRAP) {
		if (ptrace_os_new_thread(status)) {
			unsigned long new_tid = 0;
			if (0 != PTRACE(PTRACE_GETEVENTMSG, PROCESS_TID(0), 0, &new_tid)) {
				DBG_PRINT("ERROR: Failed to get new thread id\n");
			} else {
				int thread_status = -1;
        int index = target_index(new_tid);
        if (index == -1) {
          DBG_PRINT("Waiting for new child tid :%d to report stop signal\n", new_tid);
				  while(1) {
				  	/* Sleep for a 1 msec */
				  	util_usleep(1000);
				  	pid = ptrace_os_waitpid(new_tid, &thread_status);
				  	if ((pid == new_tid) &&
                (WSTOPSIG(thread_status) == SIGSTOP)) {
              DBG_PRINT("tid:%d reported stop\n", pid);
				  		break;
				  	} else if (pid == 0) { /* pid not in a waitable state */
				  		//DBG_PRINT("No children in waitable state \n");
              continue;
				  	}
				  } /* while loop */

				  if (WIFSTOPPED(thread_status) &&
				      (WSTOPSIG(thread_status) == SIGSTOP)) {
				    if (target_new_thread(CURRENT_PROCESS_PID,
                                    new_tid,
                                    thread_status,
                                    /* thread_status,*/ true,
                                    SIGSTOP)) {
				  		if (out_pid)
				  			*out_pid = new_tid;
				  		ret = true;
				  		DBG_PRINT("New child tid:%d\n", new_tid);
				  	} else {
				  		DBG_PRINT("ERROR: allocating new thread\n");
				  	}
				  } else {
				  	DBG_PRINT("ERROR: wrong child thread wait status %x\n", thread_status);
				  }
        } /* if index */
		  } /* else */
	  } /* ptrace_os_new_thread */
  } /* if SIGTRAP */
  return ret;
}

int os_thread_kill(int tid, int sig) {
  int ret;
  ret = syscall(__NR_tkill, tid, sig);
  if (errno == ENOSYS) {
    DBG_PRINT("Failed to send signal:%d tid:%d\n", sig, tid);
  } else {
    DBG_PRINT("Successfully sent signal:%d tid:%d\n", sig, tid);
  }
  return ret;
}

void ptrace_siginfo(pid_t tid, siginfo_t *si) {
  /* DEBUGGING CODE
  * Check on why the wait happend
  */
  if (0 == PTRACE(PTRACE_GETSIGINFO, tid, NULL, si)) {
    DBG_PRINT("Got siginfo tid:%d signo:%d errno:%d code:%d \n",
              tid, si->si_signo, si->si_errno, si->si_code);
    if (si->si_code == 0) {
      DBG_PRINT("Signal: si_code is ZERO\n");
    } else if (si->si_code == SI_KERNEL) { // si_code = 128
      DBG_PRINT("Signal: sent by the kernel from somewhere\n");
    } else if (si->si_code == SI_TKILL) { // si_code = -6
      DBG_PRINT("Signal: sent by tkill system call\n");
    } else if (si->si_code == TRAP_BRKPT) {
       DBG_PRINT("Signal: sent by process breakpoint\n");
    } else if (si->si_code == SIGEV_THREAD) { // si_code = 2
      DBG_PRINT("Signal: deliver via thread creation\n");
    } else if (si->si_code == ((SIGTRAP | PTRACE_EVENT_CLONE << 8))) { // si_code = 773 = 0x305
      DBG_PRINT("Signal: trap deliverd for clone system call\n");
    } else {
      DBG_PRINT("ERROR: NOT HANDLED si_code:%d\n", si->si_code);
    }
  } else {
    DBG_PRINT("No siginfo\n");
  }
}


pid_t ptrace_os_waitpid(pid_t t, int *status)
{
  pid_t tid;
  int index;
  //DBG_PRINT("waitpid:%d\n", t);
  tid = waitpid(t, status, WNOHANG | __WALL);
  if ((tid > 0) && (*status != -1)) {
    DBG_PRINT("waitpid(%d) returned tid:%d waitstatus:0x%x\n", t, tid, *status);

    index = target_index(tid);
    if (index >= 0) {
      if (WIFEXITED(*status)) {
        DBG_PRINT("ERROR: tid:%d exited with status:%d\n",
                    tid, WEXITSTATUS(*status));
        PROCESS_STATE(index)      = PRS_EXIT;
        PROCESS_WAIT_FLAG(index)  = true;
      } else if (WIFSIGNALED(*status)) {
        int s = WTERMSIG(*status);
        if (s != SIGINT) {
          DBG_PRINT("ERROR: tid:%d killed by signal:%d\n",
                    tid, s);
          PROCESS_STATE(index)      = PRS_EXIT;
          PROCESS_WAIT_FLAG(index)  = true;
        } else {
          PROCESS_STATE(index)      = PRS_STOP;
          PROCESS_WAIT_FLAG(index)  = true;
        }
      }  else if (WIFSTOPPED(*status)) {
        int sig = WSTOPSIG(*status);
        DBG_PRINT("tid:%d stopped by signal:%d\n",
                    tid, sig);
        PROCESS_STATE(index)      = PRS_STOP;
        PROCESS_WAIT_FLAG(index)  = true;
        if (sig == SIGTRAP) {
          if ( ((*status)>>8) == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
            DBG_PRINT("Parent got SIGTRAP because of event clone\n");
            pid_t new_pid;
            ptrace_os_check_new_thread(0, *status, &new_pid);
          } else if ((*status>>8) == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8))) {
            DBG_PRINT("Parent got SIGTRAP because of event vfork done\n");
          } else {
            DBG_PRINT("Got SIGTRAP tid:%d\n", tid);
          }
        } else if(sig == SIGSTOP) {
          DBG_PRINT("Got SIGSTOP\n");
        }
      } else {
        DBG_PRINT("ERROR: Not handling this case\n");
        exit(1);
      }
      PROCESS_WAIT_STATUS(index)  = *status;
    } else {
      if (!target_new_thread(PROCESS_PID(0),
                              tid,
                              *status,
                              true,
                              SIGSTOP)) {
        DBG_PRINT("ERROR: allocation of new thread failed\n");
      }
    }
  } else {
    if(tid == -1) {
      DBG_PRINT("ERROR: parent_pid:%d Failed to run waitpid(%d) return:%d : %s\n",
                 PROCESS_PID(0), t, tid, strerror(errno));
      perror ("waitpid");
    }
  }
  /* got some signal or error */
#ifndef DEEBE_RELEASE
      if (tid > 0 && *status != -1 && *status != 0) {
        siginfo_t si = { 0 };
        ptrace_siginfo(tid, &si);
      }
#endif
  return tid;
}

void ptrace_os_wait(pid_t t, int step) {
  pid_t tid;
  int status;
  int index;
  //PRINT_ALL_PROCESS_INFO("entry");
  for (index = 0; index < _target.number_processes; index++) {
    status = PROCESS_WAIT_STATUS(index);
    tid    = PROCESS_TID(index);
    if (status != PROCESS_WAIT_STATUS_DEFAULT) {
      DBG_PRINT("Earlier wait got tid:%d wait_status:%x ptrace_event:%s\n", tid, status, PTRACE_EVENT_STR(status));
      return;
    }
  }

  /* Wait for some event from either parent or child */
  while (1) {
    status    = -1;
    tid = ptrace_os_waitpid(t, &status);
    if (tid == 0) { /* no children in a waitable state */
      //DBG_PRINT("No children in waitable state \n");
      util_usleep(1000);
      continue;
    } else {
      DBG_PRINT("tid:%d wait_status:%x ptrace_event:%s\n", tid, status, PTRACE_EVENT_STR(status));
      break;
    }
  }

  //PRINT_ALL_PROCESS_INFO("exit");
}

long ptrace_os_continue_and_wait(pid_t tid, int sig)
{
  long ret       = RET_ERR;
  int real_state = get_process_state(tid);
  if (real_state == PRS_STOP) {
    /* since child is in stopped state continue it */
    ret = PTRACE(PTRACE_CONT, tid, 1, sig);
    DBG_PRINT("Waiting for tid:%d to run/stop PTRACE_CONT ret:%d\n",
                tid, ret);
    util_usleep(1000);

    //while(1) {
      //if (get_process_state(tid) == PRS_RUN) break;
      //int status = -1;
      //int wait_tid = ptrace_os_waitpid(tid, &status);
      //if (wait_tid == 0) { /* no children in a waitable state */
      //  //DBG_PRINT("No children in waitable state \n");
      //  util_usleep(1000);
      //  continue;
      //} else {
      //  break;
      //}
    //}
  }
  return ret;
}

void ptrace_os_continue_others(pid_t ctid) {
  /* In AllStop mode, this is a noop */
  if (NS_ON == _target.nonstop) {
    int index;
    for (index = 0; index < _target.number_processes; index++) {
      pid_t tid = PROCESS_TID(index);
      bool wait = PROCESS_WAIT_FLAG(index);

      DBG_PRINT("tid:%d cont_tid:%d wait_flag:%d process_state:%s pending signal:%d\n",
      				tid, ctid, wait,
      				PROCESS_STATE_STR(index), PROCESS_SIG(index));
      if (!wait || (tid == ctid)) {
        continue;
      } else {
        if (PRS_CONT == PROCESS_STATE(index) || PRS_STOP == PROCESS_STATE(index)) {
          if (PROCESS_WAIT_STATUS(index) == PROCESS_WAIT_STATUS_DEFAULT) {
            PROCESS_STATE(index) = PRS_RUN;
            PROCESS_WAIT_FLAG(index) = false;
            int sig = PROCESS_SIG(index);
            ptrace_os_continue_and_wait(tid, sig);
          }
        }
      }
    } /* for loop */
  } /* if loop */
}

long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig) {
  long ret     = RET_ERR;
  long request = PTRACE_CONT;
  int index;
  if (step == 1) {
    ptrace_arch_set_singlestep(tid, &request);
  } else {
    ptrace_arch_clear_singlestep(tid);
  }

  index = target_index(tid);
  int real_state = get_process_state(PROCESS_TID(index));
  DBG_PRINT("pid:%d tid:%d wait_flag:%d process_state:%s sig:%d real_state:%s\n",
  				    pid, tid,
              PROCESS_WAIT_FLAG(index),
              PROCESS_STATE_STR(index),
              sig,
              STATE_STR(real_state));

  /* do not simply trigger PTRACE_CONT check for stopped state */
  if (real_state == PRS_STOP) {
    if (request == PTRACE_CONT)
      ret = ptrace_os_continue_and_wait(tid, sig);
    else if (request == PTRACE_SINGLESTEP)
      ret = PTRACE(PTRACE_SINGLESTEP, tid, 1, sig);
    else
      ret = PTRACE(request, tid, 1, sig);
    PROCESS_STATE(index) = PRS_RUN;
    if (!step) ptrace_os_continue_others(tid);
  } else {
    DBG_PRINT("ERROR: Failed to continue tid:%d because it is not in stopped state real_state:%s\n",
              tid,
              STATE_STR(real_state));
  }
  return ret;
}

int ptrace_os_gen_thread(pid_t pid, pid_t tid) {
  int ret = RET_ERR;
  int index;
  if ((pid < 0) || (tid < 0))
    goto end;

  index = target_index(tid);

  DBG_PRINT("pid:%x tid:%x index:%d\n", pid, tid, index);

  if (index < 0) {
    /* Not a valid thread */
  } else if (!target_is_alive_thread(tid)) {
    /* dead thread */
    DBG_PRINT("dead %d\n", index);
  } else if (_target.current_process == index) {
    /* The trival case */
    DBG_PRINT("trivial %d\n", index);
    ret = RET_OK;
  } else if (PROCESS_WAIT_FLAG(index)) {
    /* We got lucky, the process is already in a wait state */
    target_thread_make_current(tid);

    DBG_PRINT("already waiting %d\n", index);

    /*
     * Continuing the old current will happen automatically
     * when the normal continue/wait logic runs
     */
    ret = RET_OK;
  } else {
    if(get_process_state(tid) != PRS_STOP) {
      DBG_PRINT("hard case %d %d\n", tid, index);

      /*
       * The current thread is not the one that is being switched to.
       * So stop the needed thread, and continue the now old current thread
       */
      ptrace_stop(pid, tid);
      /*
       * ptrace_stop send a SIG_INT to the tid
       * To seperate this signal from a normal signal, flag it as 'internal'
       */
      PROCESS_STATE(index) = PRS_INTERNAL_SIG_PENDING;

      /*
       * Now wait..
       * Ripped off logic from normal wait.
       * TBD : Clean up.
       */
      {
        int wait_ret;
        char str[128];
        int tries = 0;
        int max_tries = 20;
        memset(str, '\0', 128);
        do {

          /*
           * Keep track of the number of tries
           * Don't get stuck in an infinite loop here.
           */
          tries++;
          if (tries > max_tries) {
            DBG_PRINT("Exceeded maximume retries to switch threads\n");
            /* Some thread is waiting.. so goto end and return an error */
            goto end;
          }

          /* Sleep for a a msec */
          util_usleep(1000);

          wait_ret = ptrace_wait(str, 0, true);
          if (wait_ret == RET_OK) {
            DBG_PRINT("hard case str:[%s]\n", str);

            /*
             * When an RET_OK was hit, we have something to report
             * However the thread handling the event may not be
             * the thread we want.
             *
             * However since everyone is waiting then
             * it is ok to switch the current thread
             */
            target_thread_make_current(tid);
          } else if (wait_ret == RET_IGNORE) {
            int g = ptrace_arch_signal_to_gdb(SIGINT);
            ptrace_resume_from_current(CURRENT_PROCESS_PID, CURRENT_PROCESS_TID,
                                       0, g);
          }

        } while ((wait_ret == RET_IGNORE) || (wait_ret == RET_CONTINUE_WAIT));

        /*
         * ptrace_wait could have thrown an error
         * use ptrace_wait's return as this functions return
         */
        ret = wait_ret;
      }
    } else {
      target_thread_make_current(tid);
      DBG_PRINT("already waiting %d but wait flag is not correct\n", index);
      PROCESS_WAIT_FLAG(index) = true;
    }
  }
end:
  return ret;
}

void ptrace_os_stopped_single(char *str, bool debug) {
  if (CURRENT_PROCESS_WAIT_FLAG) {

    pid_t tid = CURRENT_PROCESS_TID;
    int wait_status = CURRENT_PROCESS_WAIT_STATUS;

    if (WIFSTOPPED(wait_status)) {
      unsigned long pc = 0;
      int s = WSTOPSIG(wait_status);
      int g = ptrace_arch_signal_to_gdb(s);
      ptrace_arch_get_pc(tid, &pc);

      if (debug) {
        DBG_PRINT("stopped at pc 0x%lx\n", pc);
        if (pc) {
          uint8_t b[32] = {0};
          size_t read_size = 0;
          memory_read_gdb(tid, pc, &b[0], 32, &read_size);
          util_print_buffer(fp_log, 0, 32, &b[0]);
        }
      }
      PRINT_CURRENT_PROCESS_INFO("single stop reported");
      DBG_PRINT("s:%d SIGTRAP:%d\n", s, SIGTRAP);
      if (s == SIGTRAP) {
        unsigned long watch_addr = 0;
        /* Fill out the status string */
        if (ptrace_arch_hit_hardware_breakpoint(tid, pc)) {
          gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_BREAKPOINT);
          target_thread_make_current(tid);
          CURRENT_PROCESS_STOP = LLDB_STOP_REASON_BREAKPOINT;
        } else if (ptrace_arch_hit_watchpoint(tid, &watch_addr)) {
          /* A watchpoint was hit */
          gdb_stop_string(str, g, tid, watch_addr, LLDB_STOP_REASON_WATCHPOINT);
          target_thread_make_current(tid);
          CURRENT_PROCESS_STOP = LLDB_STOP_REASON_WATCHPOINT;
        } else {
          if (!ptrace_os_new_thread(wait_status)) {
            int reason;
            if (_target.step) {
              /* stepping can run over a normal breakpoint so precidence is for
               * stepping */
              reason = LLDB_STOP_REASON_TRACE;
            } else {
              /*
               * XXX A real trap and a breakpoint could be at the same location
               *
               * lldb checks if the pc matches what was used to set the
               *breakpoint.
               * At this point the pc can advanced (at least on x86).
               * If the pc and the breakpoint don't match, lldb puts itself in a
               *bad
               * state.  So check if we are on lldb and roll back the pc one sw
               *break's
               * worth.
               *
               * On freebsd arm, the pc isn't advanced so use the arch dependent
               *function
               * ptrace_arch_swbreak_rollback
               */
              if (_target.lldb)
                ptrace_arch_set_pc(tid, pc - ptrace_arch_swbrk_rollback());

              reason = LLDB_STOP_REASON_BREAKPOINT;
            }
            gdb_stop_string(str, g, tid, 0, reason);
            DBG_PRINT("Process %x state : %d str:[%s] LLDB_STOP_REASON_BREAKPOINT\n",
            			tid, CURRENT_PROCESS_STATE, str);
            target_thread_make_current(tid);
            CURRENT_PROCESS_STOP = reason;
            int index = target_index(tid);
            PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
          } /* if ptrace_os_new_thread */
          else
          {
            DBG_PRINT("Parent process:%d got SIGTRAP because of clone ignore it\n", tid);
            target_thread_make_current(tid);
            int index = target_index(tid);
            PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
          }
        } /* else */
      } /* if SIGTRAP */
      else
      {
        if (PRS_START == CURRENT_PROCESS_STATE) {
              DBG_PRINT("Ignoring child clone stop signal pid:%x tid:%x gdb signal:%d\n",
              				CURRENT_PROCESS_PID, CURRENT_PROCESS_TID, g);
              CURRENT_PROCESS_STATE = PRS_STOP;
          } else {
            if (target_thread_make_current(tid)) {
              /* A non trap signal */
              gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_SIGNAL);
              DBG_PRINT("Process %x signal:%d state : %d str:[%s] LLDB_STOP_REASON_SIGNAL\n",
              				tid, s, CURRENT_PROCESS_STATE, str);
              CURRENT_PROCESS_STOP = LLDB_STOP_REASON_SIGNAL;
              int index = target_index(tid);
              PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
              PROCESS_SIG(index) = 0;
            }
          }
      } /* else of ptrace_os_new_thread() check */
    } /* Waiting */
  } /* CURRENT_PROCESS_WAIT_FLAG */
}

long ptrace_linux_getset(long request, pid_t pid, int addr, void *data) {
  long ret = -1;
  /* The old way.. */
  if (request < 0) {
    ret = PTRACE(request, pid, addr, data);
  } else {
    struct iovec vec;
    vec.iov_base = data;
    vec.iov_len = REG_MAX_SIZE;
    if (request == PTRACE_GETREGS) {
      ret = PTRACE(PTRACE_GETREGSET, pid, NT_PRSTATUS, &vec);
    } else if (request == PTRACE_GETFPREGS) {
      ret = PTRACE(PTRACE_GETREGSET, pid, NT_PRFPREG, &vec);
    } else if (request == PTRACE_SETREGS) {
      ret = PTRACE(PTRACE_SETREGSET, pid, NT_PRSTATUS, &vec);
    } else if (request == PTRACE_SETFPREGS) {
      ret = PTRACE(PTRACE_SETREGSET, pid, NT_PRFPREG, &vec);
    }
  }
  return ret;
}

/*
 * Tested on linux versions
 * 3.11.0
 *
 * For lldb, output is
 * start:<mem start>;size:<siz>;permissions:rx;
 *
 * Only trick bit is the permissions field, its a permutation of rwx
 * Assuming if there is no permissions, then shouldn't report the region.
 */
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff,
			       size_t out_buff_size) {
  bool ret = false;
  FILE *fp = NULL;
  pid_t pid = CURRENT_PROCESS_PID;
  char n[256];
  snprintf(n, 256, "/proc/%u/maps", pid);
  fp = fopen(n, "rt");
  if (fp) {
    char l[1024], perms[64];
    while (fgets(l, 1024, fp) != NULL) {
      memset(&perms[0], 0, 64);
      uint64_t rs, re;
      int status;
      if (sizeof(void *) == 8) {
        status =
            sscanf(l, "%016" PRIx64 "-%016" PRIx64 " %s ", &rs, &re, &perms[0]);
      } else {
        uint32_t s, e;
        status =
            sscanf(l, "%08" PRIx32 "-%08" PRIx32 " %s ", &s, &e, &perms[0]);
        rs = s;
        re = e;
      }
      /* 3 items found.. */
      if (status == 3) {
        if ((addr >= rs) && (addr < re)) {
          uint8_t p = 0;
          char perm_strs[8][4] = {"", "r", "w", "rw", "x", "rx", "wx", "rwx"};
          if (strchr(&perms[0], 'r'))
            p |= 1;
          if (strchr(&perms[0], 'w'))
            p |= 2;
          if (strchr(&perms[0], 'x'))
            p |= 4;
          if (p > 0 && p < 8) {
            snprintf(out_buff, out_buff_size,
                     "start:%" PRIx64 ";size:%" PRIx64 ";permissions:%s;", rs,
                     re - rs, &perm_strs[p][0]);
            ret = true;
          }
          break;
        }
      }
    }
    fclose(fp);
  }
  return ret;
}

bool ptrace_os_read_auxv(char *out_buf, size_t out_buf_size, size_t offset,
                         size_t *size) {
  bool ret = false;
  FILE *fp = NULL;
  pid_t pid = CURRENT_PROCESS_PID;
  char n[256];
  snprintf(n, 256, "/proc/%u/auxv", pid);
  fp = fopen(n, "rt");
  if (fp) {
    if (*size < out_buf_size) {
      if (0 == fseek(fp, offset, SEEK_SET)) {
        size_t total_read;
        total_read = fread(&out_buf[1], 1, *size - 1, fp);
        if (total_read != *size) {
          if (1 == feof(fp)) {
            out_buf[0] = 'l';
            *size = total_read + 1;
            ret = true;
          }
        } else {
          out_buf[0] = 'm';
          ret = true;
        }
      }
    }
    fclose(fp);
  }
  return ret;
}

void memory_os_request_size(size_t *size)
{
    *size = sizeof(ptrace_return_t);
}

bool memory_os_read(pid_t tid, void *addr, void *val) {
    bool ret = false;
    ptrace_return_t *pt_val = (ptrace_return_t *) val;
    errno = 0;
    *pt_val = PTRACE(PT_READ_D, tid, addr, 0);
    if (errno == 0)
	     ret = true;
    return ret;
}

bool memory_os_write(pid_t tid, void *addr, void *val) {
    bool ret = false;
    ptrace_return_t *pt_val = (ptrace_return_t *) val;
    if (0 == PTRACE(PT_WRITE_D, tid, addr, *pt_val))
	     ret = true;
    return ret;
}

int elf_os_image(pid_t pid) {
  int ret;
  char n[256];
  snprintf(n, 256, "/proc/%u/exe", pid);
  ret = open(n, O_RDONLY);
  return ret;
}

pid_t ptrace_os_get_wait_tid(pid_t pid) {
    pid_t ret = -1;
#ifdef PTRACE_GETEVENTMSG
    int status;
    unsigned long new_tid = 0;
    status = PTRACE(PTRACE_GETEVENTMSG, pid, 0, &new_tid);
    if (0 == status && new_tid != 0) {
	     ret = new_tid;
    }
#endif
    return ret;
}

int ptrace_os_get_tls_address(int64_t thread,  uint64_t lm, uint64_t offset,
			      uintptr_t *tlsaddr)
{
  return RET_NOSUPP;
}
