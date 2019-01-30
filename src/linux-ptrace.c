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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* osx */
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include "breakpoint.h"
#include "delf.h"
#include "dptrace.h"
#include "dsignal.h"
#include "gdb_interface.h"
#include "global.h"
#include "macros.h"
#include "memory.h"
#include "network.h"
#include "os.h"
#include "packet.h"
#include "target.h"
#include "util.h"

static bool _read_reg_verbose = false;
static bool _resume_current_verbose = false;
static bool _resume_from_addr_verbose = false;
#ifdef PT_SYSCALL
static bool _resume_syscall_verbose = false;
#endif
static bool _write_reg_verbose = false;
static bool _wait_verbose = false;
static bool _add_break_verbose = false;
static bool _remove_break_verbose = false;
static bool _read_single_reg_verbose = false;
static bool _write_single_reg_verbose = false;
static bool _stop_verbose = false;
static bool _restart_verbose = false;
static bool _detach_verbose = false;

static void _deliver_sig(int sig, int change_state);
static int is_all_stopped();

void _print_rll(struct reg_location_list *rl) {
  if (_read_reg_verbose || _write_reg_verbose) {
    int c = 0;
    while (1) {
      if (GUARD_RLL(rl[c])) {
        break;
      } else {
        DBG_PRINT("RLL %d : %s offset %zu size %zu gdb_size %zu gdb %d\n", c,
                  rl[c].name, rl[c].off, rl[c].size, rl[c].gdb_size, rl[c].gdb);
        c++;
      }
    }
  }
}

void _print_greg() {
  struct reg_location_list *rl = &grll[0];

  int c = 0;
  size_t max_name = 0;

  c = 0;
  while (1) {
    if (GUARD_RLL(rl[c])) {
      break;
    } else {
      if (strlen(rl[c].name) > max_name)
        max_name = strlen(rl[c].name);
    }
    c++;
  }
  max_name++;
  c = 0;
  while (1) {
    if (GUARD_RLL(rl[c])) {
      break;
    } else {
      size_t s;
      union {
        uint16_t r16;
        uint32_t r32;
        uint64_t r64;
      } r;
      r.r64 = 0;
      memcpy(&r, _target.reg + grll[c].off, grll[c].size);
      DBG_PRINT("%s", rl[c].name);
      s = max_name - strlen(rl[c].name);
      while (s--) {
        DBG_PRINT(" ");
      }
      DBG_PRINT(": off 0x%zx %zd : size %zd : ", grll[c].off, grll[c].off,
                grll[c].size);
      if (grll[c].size == 2) {
        DBG_PRINT("0x%x\n", r.r16);
      } else if (grll[c].size == 4) {
        DBG_PRINT("0x%x\n", r.r32);
      } else {
        DBG_PRINT("0x%016" PRIx64 "\n", r.r64);
      }
      c++;
    }
  }
}

static size_t _copy_greg_to_gdb(void *gdb, void *avail) {
  size_t ret = 0;
  int r, rmax;
  size_t diff;
  rmax = ptrace_arch_gdb_greg_max();
  for (r = 0; r < rmax; r++) {
    int i;
    if (target_is_gdb_reg(r, &i, grll)) {
      memcpy(gdb, _target.reg + grll[i].off, grll[i].size);
#ifndef DEEBE_RELEASE
      int j;
      if (_read_reg_verbose) {
        printf("Reg:%d Name:%s Size:%zd ", i, grll[i].name, grll[i].size);
        for (j=grll[i].size-1; j>=0; j--)
          printf("%02X ", ((char*)(_target.reg + grll[i].off))[j] & 0xFF);
        printf("\n");
      }
#endif
      memset(avail, 0xff, grll[i].size);
      gdb += grll[i].size;
      avail += grll[i].size;
      ret += grll[i].size;
      if (grll[i].gdb_size > grll[i].size) {
        diff = grll[i].gdb_size - grll[i].size;
        memset(gdb, 0, diff);
        memset(avail, 0, diff);
        gdb += diff;
        avail += diff;
        ret += diff;
      }
      else {
        diff = grll[i].size - grll[i].gdb_size;
        ret -= diff;
      }
    } else if (target_is_gdb_reg(r, &i, frll)) {
      memcpy(gdb, _target.freg + frll[i].off, frll[i].size);
      memset(avail, 0xff, frll[i].size);
      gdb += frll[i].size;
      avail += frll[i].size;
      ret += frll[i].size;
      if (frll[i].gdb_size > frll[i].size) {
        diff = frll[i].gdb_size - frll[i].size;
        memset(gdb, 0, diff);
        memset(avail, 0, diff);
        gdb += diff;
        avail += diff;
        ret += diff;
      }  else {
        diff = frll[i].size - frll[i].gdb_size;
        ret -= diff;
      }
    } else if (target_is_gdb_reg(r, &i, fxrll)) {
      if ((fxrll[i].off + fxrll[i].size) <= _target.fxreg_size) {
        memcpy(gdb, _target.fxreg + fxrll[i].off, fxrll[i].size);
        memset(avail, 0xff, frll[i].size);
        gdb += fxrll[i].size;
        avail += fxrll[i].size;
        ret += fxrll[i].size;
        if (fxrll[i].gdb_size > fxrll[i].size) {
          diff = fxrll[i].gdb_size - fxrll[i].size;
          memset(gdb, 0, diff);
          memset(avail, 0, diff);
          gdb += diff;
          avail += diff;
          ret += diff;
        }  else {
          diff = fxrll[i].size - fxrll[i].gdb_size;
          ret -= diff;
        }
      } else {
        DBG_PRINT("INTERNAL ERROR : rll entry %d exceeds reg buffer (%zu + "
                  "%zu) vs %zu\n",
                  i, fxrll[i].off, fxrll[i].size, _target.fxreg_size);
        /* try to cope */
        memset(gdb, 0, fxrll[i].gdb_size);
        memset(avail, 0, fxrll[i].gdb_size);
        gdb += fxrll[i].gdb_size;
        avail += fxrll[i].gdb_size;
        ret += fxrll[i].gdb_size;
      }
    } else {
      size_t pad_size = 0;
      if (ptrace_arch_check_unrecognized_register(r, &pad_size)) {
        /* If the register is known not to be supported, handle */
        if (pad_size > 0) {
          memset(gdb, 0, pad_size);
          memset(avail, 0, pad_size);
          gdb += pad_size;
          avail += pad_size;
          ret += pad_size;
        } else {
          DBG_PRINT("INTERNAL ERROR : expecting pad size to be non zero\n");
        }
      } else {
        DBG_PRINT("INTERNAL ERROR : unrecognized reg %d\n", r);
      }
    }
  }
  return ret;
}

#ifdef PT_GETREGS
bool _read_reg(pid_t tid, int GET, int SET, void **reg, uint8_t **reg_rw,
               size_t *reg_size) {
  bool ret = false;
  size_t buf_size = REG_MAX_SIZE;
  uint8_t *a = NULL;
  a = (uint8_t *)malloc(buf_size);

  if (a) {
    uint8_t *b = NULL;
    b = (uint8_t *)malloc(buf_size);
    if (b) {
      int ptrace_status;
      /*
       * ptrace get's do not return how much was written
       * so the have a general read function, we need to figure
       * that out for ourselves.
       *
       * Fill the 'a' buffer with 0xff
       * fill the 'b' buffer with 0xee
       * Do 2 reads
       * Reading from the end of the buffer,
       * figure out the size of the returned buffer.
       */
      memset(a, 0xff, buf_size);
      memset(b, 0xee, buf_size);
      errno = 0;
      ptrace_status = PTRACE_GETSET(GET, tid, 0, a);
      int perrno = errno;
      if (0 != ptrace_status) {
        /* Failure */
        if (_read_reg_verbose) {
          char str[128];
          memset(&str[0], 0, 128);
          DBG_PRINT("Error reading registers tid %d status is %d\n", tid,
                    ptrace_status);
          if (0 == strerror_r(perrno, &str[0], 128)) {
            DBG_PRINT("Error %d %s\n", perrno, str);
          }
        }
      } else {
        ptrace_status = PTRACE_GETSET(GET, tid, 0, b);
        if (0 == ptrace_status) {
          size_t i = 0;
          for (i = buf_size; i > 0; i--) {
            if ((a[i - 1] != 0xff) || (b[i - 1] != 0xee))
              break;
          }
          if (i) {
            /* check if end of buffer was used */
            if (i > buf_size / 2) {
              if (_read_reg_verbose) {
                DBG_PRINT("Warning register read buffer may not be big enough "
                          "used %zu of %zu\n",
                          i, buf_size);
              }
            }
            if (*reg_size) {
              if (*reg_size != i) {
                if (_read_reg_verbose) {
                  DBG_PRINT("%s Warning register read size does not agree with "
                            "last read %zu vs %zu\n",
                            __func__, *reg_size, i);
                }
                *reg_size = i;
                if (*reg) {
                  if (*reg)
                    free(*reg);
                  *reg = malloc(*reg_size);
                  if (*reg == NULL) {
                    DBG_PRINT(
                        "%s Internal Error register buffer allocation failed\n",
                        __func__);
                    *reg_size = 0;
                  }
                  if (*reg_rw) {
                    free(*reg_rw);
                    *reg_rw = NULL;
                  }
                }
              }

            } else {
              /* First */
              *reg_size = i;
              *reg = malloc(*reg_size);
              if (*reg == NULL) {
                DBG_PRINT(
                    "%s Internal Error register buffer allocation failed\n",
                    __func__);
                *reg_size = 0;
              }
            }

            if (0 != (*reg_size) && (NULL != *reg)) {
              memcpy(*reg, b, *reg_size);
              /* Success or no point in handling the error */
              ret = true;

              /*
               * Find out which registers are read/write vs just read only
               * Do this by toggling each byte in just read registers and
               * noting where failures happen.  This depends on a well
               * behaved kernel reporting the error and that the registers
               * are accessed on byte boundaryies.
               *
               * Assume the read/write nature does not change and only
               * recalculate the read/write information when the size of
               * the register read changes (should also not happen) or
               * to initialize.
               */
              if (*reg_rw == NULL) {
                *reg_rw = (uint8_t *)malloc(*reg_size * sizeof(uint8_t));
                if (*reg_rw) {
                  size_t j;
                  /* Assume read write */
                  memset(*reg_rw, 0xff, *reg_size);
                  for (j = 0; j < *reg_size; j++) {
                    if (0 == PTRACE_GETSET(SET, tid, 0, a)) {
                      /* Toggle current byte */
                      a[j] ^= 0xff;
                      if (0 != PTRACE_GETSET(SET, tid, 0, a)) {
                        /* Set byte to read only */
                        (*reg_rw)[j] = 0;
                        if (_read_reg_verbose) {
                          DBG_PRINT("Register location %zu is read only\n", j);
                        }
                      }
                      /* Restore current byte */
                      a[j] ^= 0xff;
                    }
                  }
                  /*
                   * Trailing restore
                   * No point handling the error case
                   */
                  if (0 != PTRACE_GETSET(SET, tid, 0, a)) {
                    if (_read_reg_verbose) {
                      DBG_PRINT("Error restoring registers\n");
                    }
                  }
                }
              }
            } else {
              /* Failure */
              ;
            }
          } else {
            if (_read_reg_verbose) {
              DBG_PRINT("Error no data returned in %s\n", __func__);
            }
          }
        } else {
          /* Failure */
          if (_read_reg_verbose) {
            DBG_PRINT("Error reading registers in %s\n", __func__);
          }
        }
      }
      free(b);
      b = NULL;
    } else {
      /* Failure */
      ;
    }
    free(a);
    a = NULL;
  } else {
    /* Failure */
    ;
  }
  return ret;
}
#endif

#ifdef PT_SETREGS
void _write_reg(pid_t tid, long SET, void *reg) {
  if (0 != PTRACE_GETSET(SET, tid, 0, reg)) {
    if (_write_reg_verbose) {
      DBG_PRINT("Error : Write register %d : %s\n", SET, strerror(errno));
    }
  }
}
#endif

bool _read_greg(pid_t tid) {
  bool ret = false;
#ifdef PT_GETREGS
  ret = _read_reg(tid, PT_GETREGS, PT_SETREGS, &_target.reg, &_target.reg_rw,
                  &_target.reg_size);
#else
  _target.reg = NULL;
  _target.reg_rw = NULL;
  _target.reg_size = 0;
#endif
  return ret;
}

bool _read_freg(pid_t tid) {
  bool ret = false;
#ifdef PT_GETFPREGS
  ret = _read_reg(tid, PT_GETFPREGS, PT_SETFPREGS, &_target.freg,
                  &_target.freg_rw, &_target.freg_size);
#else
  _target.freg = NULL;
  _target.freg_rw = NULL;
  _target.freg_size = 0;
#endif
  return ret;
}

bool _read_dbreg(pid_t tid) {
  bool ret = false;
#ifdef PT_GETDBREGS
  ret = _read_reg(tid, PT_GETDBREGS, PT_SETDBREGS, &_target.dbreg,
                  &_target.dbreg_rw, &_target.dbreg_size);
#else
  ptrace_arch_read_dbreg(tid);
  if (_target.dbreg_size > 0)
    ret = true;
#endif
  return ret;
}

void _write_greg(pid_t tid) {
#ifdef PT_SETREGS
  _write_reg(tid, PT_SETREGS, _target.reg);
#endif
}

void _write_freg(pid_t tid) {
#ifdef PT_SETFPREGS
  _write_reg(tid, PT_SETFPREGS, _target.freg);
#endif
}

void _write_dbreg(pid_t tid) {
#ifdef PT_GETDBREGS
  _write_reg(tid, PT_SETDBREGS, _target.dbreg);
#else
  ptrace_arch_write_dbreg(tid);
#endif
}

void ptrace_help(/*@unused@*/ char *prog_name) {}

static int _yamma_check() {
  int ret = 0;
  int fd = -1;
  fd = open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY);
  if (fd >= 0) {
    ssize_t got = -1;
    char buf[0x10];
    memset(&buf[0], 0, sizeof(buf));
    got = read(fd, buf, sizeof(buf) - 1);
    if (got > 0)
      ret = atoi(&buf[0]);
    if (0 != close(fd)) {
      DBG_PRINT("Error closing file descriptor for yamma check\n");
    }
  }
  return ret;
}

int ptrace_attach(pid_t process_id) {
  int ret = RET_ERR;
  int status;
  pid_t wait_child;
  if (0 != PTRACE(PT_ATTACH, process_id, 0, 0)) {
    /* Failure */
    DBG_PRINT("Error attaching to pid %d\n", process_id);
    /* Check for security */
    if (_yamma_check()) {
      DBG_PRINT("Failure caused by YAMA security setting of %d\n", ret);
      DBG_PRINT("Recommend as root : \n");
      DBG_PRINT("# echo \"0\" > /proc/sys/kernel/yama/ptrace_scope\n");
    }
  } else {
    /* Success */
    wait_child = waitpid(process_id, &status, 0);
    if (wait_child == process_id) {
      /* Check for error / early exit */
      if (WIFEXITED(status)) {
        int __attribute__((unused)) exit_status;
        exit_status = WEXITSTATUS(status);

        DBG_PRINT("Debuggee %d exited with %d\n", process_id, exit_status);
      } else {
        /* Check that process stopped because of implied SIGSTOP */
        if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
	    pid_t tid = ptrace_os_get_wait_tid(process_id);
	    if (tid < 0) {
	        tid = process_id;
	    }
          if (target_new_thread(process_id, tid, status, true,
                                SIGSTOP)) {
            ptrace_arch_option_set_thread(process_id);
            ret = RET_OK;
            ptrace_os_attach_threads(process_id);
            target_attached(true);
          } else {
            DBG_PRINT("%s error allocating for new thread\n");
          }

        } else {
          /* Unexpected */
          DBG_PRINT("ptrace unexpected wait status\n");
        }
      }
    } else {
      /* Unexpected */
      DBG_PRINT("ptrace unexpected wait return\n");
    }
  }
  return ret;
}

static int _ptrace_detach(int gdb_sig) {
  int ret = RET_ERR;
  pid_t tid;
  int sig, index;
  sig = ptrace_arch_signal_from_gdb(gdb_sig);
  if (sig < 0)
    sig = 0;
  ptrace_os_continue(CURRENT_PROCESS_PID,
                      CURRENT_PROCESS_TID,
                      0, 0);
  for (index=0; index<_target.number_processes; index++) {
    tid = PROCESS_TID(index);
    DBG_PRINT("Waiting for tid:%d before detaching\n", tid);
    if (0 != PTRACE(PT_DETACH, tid, 0, sig)) { /* XXX convert to pid */
      /* Failure */
      if (_detach_verbose) {
        DBG_PRINT("Error detaching from tid %d\n", tid);
      }
    } else {
      if (_detach_verbose) {
        DBG_PRINT("OK detaching from tid %d\n", tid);
      }
      ret = RET_OK;
      target_attached(false);
    }
  } /* for loop */
  return ret;
}

int ptrace_detach() {
  DBG_PRINT("called\n");
  int ret = _ptrace_detach(0);
  return ret;
}

void ptrace_detach_wait() {
  int status, ret;
  pid_t pid = CURRENT_PROCESS_PID;

  do {
    ret = waitpid (pid, &status, 0);
    if (WIFEXITED (status) || WIFSIGNALED (status))
      break;
  } while (ret != -1 || errno != ECHILD);
}

void ptrace_close(void) {
  DBG_PRINT("called\n");
}

int ptrace_connect(char *status_string, size_t status_string_len,
                   int *can_restart) {
  return RET_NOSUPP;
}

int ptrace_disconnect(void) { return RET_NOSUPP; }

int ptrace_restart(void) {
  int ret = RET_ERR;
  if (cmdline_argc) {
    /* fork -n- exec */
    pid_t try_child;
    /* The pipes that will be used to redirect the debugee's stdout and stderr
     */
#if 0
    /*
     * Disable it for now as it does not appear to work. Running a simple
     * program which does a printf() in a loop does not produce any output
     * on either side, deebe or gdb.
     */
    if (0 == pipe(gPipeStdout)) {
      /* Non blocking please.. */
      fcntl(gPipeStdout[0], F_SETFL, O_NONBLOCK);
      fcntl(gPipeStdout[1], F_SETFL, O_NONBLOCK);
    }
#endif
    try_child = fork();
    if (try_child == 0) {
      /* The child */
      if (0 != PTRACE(PT_TRACE_ME, 0,
                      /*@null@*/ 0, /*@null@*/ 0)) {
        _exit(PTRACE_ERROR_TRACEME);
      } else {
        /* Child closes input side of pipe */
        if (gPipeStdout[0] > 0) {
          close(gPipeStdout[0]);
          /* Replace with pipe output, dup2 takes care of the closing */
          if (-1 == dup2(gPipeStdout[1], STDOUT_FILENO)) {
            DBG_PRINT("ERROR Dup2 failed.. \n");
          }
          if (-1 == dup2(gPipeStdout[1], STDERR_FILENO)) {
            DBG_PRINT("ERROR Dup2 failed.. \n");
          }
        }
        /* Implied SIGTRAP when ptraced execv is successful */
        if (execv(cmdline_argv[0], cmdline_argv)) {
          _exit(PTRACE_ERROR_EXECV);
        }
        /* Not expecting to reach here.. */
        _exit(PTRACE_ERROR_INTERNAL);
      }
    } else {
      if (try_child > 0) {
        /* The parent with a child */
        int status;
        pid_t wait_child;
        /* Parent closes the output side of pipe */
        if (gPipeStdout[1] > 0)
          close(gPipeStdout[1]);
        wait_child = waitpid(try_child, &status, 0);
        if (wait_child == try_child) {
          /* Check for error / early exit */
          if (WIFEXITED(status)) {
            int __attribute__((unused)) exit_status;
            exit_status = WEXITSTATUS(status);
            DBG_PRINT("Debuggee %s exited with %d\n", cmdline_argv[0],
                      exit_status);
          } else {
            /*
             * Check that process stopped because of implied
             * SIGTRAP from execv
             */
            if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGTRAP)) {
	      pid_t tid = ptrace_os_get_wait_tid(try_child);
	      if (tid < 0) {
	        tid = try_child;
	      }
              if (target_new_thread(
                      try_child, tid, status, true, SIGTRAP)) {
                ptrace_arch_option_set_thread(try_child);
                fprintf(stdout, "Process %s created; pid = %d\n",
                        cmdline_argv[0], CURRENT_PROCESS_PID);
                fflush(stdout);
		/* DEBUGGING CODE START */
		/* elf_dump_symbol_table(try_child); */
		/* DEBUGGING CODE END */
                ret = RET_OK;
              }
            } else {
              /* Unexpected */
              if (_restart_verbose) {
                DBG_PRINT("ptrace unexpected wait status\n");
              }
            }
          }
        } else {
          /* Unexpected */
          if (_restart_verbose) {
            DBG_PRINT("ptrace unexpected wait return\n");
          }
        }
      } else {
        /* The parent without a child */
        /* Unexpected */
        if (_restart_verbose) {
          DBG_PRINT("ptrace fork failed\n");
        }
      }
    }
  }
  return ret;
}

int ptrace_open(/*@unused@*/ int argc, /*@unused@*/ char *argv[],
                /*@unused@*/ char *prog_name) {
  int ret = RET_ERR;
  ret = ptrace_restart();
  return ret;
}

void ptrace_stop(pid_t pid, pid_t tid) {
  if (kill(pid, SIGINT)) { /* XXX pid or tid ? */
    /* Failure */
    if (_stop_verbose) {
      DBG_PRINT("ERROR sending SIGINT to %x\n", tid);
    }
  } else {
    int index = target_index(tid);
    if (index >= 0) {
      PROCESS_SIG(index) = SIGINT;
    } else {
      DBG_PRINT("Error with target index\n");
    }
    /* Success */
    if (_stop_verbose) {
      DBG_PRINT("OK sending SIGINT to %x\n", tid);
    }
  }
}

int ptrace_read_registers(pid_t tid, uint8_t *data, uint8_t *avail,
                          size_t buf_size, size_t *read_size) {
  int ret = RET_ERR;
  uint8_t *g = data;
  uint8_t *ga = avail;
  size_t s = 0;
  //printf("Read register tid:%d\n", tid);
  if (_read_greg(tid)) {
    if (_read_freg(tid)) {
      ptrace_arch_read_fxreg(tid);
    } else {
      if (_read_reg_verbose) {
        DBG_PRINT("Error reading floating point registers\n");
      }
    }
    /* Pass is just the general registers are read */
    s = _copy_greg_to_gdb(g, ga);
    if (s > 0)
      ret = RET_OK;
  } else {
    if (_read_reg_verbose) {
      DBG_PRINT("Error reading general registers\n");
    }
  }
  *read_size = s;
  return ret;
}

int ptrace_read_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
                                uint8_t *avail, size_t buf_size,
                                size_t *read_size) {
  int ret = RET_ERR;
  if (_read_single_reg_verbose) {
    DBG_PRINT("%s %d\n", __func__, gdb);
  }
  int c = 0;
  if (target_is_gdb_reg(gdb, &c, &grll[0])) {
    _read_greg(tid);
    if (grll[c].off < _target.reg_size) {
      size_t s = 0;
#ifdef DEEBE_BIG_ENDIAN
      if (grll[c].gdb_size > grll[c].size) {
        size_t diff = grll[c].gdb_size - grll[c].size;
        memset(data, 0, diff);
        memset(avail, 0xff, diff);
        s = diff;
      }
#endif
      /* Success */
      memcpy(data + s, _target.reg + grll[c].off, grll[c].size);
      memset(avail + s, 0xff, grll[c].size);
      *read_size = s + grll[c].size;
      ret = RET_OK;
    } else {
      /* Failure */
      if (_read_single_reg_verbose) {
        DBG_PRINT("INTERNAL ERROR Problem in g read of reg %d\n", gdb);
      }
    }
  } else if (target_is_gdb_reg(gdb, &c, &frll[0])) {
    _read_freg(tid);
    if (frll[c].off < _target.freg_size) {
      if (frll[c].size > 0) {
        size_t pad = 0;
        /* Success */
        memcpy(data, _target.freg + frll[c].off, frll[c].size);
        memset(avail, 0xff, frll[c].size);
        /* for parts of x86_64 */
        if (frll[c].size < frll[c].gdb_size) {
          pad = frll[c].gdb_size - frll[c].size;
          memset(data + frll[c].size, 0, pad);
          memset(avail + frll[c].size, 0xff, pad);
        }
        *read_size = frll[c].size + pad;
        ret = RET_OK;
      } else {
        /* Internal error, something is wrong with fp rll */
        DBG_PRINT(
            "INTERNAL ERROR floating point register size is 0 for reg %d %d\n",
            gdb, c);
      }
    } else {
      /* Failure */
      DBG_PRINT(
          "Problem in fp read of reg %d offset %zu size %zu freg size %zu\n",
          gdb, frll[c].off, frll[c].size, _target.freg_size);
    }
  } else if (target_is_gdb_reg(gdb, &c, &fxrll[0])) {
    ptrace_arch_read_fxreg(tid);
    if (fxrll[c].off < _target.fxreg_size) {
      /* Success */
      memcpy(data, _target.fxreg + fxrll[c].off, fxrll[c].size);
      memset(avail, 0xff, fxrll[c].size);
      *read_size = fxrll[c].size;
      ret = RET_OK;
    } else {
      /* Failure */
      DBG_PRINT("Problem in fx read of reg %d\n", gdb);
      memset(data, 0, fxrll[c].size);
      memset(avail, 0, fxrll[c].size);
      *read_size = fxrll[c].size;
      ret = RET_OK;
    }
  } else {
    size_t pad_size = 0;
    if (ptrace_arch_check_unrecognized_register(gdb, &pad_size)) {
      /* If the register is known not to be supported, handle */
      if (pad_size > 0) {
        memset(data, 0, pad_size);
        memset(avail, 0, pad_size);
        ret = RET_OK;
      } else {
        /* no support or returning 0 pad and an ok does not work, so return
         * default error */
        DBG_PRINT("Unhandled read of reg %d\n", gdb);
      }
      *read_size = pad_size;
    } else {
      /* Freak out */
      DBG_PRINT("Unhandled read of reg %d\n", gdb);
    }
  }
  return ret;
}

static bool _gdb_register_size(unsigned int gdb, size_t *gdb_size,
                               size_t *size) {
  bool ret = false;
  *gdb_size = *size = 0;
  int c = 0;
  if (target_is_gdb_reg(gdb, &c, &grll[0])) {
    *size = grll[c].size;
    *gdb_size = grll[c].gdb_size;
    ret = true;
  } else if (target_is_gdb_reg(gdb, &c, &frll[0])) {
    *size = frll[c].size;
    *gdb_size = frll[c].gdb_size;
    ret = true;
  } else if (target_is_gdb_reg(gdb, &c, &fxrll[0])) {
    *size = fxrll[c].size;
    *gdb_size = fxrll[c].gdb_size;
    ret = true;
  }
  return ret;
}

int ptrace_write_single_register(pid_t tid, unsigned int gdb, uint8_t *data,
                                 size_t size) {
  int ret = RET_ERR;
  if (_write_single_reg_verbose) {
    DBG_PRINT("%s %d %p %zu\n", __func__, gdb, data, size);
    util_print_buffer(fp_log, 0, size, data);
  }
  int c = 0;
  if (target_is_gdb_reg(gdb, &c, &grll[0])) {
    _read_greg(tid);
    if (grll[c].off < _target.reg_size) {
      /* Success */
      size_t s = 0;
#ifdef DEEBE_BIG_ENDIAN
      /* For mips32 in 64 bit compatiblity mode */
      if (size > grll[c].size) {
        size_t diff = size - grll[c].size;
        s = diff;
      }
#endif
      memcpy(_target.reg + grll[c].off, data + s, grll[c].size);
      _write_greg(tid);
      ret = RET_OK;
    } else {
      /* Failure */
      DBG_PRINT("Problem in g read of reg %d\n", gdb);
    }
  } else if (target_is_gdb_reg(gdb, &c, &frll[0])) {
    _read_freg(tid);
    if (frll[c].off < _target.freg_size) {
      /* Success */
      memcpy(_target.freg + frll[c].off, data, frll[c].size);
      _write_freg(tid);
      ret = RET_OK;
    } else {
      /* Failure */
      DBG_PRINT("Problem in fp read of reg %d\n", gdb);
    }
  } else if (target_is_gdb_reg(gdb, &c, &fxrll[0])) {
    ptrace_arch_read_fxreg(tid);
    /*
     * It is possible for the fx reg read to fail
     * because the registers are not supported or
     * available on the machine.  When this happens
     * nothing is read and the fxreg_size is 0
     *
     * Treat this as an unrecognized register
     */
    if (0 == _target.fxreg_size) {
      /* Failure */
      DBG_PRINT("Warning : coping with fx read failure\n");
      ret = RET_NOSUPP;
    } else {
      /* Read at least partially succeeded */
      if (fxrll[c].off < _target.fxreg_size) {
        /* Success */
        memcpy(_target.fxreg + fxrll[c].off, data, fxrll[c].size);
        ptrace_arch_write_fxreg(tid);
        ret = RET_OK;
      } else {
        /* Failure */
        DBG_PRINT("INTERNAL ERROR : Problem in fx read of reg %d\n", gdb);
      }
    }
  } else {
    size_t pad_size = 0;
    if (ptrace_arch_check_unrecognized_register(gdb, &pad_size)) {
      /* Unsupported */
      ret = RET_NOSUPP;
    } else {
      /* Freak out */
      DBG_PRINT("INTERNAL ERROR : Unhandled read of reg %d\n", gdb);
    }
  }
  return ret;
}

int ptrace_write_registers(pid_t tid, uint8_t *data, size_t size) {
  int ret = RET_ERR;
  unsigned int gdb = 0;
  size_t done = 0;
  while (done < size) {
    size_t gdb_size, r_size;
    if (_gdb_register_size(gdb, &gdb_size, /*@unused@*/ &r_size)) {
      if (done + gdb_size > size) {
        break;
      } else if (gdb_size == 0) {
        break;
      }
      if (RET_OK !=
          ptrace_write_single_register(tid, gdb, &data[done], gdb_size)) {
        break;
      }
    } else {
      DBG_PRINT("INTERNAL ERROR : Unhandled write of reg %d\n", gdb);
      break;
    }
    done += gdb_size;
    gdb++;
  }
  if (done == size)
    ret = RET_OK;
  return ret;
}


int _ptrace_resume(pid_t pid, pid_t tid, int step, int gdb_sig) {
  int ret = RET_ERR;
  int sig;
  DBG_PRINT("pid:%d tid:%d step:%d gdb_sig:%d\n",
            pid, tid, step, gdb_sig);
  int index = target_index(tid);
  if (index >= 0) {
    sig = ptrace_arch_signal_from_gdb(gdb_sig);
    if (sig < 0) {
      sig = 0;
    }
    /*
     * Manage the process state
     * Since we are going from stopped to running,
     * set the state to PRS_RUN.
     * Also clear the wait flag and reset the wait status
     */
    PROCESS_STATE(index) = PRS_RUN;
    PROCESS_WAIT_FLAG(index) = false;
    PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
    PROCESS_SIG(index) = 0;
    if (sig) {
      PROCESS_STATE(index) = PRS_SIG_PENDING;
    } else {
      PROCESS_STATE(index) = PRS_RUN;
    }
    DBG_PRINT("pid:%d tid:%d wait_flag:%d process_state:%s\n",
                PROCESS_PID(index),
                PROCESS_TID(index),
                PROCESS_WAIT_FLAG(index),
                PROCESS_STATE_STR(index));
    if (step == 0)
      _target.step = false;
    else
      _target.step = true;
    /* TODO : Map sig to arg4 */
    if (0 == ptrace_os_continue(pid, tid, step, sig)) {
      ret = RET_OK;
    } else {
      PROCESS_STATE(index) = PRS_ERR;
      /* Failure */
      if (_resume_current_verbose) {
        DBG_PRINT("Error tid %x index %d step %d sig %d : %s\n",
                  tid, index, step, sig, strerror(errno));
      }
    }
  }
  return ret;
}
int ptrace_resume_from_current(pid_t pid, pid_t tid, int step, int gdb_sig) {
  return _ptrace_resume(pid, tid, step, gdb_sig);
}

int ptrace_resume_with_syscall(pid_t tid) {
  int ret = RET_ERR;
#ifdef PT_SYSCALL
  errno = 0;
  ret   = PTRACE(PT_SYSCALL, tid, PT_SYSCALL_ARG3, 0);
  if (0 == ret) {
    /* Success */
    CURRENT_PROCESS_STATE = PRS_RUN;
    ret = RET_OK;
  } else {
    /* Failure */
    if (_resume_syscall_verbose) {
      char str[128];
      memset(&str[0], 0, 128);
      DBG_PRINT("Error in resume with syscall\n");
      if (0 == strerror_r(errno, &str[0], 128)) {
        DBG_PRINT("Error %d %s\n", errno, str);
      } else {
        DBG_PRINT("Error %d\n", errno);
      }
    }
  }
#endif
  return ret;
}

int ptrace_resume_from_addr(pid_t pid, pid_t tid, int step, int gdb_sig,
                            uint64_t addr) {
  int ret = RET_ERR;
#ifndef DEEBE_RELEASE
  unsigned long kb_addr = (unsigned long)addr;
#endif
  int sig;
  sig = ptrace_arch_signal_from_gdb(gdb_sig);
  if (sig < 0)
    sig = 0;
  if (_resume_from_addr_verbose) {
    DBG_PRINT("ERROR NEED TO SUPPORT %s %d %d 0x%lx\n", __func__, step, sig,
              kb_addr);
  }
  return ret;
}

void ptrace_quick_kill(pid_t pid, pid_t tid) {
  if(!target_is_attached()) {
    DBG_PRINT("Killing tracee\n");
    kill(pid, SIGKILL); /* XXX change to pid */
    util_usleep(1000);
  }
  DBG_PRINT("Killing tracer\n");
  exit(0);
}

void ptrace_quick_signal(pid_t pid, pid_t tid, int gdb_sig) {
  /* This is how the routine should work */
  int sig;
  sig = ptrace_arch_signal_from_gdb(gdb_sig);
  if (sig > 0)
    kill(pid, sig);
}

void ptrace_kill(pid_t pid, pid_t tid) {
  if(!target_is_attached()) {
    DBG_PRINT("Killing tracee\n");
    /* As per linux manual PTRACE_KILL is deprecated */
    kill(PROCESS_PID(0), SIGKILL);
    util_usleep(1000);
  } else {
    ptrace_detach();
  }
}

int ptrace_go_waiting(int gdb_sig) { return RET_NOSUPP; }

int ptrace_offsets_query(uint64_t *text, uint64_t *data, uint64_t *bss) {
  *text = 0;
  *data = 0;
  *bss = 0;
  return RET_OK;
}

int ptrace_crc_query(uint64_t addr, size_t len, uint32_t *val) {
  return RET_ERR;
}

int ptrace_add_break(pid_t tid, int type, uint64_t addr, size_t len) {
  int ret = RET_ERR;

  unsigned long kaddr = (unsigned long)addr;

  ret = RET_ERR;
  if (_add_break_verbose) {
    DBG_PRINT("%d %lx %zu\n", type, kaddr, len);
  }

  if (type == GDB_INTERFACE_BP_HARDWARE) {
    if (ptrace_arch_support_hardware_breakpoints(tid)) {
      if (ptrace_arch_add_hardware_breakpoint(tid, addr, len)) {
        ret = RET_OK;
        if (_add_break_verbose) {
          DBG_PRINT("OK setting hardware breakpoint at 0x%lx\n", kaddr);
        }
      } else {
        if (_add_break_verbose) {
          DBG_PRINT("ERROR setting hardware breakpoint at 0x%lx\n", kaddr);
        }
      }
    } else {
      ret = RET_NOSUPP;
      if (_add_break_verbose) {
        DBG_PRINT("Hardware breakpoint is not supported\n");
      }
    }
  } else if ((type == GDB_INTERFACE_BP_READ_WATCH) ||
             (type == GDB_INTERFACE_BP_WRITE_WATCH) ||
             (type == GDB_INTERFACE_BP_ACCESS_WATCH)) {
    if (ptrace_arch_support_watchpoint(tid, type)) {
      if (ptrace_arch_add_watchpoint(tid, type, addr, len)) {
        ret = RET_OK;
        if (_add_break_verbose) {
          DBG_PRINT("OK setting watchpoint at 0x%lx\n", kaddr);
        }
      } else {
        if (_add_break_verbose) {
          DBG_PRINT("ERROR setting watchpoint at 0x%lx\n", kaddr);
        }
      }
    } else {
      ret = RET_NOSUPP;
      if (_add_break_verbose) {
        DBG_PRINT("Watchpoints type %d is not supported\n", type);
      }
    }
  } else if (type == GDB_INTERFACE_BP_SOFTWARE) {
    /* Add to general list first */
    struct breakpoint *bp = NULL;
    size_t arch_brkpt_len = ptrace_arch_swbreak_size();
    bp = breakpoint_add(&_target.bpl, _add_break_verbose, kaddr, type,
                        arch_brkpt_len);
    if (bp) {
      /* Get the arch specific break insn */
      ret = ptrace_arch_swbreak_insn(bp->bdata);
      if (ret == RET_OK) {
        size_t read_size;
        /* Read and save off the memory location that the break is goint to */
        ret = memory_read(tid, addr, bp->data, bp->len, &read_size, false);
        if (ret == RET_OK) {
          /* Now write the sw break insn in it's place */
          ret = memory_write(tid, addr, bp->bdata, bp->len, false);
          if (ret == RET_OK) {
            if (_add_break_verbose) {
              DBG_PRINT("OK setting breakpoint at 0x%lx\n", kaddr);
            }
          } else {
            /* Failure */
            if (_add_break_verbose) {
              DBG_PRINT("ERROR writing breakpoint at 0x%lx\n", kaddr);
            }
            breakpoint_remove(&_target.bpl, _add_break_verbose, kaddr);
          }
        } else {
          /* Failure */
          if (_add_break_verbose) {
            DBG_PRINT("ERROR reading data for breakpoint at 0x%lx\n", kaddr);
          }
          breakpoint_remove(&_target.bpl, _add_break_verbose, kaddr);
        }
      } else {
        /* Failure */
        if (_add_break_verbose) {
          DBG_PRINT("INTERNAL ERROR with ARCH breakpoint at 0x%lx\n", kaddr);
        }
        breakpoint_remove(&_target.bpl, _add_break_verbose, kaddr);
      }
    } else {
      if (_add_break_verbose) {
        DBG_PRINT("INTERNAL ERROR creating breakpoint at 0x%lx\n", kaddr);
      }
    }
  } else {
    if (_add_break_verbose) {
      DBG_PRINT("Warning unsupported breakpoint type %d at 0x%lx\n", type,
                kaddr);
    }
    ret = RET_NOSUPP;
  }
  return ret;
}

int ptrace_remove_break(pid_t tid, int type, uint64_t addr, size_t len) {
  int ret = RET_ERR;
  unsigned long kaddr = (unsigned long)addr;
  if (_remove_break_verbose) {
    DBG_PRINT("%s %d %lx %zu\n", __func__, type, kaddr, len);
  }

  if (type == GDB_INTERFACE_BP_HARDWARE) {
    if (ptrace_arch_support_hardware_breakpoints(tid)) {
      if (ptrace_arch_remove_hardware_breakpoint(tid, addr, len)) {
        ret = RET_OK;
        if (_remove_break_verbose) {
          DBG_PRINT("OK removing hardware breakpoint at 0x%lx\n", kaddr);
        }
      } else {
        if (_remove_break_verbose) {
          DBG_PRINT("ERROR removing hardware breakpoint at 0x%lx\n", kaddr);
        }
      }
    } else {
      ret = RET_NOSUPP;
      if (_add_break_verbose) {
        DBG_PRINT("Hardware breakpoint is not supported\n");
      }
    }
  } else if ((type == GDB_INTERFACE_BP_READ_WATCH) ||
             (type == GDB_INTERFACE_BP_WRITE_WATCH) ||
             (type == GDB_INTERFACE_BP_ACCESS_WATCH)) {
    if (ptrace_arch_support_watchpoint(tid, type)) {
      if (ptrace_arch_remove_watchpoint(tid, type, addr, len)) {
        ret = RET_OK;
        if (_remove_break_verbose) {
          DBG_PRINT("OK removing watchpoint at 0x%lx\n", kaddr);
        }
      } else {
        if (_remove_break_verbose) {
          DBG_PRINT("ERROR removing watchpoint at 0x%lx\n", kaddr);
        }
      }
    } else {
      ret = RET_NOSUPP;
      if (_remove_break_verbose) {
        DBG_PRINT("Watchpoint type %d is not supported\n", type);
      }
    }
  } else if (type == GDB_INTERFACE_BP_SOFTWARE) {
    struct breakpoint *bp = NULL;
    bp = breakpoint_find(_target.bpl, _remove_break_verbose, kaddr);
    if (bp) {
      /*
       * Only really remove the breakpoint if it's reference count
       * is one. Write shadow content back anyway.
       */
      ret = memory_write(tid, addr, bp->data, bp->len, false);
      if (1 == bp->ref_count) {
        if (ret == RET_OK) {
          breakpoint_remove(&_target.bpl, _remove_break_verbose, kaddr);
          if (_add_break_verbose) {
            DBG_PRINT("OK removing breakpoint at 0x%lx\n", kaddr);
          }
        } else {
          /* Failure */
          if (_add_break_verbose) {
            DBG_PRINT("ERROR restoring data for breakpoint at 0x%lx\n", kaddr);
          }
        }
      } else {
        /* This just decrements the ref_count */
        breakpoint_remove(&_target.bpl, _remove_break_verbose, kaddr);
        ret = RET_OK;
      }
    } else {
      if (_add_break_verbose) {
        DBG_PRINT("Warning problem removing breakpoint at 0x%lx\n", kaddr);
      }
    }
  } else {
    if (_remove_break_verbose) {
      DBG_PRINT("Warning unsupported breakpoint type %d at 0x%lx\n", type,
                kaddr);
    }
    ret = RET_NOSUPP;
  }

  return ret;
}
#if 0
static void update_process_state(pid_t tid)
{
  int wait_status;
  int wait_tid;
  int real_state;
  int index      = target_index(tid);
  real_state     = get_process_state(tid);
  DBG_PRINT("Waiting for tid:%d to update state real_state:%s state:%s\n",
              tid, STATE_STR(real_state), STATE_STR(PROCESS_STATE(index)));
  do {
    wait_status  = -1;
    wait_tid     = ptrace_os_waitpid(tid, &wait_status);
    if (wait_tid == tid) {
      real_state   = get_process_state(tid);
      DBG_PRINT("tid:%d reported stop\n", wait_tid);
    } else if (wait_tid == 0) {
      //DBG_PRINT("No children in waitable state \n");
      util_usleep(100);
    }
  } while(real_state != PROCESS_STATE(index));
}
#endif

static int ignore_signal[MAX_TARGET_PROCESS];
static void _deliver_sig(int sig, int change_state) {
#if __linux__
	int index;
	for (index = 0; index < _target.number_processes; index++) {
    if (CURRENT_PROCESS_TID == PROCESS_TID(index)) continue;

    int real_state = get_process_state(PROCESS_TID(index));
    DBG_PRINT("tid:%d state:%s real_state:%s change_state:%s\n",
                PROCESS_TID(index),
                PROCESS_STATE_STR(index),
                STATE_STR(real_state),
                STATE_STR(change_state));

    /* lucky */
    if (change_state == real_state) {
      PROCESS_STATE(index) = real_state;
      PROCESS_WAIT_FLAG(index) = true;
      continue;
    }

    if (sig > 0) {
      if ( (real_state != PRS_STOP) && (real_state != PRS_EXIT) ) {
        if ( !ptrace_os_new_thread(PROCESS_WAIT_STATUS(index)) ) {

          /* deebe stored state & actual state does not match */
          //if(PROCESS_STATE(index) != real_state) update_process_state(PROCESS_TID(index));
		    	int wait_status;
		    	int wait_tid;
		    	pid_t tid = PROCESS_TID(index);
          DBG_PRINT("Waiting for tid:%d to receive signal:%d\n", tid, sig);
		    	/* send signal */
          os_thread_kill(tid, sig);
          while (1) {
            /* Sleep for a msec */
            util_usleep(1000);
            /* wait for the signal to takes affect */
            wait_status = -1;
		    		wait_tid = ptrace_os_waitpid(tid, &wait_status);
		    		if ((tid == wait_tid)) {
                if ((WSTOPSIG(wait_status) == sig)) {
                  PROCESS_WAIT_STATUS(index)  = PROCESS_WAIT_STATUS_DEFAULT;
                  DBG_PRINT("tid:%d reported sig stop\n", wait_tid);
                } else {
                  PROCESS_WAIT_STATUS(index)  = wait_status;
                  DBG_PRINT("tid:%d reported other signal\n", wait_tid);
                  ignore_signal[index] = sig;
                }
                PROCESS_SIG(index)          = 0;
                PROCESS_STATE(index)        = PRS_STOP;
                PROCESS_WAIT_FLAG(index)    = true;
		    			break;
		    		} else if (tid == 0) { /* pid not in a waitable state */
              //DBG_PRINT("No children in waitable state \n");
		    			continue;
		    		}
		    	} /* while loop */
        } /* ptrace_os_new_thread */
		  }
    }
  } /* for loop */
#endif
}

void _wait_all() {
  ptrace_os_wait(-1);
}

void _wait_single() { ptrace_os_wait(CURRENT_PROCESS_TID); }

bool __exited(char *str, int index, int wait_status) {
  bool ret = false;
  DBG_PRINT("tid:%d wait_status: %d\n", PROCESS_TID(index), wait_status);
  if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
    if (index == 0) {
      if (WIFEXITED(wait_status)) {
        /*
         * returns true if the child terminated normally, that is,
         * by calling exit(3) or _exit(2), or by returning from main().
         */
        int exit_status = WEXITSTATUS(wait_status);
        /*
         * returns the exit status of the  child.   This  consists  of  the
         * least  significant  16-8  bits  of  the status argument that the
         * child specified in a call to exit() or _exit() or as  the  argu-
         * ment  for  a return statement in main().  This macro should only
         * be employed if WIFEXITED returned true.
         */
        /* Fill out the status string */
        sprintf(str, "W%02x", exit_status);
      } else {
        /* Signaled */
        int s = WTERMSIG(wait_status);
        if (ptrace_os_new_thread(wait_status)) {
          DBG_PRINT("its new thread\n");
          return true;
        }
        int g = ptrace_arch_signal_to_gdb(s);
        sprintf(str, "X%02x", g);
      }
      PROCESS_STATE(index) = PRS_EXIT;
      /* Set the main thread to the current so this event is reported */
      _target.current_process = 0;
      /* For main */
      gDebugeeRunning = false;
      ret = true;
    } else {
      /*
       * A thread has exited, set it's alive state to false
       * and switch to the parent process
       */
      PROCESS_STATE(index)        = PRS_EXIT;
      PROCESS_WAIT_FLAG(index)    = false;
      PROCESS_WAIT_STATUS(index)  = PROCESS_WAIT_STATUS_DEFAULT;
      /* Need to find a replacement for current thread, use the parent */
      if (index == target_current_index())
        _target.current_process = 0;
    }
  }
  return ret;
}
static bool _exited_single(char *str) {
  bool ret = false;
  if (CURRENT_PROCESS_WAIT_FLAG)
    ret = __exited(str, target_current_index(), CURRENT_PROCESS_WAIT_STATUS);
  return ret;
}

static bool _exited_all(char *str) {
  bool ret = false;
  int index;
  for (index = 0; index < _target.number_processes; index++) {
    if (PROCESS_WAIT_FLAG(index)) {
      int wait_status = PROCESS_WAIT_STATUS(index);
      ret = __exited(str, index, wait_status);
      /*
       * When __exited returns true the debuggee exited
       * There is no point continuing, bail
       */
      if (ret)
        break;
    }
  }
  return ret;
}

static void __continued(int index, int wait_status) {
#ifdef WIFCONTINUED
  if (WIFCONTINUED(wait_status)) {
    DBG_PRINT("Process %lx updated state to PRS_CONT\n", PROCESS_TID(index));
    PROCESS_STATE(index) = PRS_CONT;
  }
#endif
}

static void _continued_single() {
  if (CURRENT_PROCESS_WAIT_FLAG)
    __continued(target_current_index(), CURRENT_PROCESS_WAIT_STATUS);
}

static void _continued_all() {
  int index;
  for (index = 0; index < _target.number_processes; index++) {
    if (PROCESS_WAIT_FLAG(index)) {
      int wait_status = PROCESS_WAIT_STATUS(index);
      __continued(index, wait_status);
    }
  }
}

static void _stopped_all(char *str) {
  int index;
  bool no_event = true; /* Nothing to report to gdb */
  /* This does not work for FreeBSD as the threads are not free running */
  for (index = 0; no_event && index < _target.number_processes; index++) {
    //DBG_PRINT("pid:%d tid:%d wait_flag:%d\n",
    //            PROCESS_PID(index),
    //            PROCESS_TID(index),
    //            PROCESS_WAIT_FLAG(index));
    bool process_wait = PROCESS_WAIT_FLAG(index);
    if (process_wait) {
      pid_t tid = PROCESS_TID(index);
      int wait_status = PROCESS_WAIT_STATUS(index);
      if (WIFSTOPPED(wait_status)) {
        unsigned long pc = 0;
        int s = WSTOPSIG(wait_status);
        int g = ptrace_arch_signal_to_gdb(s);
        DBG_PRINT("pid:%d tid:%d wait_flag:%d process_state:%s platform_signal:%d gdb_signal:%d\n",
                    PROCESS_PID(index), PROCESS_TID(index),
                    PROCESS_WAIT_FLAG(index), PROCESS_STATE_STR(index), s, g);
        ptrace_arch_get_pc(tid, &pc);
        if (_wait_verbose) {
          DBG_PRINT("stopped at pc 0x%lx index:%d\n", pc, index);
          if (pc) {
            uint8_t b[32] = {0};
            size_t read_size = 0;
            memory_read_gdb(tid, pc, &b[0], 32, &read_size);
            util_print_buffer(fp_log, 0, 32, &b[0]);
          }
        }
        if (s == SIGTRAP) {
          DBG_PRINT("**** GOT SIGTRAP SIGNAL ****\n");
          unsigned long watch_addr = 0;
          /* Fill out the status string */
          if (ptrace_arch_hit_hardware_breakpoint(tid, pc)) {
            gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_BREAKPOINT);
            target_thread_make_current(tid);
            CURRENT_PROCESS_STOP = LLDB_STOP_REASON_BREAKPOINT;
            no_event = false;
          } else if (ptrace_arch_hit_watchpoint(tid, &watch_addr)) {
            gdb_stop_string(str, g, tid, watch_addr,
                            LLDB_STOP_REASON_WATCHPOINT);
            target_thread_make_current(tid);
            CURRENT_PROCESS_STOP = LLDB_STOP_REASON_WATCHPOINT;
            no_event = false;
          } else {
            /*
             * On Linux, when a new thread is created, the parent receives
             * a SIGTRAP with the addition information of PTRACE_EVENT_CLONE
             * embedded in the wait status status.  Check for this before
             * returning an SIGTRAP to gdb.  Gdb will receive the the
             *notification
             * of a new thread from the the new thread, not the parent
             *
             * On FreeBSD, a new thread is inferred by polling the syscalls
             * Looking for a thread create or an increase in the threads
             * reported by the kernel.
             */
            if (!ptrace_os_new_thread(wait_status)) {
              /* A normal breakpoint was hit, or a trap instruction */
              int reason;
              if (_target.step) {
                /* stepping can run over a normal breakpoint so precidence is
                 * for stepping */
                reason = LLDB_STOP_REASON_TRACE;
              } else {
                /*
                 * XXX A real trap and a breakpoint could be at the same
                 *location
                 *
                 * lldb checks if the pc matches what was used to set the
                 *breakpoint.
                 * At this point the pc can advanced (at least on x86).
                 * If the pc and the breakpoint don't match, lldb puts itself in
                 *a bad
                 * state.  So check if we are on lldb and roll back the pc one
                 *sw break's
                 * worth.
                 *
                 * On freebsd arm, the pc isn't advanced so use the arch
                 *dependent function
                 * ptrace_arch_swbreak_rollback
                 */
                if (_target.lldb)
                  ptrace_arch_set_pc(tid, pc - ptrace_arch_swbrk_rollback());

                reason = LLDB_STOP_REASON_BREAKPOINT;
              }
              gdb_stop_string(str, g, tid, 0, reason);
              DBG_PRINT("pid:%d tid:%d wait_flag:%d process_state:%s str:[%s] LLDB_STOP_REASON_BREAKPOINT\n",
                          PROCESS_PID(index), PROCESS_TID(index),
                          PROCESS_WAIT_FLAG(index),
                          PROCESS_STATE_STR(index), str);
              target_thread_make_current(tid);
              CURRENT_PROCESS_STOP = reason;
              no_event = false;
              PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
            } /* if ptrace_os_new_thread */
            else
            {
              DBG_PRINT("Parent process:%d got SIGTRAP because of clone ignore it\n", tid);
              target_thread_make_current(tid);
              PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
            }
          } /* else */
        } /* if SIGTRAP */
        else
        {
          DBG_PRINT("**** GOT NON_SIGTRAP SIGNAL ****\n");
          /*
           * On linux, thread indicates it has been started
           * by starting with a STOP signal.  When this is
           * seen when the process state is at PRS_START and
           * running in NonStop, ignore.
           * The enumeration of the new thread has already happended.
           *
           * Strengthen the check to ignore all signals when the
           * process is in the start state
           *
           */

          DBG_PRINT("Process pid:%d tid:%d state:%s\n",
                      PROCESS_PID(index),
                      PROCESS_TID(index),
                      PROCESS_STATE_STR(index));

          if (ignore_signal[index] != s) {
            if (PRS_START == PROCESS_STATE(index)) {
                DBG_PRINT("Ignoring clone stop signal pid:%d tid:%d gdb signal:%d\n",
                            PROCESS_PID(index), PROCESS_TID(index), g);
                PROCESS_WAIT_STATUS(index)= PROCESS_WAIT_STATUS_DEFAULT;
                PROCESS_WAIT_FLAG(index)  = 0;
                PROCESS_STATE(index)      = PRS_RUN;
                ptrace_os_continue_and_wait(PROCESS_TID(index), PROCESS_SIG(index));
            } else {
              /*
               * A normal, non trap signal
               *
               * Report all
               */
              if (target_thread_make_current(tid)) {
                /* A non trap signal */
                gdb_stop_string(str, g, tid, 0, LLDB_STOP_REASON_SIGNAL);
                DBG_PRINT("pid:%d tid:%d wait_flag:%d process_state:%s str:[%s] LLDB_STOP_REASON_SIGNAL\n",
                            PROCESS_PID(index), PROCESS_TID(index),
                            PROCESS_WAIT_FLAG(index), PROCESS_STATE_STR(index), str);
                CURRENT_PROCESS_STOP = LLDB_STOP_REASON_SIGNAL;
                no_event = false;
                PROCESS_WAIT_STATUS(index) = PROCESS_WAIT_STATUS_DEFAULT;
                PROCESS_SIG(index) = 0;
              }
            } /* else */
          } /* ignore signal */
          else
          {
            DBG_PRINT("tid:%d Ignoring signal s:%d\n", s);
            PROCESS_WAIT_STATUS(index)= PROCESS_WAIT_STATUS_DEFAULT;
            PROCESS_WAIT_FLAG(index)  = 0;
            PROCESS_STATE(index) = PRS_RUN;
            ptrace_os_continue_and_wait(PROCESS_TID(index), PROCESS_SIG(index));
            ignore_signal[index] = 0;
          }
        } /* else */
      } /* WIFSTOPPED */
#ifdef WIFCONTINUED
      else if (WIFCONTINUED(wait_status)) {
        CURRENT_PROCESS_STATE = PRS_CONT;
      } /* WIFCONTINUED */
#endif
      /* wait flag is set process is waitng */
      if (PROCESS_STATE(index) == PRS_START)
        PROCESS_STATE(index) = PRS_CONT;
    } /* process waiting */
  }   /* process loop */
}

static int is_all_stopped()
{
  int index;
  for (index = 0; index < _target.number_processes; index++) {
    int real_state = get_process_state(PROCESS_TID(index));
    if (!((real_state == PRS_STOP) ||
          (real_state == PRS_EXIT) ||
          (real_state == PRS_ERR))) {
      return 0;
    }
  }
  return 1;
}


#if 0
static int is_all_stopped()
{
  int index;
  for (index = 0; index < _target.number_processes; index++) {
    int real_state = get_process_state(PROCESS_TID(index));
    if (!PROCESS_WAIT_FLAG(index)) {
      if (real_state == PRS_STOP || real_state == PRS_EXIT)
        PROCESS_WAIT_FLAG(index) = true;
      else {
        DBG_PRINT("Thread tid:%d waitflag not set & real_state:%s\n",
        PROCESS_TID(index),
        STATE_STR(real_state));
        return 0;
      }
    }
    if (real_state != PRS_STOP || real_state != PRS_EXIT) {
      DBG_PRINT("Thread tid:%d not in stop but in state:%s\n",
        PROCESS_TID(index),
        STATE_STR(real_state));
      return 0;
    }
    PROCESS_STATE(index) = real_state;
  }
  return 1;
}
#endif
int ptrace_wait(char *str, int step, bool skip_continue_others) {
  int ret = RET_ERR;
  if(str) str[0] = '\0'; /* clear old string */

  /* Could be waiting awhile, turn on sigio */
  signal_sigio_on();
  if (step) {
    _wait_single();
    if (!_exited_single(str)) {
      /*
       * The current thread could have exited
       * This will change the currnet thread to
       * the parent thread
       */
      ptrace_os_stopped_single(str, _wait_verbose);
      _continued_single();
      /* _newthread_single(); */
    }
  } else {
    _wait_all();
    if (!_exited_all(str)) {
      /*
       * The current thread could have exited
       * This will change the current thread to
       * the parent thread
       */
      _stopped_all(str);
      /*
       * Some random thread could have trapped/signaled
       * This will change the current thread to the
       * the thread causing the event.  It also means
       * that some events went unhandled.
       */
    }
    /*
     * These routines do not return events so they are
     * they are safe to run anytime
     */
    _continued_all();
    /*
     * Sometime the caller wants everyone to stop
     * So do not start up the non-current threads
     */
    //if (!skip_continue_others)
    //  ptrace_os_continue_others();
  }
  /* Finished waiting, turn off sigio */
  signal_sigio_off();

  //PRINT_ALL_PROCESS_INFO("check");
  /* make sure current process & all threads are in stopped state */
  if (CURRENT_PROCESS_WAIT_FLAG) {
    if (!strlen(str)) {
      ret = RET_IGNORE;
      /* Add sleep here so that deebe accepts Ctrl+C from debugger */
      util_usleep(100);
    } else {
      DBG_PRINT("Waiting for all threads to stop/exit\n");
      while(1) {
        if(is_all_stopped()) {
          DBG_PRINT("All threads in stopped/exited state\n");
          ret = RET_OK;
          break;
        }
        _deliver_sig(SIGSTOP, PRS_STOP);
        /* Add sleep here so that deebe accepts Ctrl+C from debugger */
        util_usleep(100);
      }
    }
  } else {
    if (step) ret = RET_OK;
    ret = RET_CONTINUE_WAIT;
    /* Add sleep here so that deebe accepts Ctrl+C from debugger */
    util_usleep(100);
  }
  //PRINT_ALL_PROCESS_INFO("exit");
  DBG_PRINT("return:%s\n", RETURN_CODE_STR(ret));
  return ret;
}

#if 0
/* As per GDB manual the very first thread ID mentioned in the
   reply will be stopped by GDB in a subsequent message
 */
void ptrace_threadinfo_query(int first, char *out_buf) {
  static int index = 0;
  pid_t tid;
  pid_t pid = PROCESS_PID(0);
  //PRINT_ALL_PROCESS_INFO("Bingo");
  //DBG_PRINT("Number of threads:%d index:%d tid:\n", _target.number_processes, index);
  if (first) {
    sprintf(out_buf, "mp%x.%x", pid, CURRENT_PROCESS_TID);
  } else {
    if (index < _target.number_processes) {
        tid = PROCESS_TID(index);
        if (tid != CURRENT_PROCESS_TID) {
          sprintf(out_buf, "mp%x.%x", pid, tid);
          index++;
        } else {
          index++;
          if (index < _target.number_processes) {
            tid = PROCESS_TID(index);
            sprintf(out_buf, "mp%x.%x", pid, tid);
            index++;
          } else {
            sprintf(out_buf, "l");
            index = 0;
          }
        }
     } else {
        sprintf(out_buf, "l");
        index = 0;
     }
  }
}
#endif

#if 1
void ptrace_threadinfo_query(int first, char *out_buf) {
  static int n;
  int i;
  pid_t t;


  /* Find next active thread */
  for (i = first ? 0 : n + 1; i < _target.number_processes; i++) {
    if (PROCESS_STATE(i) != PRS_EXIT) {
      n = i;
      break;
    }
  }

  if (_target.lldb) {
    if (i < _target.number_processes) {
      t = PROCESS_TID(n);
      sprintf(out_buf, "m%x", t);
    } else {
      sprintf(out_buf, "l");
    }
  } else {
    pid_t p = PROCESS_PID(0);
    if (i < _target.number_processes) {
      t = PROCESS_TID(n);
      if (n > 0)
	       sprintf(out_buf, "mp%x.%x", p, t);
      else
	       sprintf(out_buf, "mp%x.%x", p, t);
    } else {
      sprintf(out_buf, "l");
    }
  }
}
#endif

void ptrace_supported_features_query(char *out_buf) {
  char str[128];
  sprintf(str, "PacketSize=%x;", GDB_INTERFACE_PARAM_DATABYTES_MAX);
  strcat(out_buf, str);

  if (_target.multiprocess) {
    /* Support multi process extensions */
    sprintf(str, "multiprocess+;");
    strcat(out_buf, str);
  }
#if 0
	sprintf(str, "QPassSignals+;");
	strcat(out_buf, str);

	sprintf(str, "QProgramSignals+;");
	strcat(out_buf, str);
#endif
  /*
   * gdb
   * Cause gdb to ignore errors on unsupported features
   *
   * lldb
   * lldb assumes it is supported, it's first packet is QStartNoAckMode
   */
  sprintf(str, "QStartNoAckMode+;");
  strcat(out_buf, str);
#if 0
	/*
	 * NonStop means threads can run conncurrently
	 * The difficulty is when things like memory
	 * need to be written too.
	 */
	sprintf(str, "QNonStop+;");
	strcat(out_buf, str);
#endif
  /*
   * On lldb
   * Support thread suffix support for 'g', 'G', 'p' and 'P'
   */
  sprintf(str, "QThreadSuffixSupported+;");
  strcat(out_buf, str);

  /*
   * On lldb
   * To list threads in stop reply
   */
  sprintf(str, "QListThreadsInStopReply+;");
  strcat(out_buf, str);

  sprintf(str, "qEcho+;");
  strcat(out_buf, str);

  sprintf(str, "qXfer:auxv:read+");
  strcat(out_buf, str);
}

int ptrace_get_signal(void) { return CURRENT_PROCESS_SIG; }

void ptrace_option_set_syscall(pid_t tid) {
  ptrace_arch_option_set_syscall(tid);
}

void ptrace_get_syscall(pid_t tid, void *id, void *arg1, void *arg2, void *arg3,
                        void *arg4, void *ret) {
  ptrace_arch_get_syscall(tid, id, arg1, arg2, arg3, arg4, ret);
}

int ptrace_set_gen_thread(int64_t pid, int64_t tid) {
  int ret = RET_ERR;
  int64_t key;
  if (_target.multiprocess) {
    /* pid and tid are valid */
    key = tid;
  } else {
    /* only pid is valid, but it is really tid */
    key = pid;
  }
  DBG_PRINT("pid:%d tid:%d\n", pid, tid);
  if ((key == 0) || (key == -1)) {
    /* TODO HANDLE */
    ret = RET_OK;
  } else {
    int index;
    /* Normal case */
    index = target_index(key);
    if (index < 0) {
      /* gdb can pass in the process id, assume this means index == 0 */
      /* XXX may not work for linux */
      if (target_is_alive_process(key)) {
        index = 0;
      }
    }
    if (index >= 0) {
      pid_t new_pid = PROCESS_PID(index);
      pid_t new_tid = PROCESS_TID(index);
      ret = ptrace_os_gen_thread(new_pid, new_tid);
    }
  }
  return ret;
}

const char *ptrace_get_xml_register_string() {
  return ptrace_arch_get_xml_register_string();
}

void ptrace_set_xml_register_reporting() {
  _target.xml_register_reporting = true;
}

bool ptrace_register_info(uint32_t reg, char *buf) {
  bool ret = false;
  int i = 0;
  char str[128];
  struct reg_location_list *rlll[2] = {grll, frll};
  char *descriptions[2] = {"General Purpose Registers",
                           "Floating Point Registers"};
  int reg_class;

  for (reg_class = 0; reg_class < 2; reg_class++) {
    struct reg_location_list *rll = rlll[reg_class];
    char *description = descriptions[reg_class];
    if (target_is_gdb_reg(reg, &i, rll)) {
      /* General Purpose Reg */
      sprintf(str, "name:%s;", rll[i].name);
      strcat(buf, str);
      /* XXX Magic 'X' means this is a non value */
      if (rll[i].altname[0] != 'X') {
        sprintf(str, "alt-name:%s;", rll[i].altname);
        strcat(buf, str);
      }
      sprintf(str, "bitsize:%zu;", rll[i].size * 8);
      strcat(buf, str);
      sprintf(str, "offset:%zu;", rll[i].off);
      strcat(buf, str);
      sprintf(str, "encoding:%s;", rll[i].encoding);
      strcat(buf, str);
      sprintf(str, "format:%s;", rll[i].format);
      strcat(buf, str);
      sprintf(str, "set:%s;", description);
      strcat(buf, str);
      if (rll[i].gcc >= 0) {
        sprintf(str, "gcc:%d;", rll[i].gcc);
        strcat(buf, str);
      }
      if (rll[i].dwarf >= 0) {
        sprintf(str, "dwarf:%d;", rll[i].dwarf);
        strcat(buf, str);
      }
      /* XXX Magic 'X' means this is a non value */
      if (rll[i].generic[0] != 'X') {
        sprintf(str, "generic:%s;", rll[i].generic);
        strcat(buf, str);
      }

      ret = true;
      break;
    }
  }

  return ret;
}

bool ptrace_read_auxv(char *out_buf, size_t out_buf_size, size_t offset,
                      size_t *size) {
  return ptrace_arch_read_auxv(out_buf, out_buf_size, offset, size);
}

int ptrace_get_tls_address(int64_t thread, uint64_t offset, uint64_t lm,
			   uintptr_t *tlsaddr)
{
  return ptrace_os_get_tls_address(thread, lm, offset, tlsaddr);
}

#ifndef DEEBE_RELEASE
void log_ptrace(int request, pid_t pid, char *reqstr, char *srcname,
                uint line, int perrno, long int ret)
{
  char str[128];
  if (perrno != 0) {
    if (perrno == ESRCH) {
       DBG_PRINT("Tracee pid %d is dead or not traced or not stopped\n", pid);
    }
    DBG_PRINT("ERROR: PTRACE call failed @ source %s:%d\n", srcname, line);
    DBG_PRINT("Failed for request %d (%s) pid : %d perrno: %d\n",
                request, reqstr, pid, perrno);
    memset(&str[0], 0, 128);
    if (0 == strerror_r(perrno, &str[0], 128)) {
      DBG_PRINT("\tError-code : %d Error-msg : %s\n", perrno, str);
    }
  } else {
    if (request != 3) {
      DBG_PRINT("PTRACE call @ source %s:%d request:%d (%s) pid:%zd ret:%lx\n",
                  srcname, line, request, reqstr, pid, ret);
    }
  }
}

#ifdef __linux__
int ptrace_debug(char *reqstr, char *srcname, uint line,
                  int request, pid_t pid, ...)
{
  int perrno;
  va_list args;
  va_start(args, pid);
  errno = 0;
  long int ret = ptrace(request, pid, args);
  perrno = errno;
  log_ptrace(request, pid, reqstr, srcname, line, errno, ret);
  va_end(args);
  errno = perrno;
  return ret;
}
#else
int ptrace_debug(int request, pid_t pid, caddr_t addr,
                  int data, char *reqstr, char *srcname,
                  uint line)
{
  int perrno;
  errno   = 0;
  int ret = ptrace(request, pid, addr, data);
  perrno  = errno;
  log_ptrace(request, pid, reqstr, srcname, line, errno, ret);
  errno = perrno;
  return ret;
}
#endif
#endif
