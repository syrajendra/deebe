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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "cmdline.h"
#include "gdb_interface.h"
#define DECL_GLOBAL
#include "global.h"
#undef DECL_GLOBAL
#include "global.h"
#include "macros.h"
#include "network.h"
#include "packet.h"
#include "watchdog.h"

// default dir of deebe.log or set DEEBE_LOG_DIR env var
#define LOG_PATH     "/tmp"
#define LOG_FILENAME "deebe.log"

/* Defined in signal.c */
extern void (*signal_handle_sigio)(int sig);
extern void (*signal_handle_sigrtmin)(int sig);
extern void (*signal_handle_sigchld)(int sig);

void main_sigchld(/*@unused@*/ int sig) {}

void main_sigio(/*@unused@*/ int sig) {
  /*
   * When switching from normal to quick
   * drop the oustanding output packages
   */
  network_clear_write();

  packet_quick_exchange ();
}

void main_sigrtmin(int sig) {
  bool watch = watchdog_get();
  if (watch) {
    WATCHDOG_ERROR();
  } else {
    watchdog_set();
  }
}
static void _forward_packet(uint8_t *dst, uint8_t *src, size_t *dst_size,
                            size_t *src_size) {
  if (*src_size) {
    memcpy(dst, src, *src_size);
    *dst_size = *src_size;
    *src_size = 0;
  }
}

int main_forward() {
  int ret = 1;

  /* reuse the normal network setup */
  if (network_init()) {
    /* Now accept from gdb */
    if (network_accept()) {
      /* Now connect to remote deebe */
      if (network_connect()) {
        while (true) {
          network_read();
          if (network_in_buffer_total > 0) {
            _forward_packet(&network_out_buffer[0], &network_in_buffer[0],
                            &network_out_buffer_total,
                            &network_in_buffer_total);

            network_write_fwd();
          }
          network_read_fwd();
          if (network_in_buffer_total > 0) {
            _forward_packet(&network_out_buffer[0], &network_in_buffer[0],
                            &network_out_buffer_total,
                            &network_in_buffer_total);

            network_write();
          }
        }
      }
    }
    network_cleanup();
  }

  return ret;
}

int main_debug() {
  int ret = 1;
  bool debugee_ok = false;

  /* Sets up the gdb_interface_target */
  gdb_interface_init();

  if (gdb_interface_target == NULL) {
    fprintf(stderr, "INTERNAL ERROR : gdb interface uninitalized\n");
  } else {
    /* Check network setup */
    if (network_init()) {
      /* Basic network ok, now setup the cmdline debuggee */
      if (0 != cmdline_pid) {
        if (gdb_interface_target->attach) {
          if (RET_OK != gdb_interface_target->attach(cmdline_pid))
            fprintf(stderr, "Error attaching to pid %d\n", cmdline_pid);
          else
            debugee_ok = true;

        } else {
          fprintf(stderr,
                  "Error : Attaching to a running process is not supported\n");
        }

      } else if (0 != cmdline_argc) {
        if (gdb_interface_target->open) {
          if (RET_OK !=
              gdb_interface_target->open(cmdline_argc, cmdline_argv,
                                         cmdline_argv[0]))
            fprintf(stderr, "Error opening program %s to debug\n",
                    cmdline_argv[0]);
          else
            debugee_ok = true;

        } else {
          fprintf(stderr, "Error : Starting a new process is not supported\n");
        }

      } else {
        fprintf(stderr, "Error : no valid program to debug\n");
      }
      if (debugee_ok) {
        /* Debuggee is ok, now accept connection */
        /* Success */
        char ip_addr[512] = {'\0'};
        network_ip_address(ip_addr);
        if (strlen(ip_addr) > 0)
          fprintf(stdout, "Listening on %s:%ld\n", ip_addr, cmdline_port);
        else
          fprintf(stdout, "Listening on port %ld\n", cmdline_port);
        fflush(stdout);

        if (network_accept()) {
          char hostname[256] = {'\0'};
          network_hostname(hostname);
          if (strlen(hostname) > 0)
            fprintf(stdout, "Successfully connected to %s\n", hostname);
          do {
	    if (packet_exchange ()) {
              break;
            }
          } while (gDebugeeRunning);
        }
      }
      network_cleanup();
    }
  }

  gdb_interface_cleanup();

  return ret;
}

void exit_cleanup()
{
  buffer_cleanup();
#ifdef __linux__
  thread_db_cleanup();
  ptrace_cleanup();
  symbol_cleanup();
#endif
  network_cleanup();
  cmdline_cleanup();
}

#ifndef DEEBE_RELEASE
static void create_log_file()
{
  char logfile[1024];
  char *user    = getenv("USER");
  char *tmp_dir = getenv("DEEBE_LOG_DIR");
  if (!tmp_dir) {
    tmp_dir     = LOG_PATH;
  }
  if (!user) {
    user        = "";
  }
  snprintf(logfile, 1024, "%s/%s", tmp_dir, user);
  if (0 != mkdir(logfile, 0700)) {
    if (errno != EEXIST) {
      printf("Error: Failed to create log dir '%s' : %s\n", logfile, strerror(errno));
      return;
    }
  }
  snprintf(logfile, 1024, "%s/%s/%s", tmp_dir, user, LOG_FILENAME);
  fp_log        = fopen(logfile, "w");
  if (fp_log) {
    printf("Deebe log file : %s\n", logfile);
  } else {
    printf("Error: Failed to create log file '%s' : %s\n", logfile, strerror(errno));
  }
}
#endif

int main(int argc, char *argv[]) {
  int ret = -1;

  atexit(exit_cleanup);

#ifndef DEEBE_RELEASE
  create_log_file();
#endif
  /* Signal handlers */
  signal_handle_sigio = main_sigio;
  signal_handle_sigrtmin = main_sigrtmin;
  signal_handle_sigchld = main_sigchld;

  if (0 != cmdline_init(argc, argv)) {
    /* start the watchdog timer */
    if (cmdline_watchdog_minutes > 0) {
      /* watchdog is in seconds, for *= 60 */
      long seconds = 60 * cmdline_watchdog_minutes;
      if (!watchdog_init(seconds)) {
/*
 * Only report this error if timer_create
 * is supported.  If it isn't then the watchdog
 * functionality is simulated in the network
 * code where read or connect delays are
 * expected.
 */
#ifdef HAVE_TIMER_CREATE
        fprintf(stderr, "Problem initializing watchdog timer for %ld seconds\n",
                seconds);
/*
 * watchdog_init does not turn on the
 * the signal unless it is successful
 * so we do not have to disable it
 */
#endif
      }
    }

    if (!cmdline_msg) {
      if (cmdline_port_fwd > 0)
        ret = main_forward();
      else
        ret = main_debug();
    } else {
      /* Returning a message is ok */
      ret = 0;
    }

    /* else cmdline printed a message from an option --license and returns */
  }
  cmdline_cleanup();

  if (fp_log) {
      fflush(fp_log);
      fclose(fp_log);
  }
  return ret;
}
