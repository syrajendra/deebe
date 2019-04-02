/*
 * Copyright (c) 2012-2016, Juniper Networks, Inc.
 * All rights reserved.
 *
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

#ifndef DEEBE_GLOBAL_H
#define DEEBE_GLOBAL_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "gdb_interface.h"
#include "version.h"
#include "util.h"
#include "macros.h"

#define REG_MAX_SIZE 0x1000

#ifndef DECL_GLOBAL

/* cmdline */
extern char *cmdline_net;
extern char *cmdline_net_fwd;
extern long cmdline_port;
extern long cmdline_port_fwd;
extern int cmdline_argc;
extern char **cmdline_argv;
extern pid_t cmdline_pid;
extern char *cmdline_program_name;
extern bool cmdline_once;
extern long cmdline_watchdog_minutes;
extern bool cmdline_silence_memory_read_errors;
extern bool cmdline_msg;

/* network */
extern int network_listen_sd;
extern int network_client_sd;
extern int network_fwd_sd;
extern struct sockaddr_in network_address;
extern struct sockaddr_in network_address_fwd;
extern struct sockaddr_in network_client_address;
extern socklen_t network_client_address_size;
extern uint8_t *network_out_buffer;
extern uint8_t *network_in_buffer;
extern size_t network_out_buffer_size;
extern size_t network_out_buffer_current;
extern size_t network_out_buffer_total;
extern size_t network_in_buffer_size;
extern size_t network_in_buffer_current;
extern size_t network_in_buffer_total;
/* gdb interface */
extern gdb_target *gdb_interface_target;

extern FILE *fp_log;

extern bool gDebugeeRunning;

/* host signal mappings */
extern int host_signal_to_gdb(int sig);
extern int host_signal_from_gdb(int gdb);

extern int gPipeStdout[2];


extern void symbol_cleanup();
extern void ptrace_cleanup();
extern void buffer_cleanup();
extern void thread_db_cleanup();

#else

/* cmdline */
/*@null@*/ char *cmdline_net = NULL;
/*@null@*/ char *cmdline_net_fwd = NULL;
long cmdline_port = -1;
long cmdline_port_fwd = -1;
int cmdline_argc = 0;
/*@null@*/ char **cmdline_argv = NULL;
pid_t cmdline_pid = 0;
/*@null@*/ char *cmdline_program_name = NULL;
bool cmdline_once = false;
long cmdline_watchdog_minutes = -1;
bool cmdline_silence_memory_read_errors = false;
bool cmdline_msg = false;

/* network */
int network_listen_sd = -1;
int network_client_sd = -1;
int network_fwd_sd = -1;
struct sockaddr_in network_address = {0};
struct sockaddr_in network_client_address = {0};
struct sockaddr_in network_address_fwd = {0};
socklen_t network_client_address_size = sizeof(struct sockaddr_in);
uint8_t *network_out_buffer = NULL;
uint8_t *network_in_buffer = NULL;
size_t network_out_buffer_size = 0;
size_t network_out_buffer_current = 0;
size_t network_out_buffer_total = 0;
size_t network_in_buffer_size = 0;
size_t network_in_buffer_current = 0;
size_t network_in_buffer_total = 0;
/* gdb interface */
/*@null@*/ gdb_target *gdb_interface_target = NULL;

FILE *fp_log = NULL;

bool gDebugeeRunning = true;

int gPipeStdout[2] = {
    -1, -1,
};


void symbol_cleanup();
void ptrace_cleanup();
void buffer_cleanup();
void thread_db_cleanup();

#endif /* DECL_GLOBAL */
#endif /* DEEBE_GLOBAL_H */
