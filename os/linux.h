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
#ifndef __DEEBE_LINUX_H
#define __DEEBE_LINUX_H

#include <linux/elf.h>
#include <endian.h>
#include <stdarg.h>
#include <sys/ptrace.h>
#ifdef DEEBE_RELEASE
	/*
	 * To get the cast of normal arguements correct,
	 * default is linux so this is a noop
	*/
	#define PTRACE(a, b, c, d) 	   ptrace((a), (b), (c), (d))
	/*
	 * FreeBSD and Linux swap the 3rd / 4th arg,
	 * default is linux so this is a noop
	 */
	#define PTRACE_GETSET(a, b, c, d) ptrace_linux_getset((a), (b), (c), (d))
#else
	/* Don't know how to implement pass by reference of variable number of arguments */
	//int ptrace_debug(char *reqstr, char *srcname, uint line, int request, pid_t pid, ...);
	//#define PTRACE(a, b, ...) ptrace_debug(#a, __FILE__, __LINE__, (a), (b), __VA_ARGS__)

	void log_ptrace(int request, pid_t pid, char *reqstr,
						char *srcname, uint line,
						int perrno, long int ret);
	/* Below PTRACE() call has loggging whcih is disabling non-interesting things */
	/* Change below code as per your requirement */
	#define PTRACE(a, b, c, d) \
		({ \
			errno = 0; \
			long int ret = ptrace(a, b, c, d); \
			int _perrno  = errno; \
			if ((strcmp("PTRACE_GETREGSET", #a) != 0) && \
				(strcmp("PTRACE_SETREGSET", #a) != 0) && \
				(strcmp("PT_READ_D", #a) != 0) && \
				(strcmp("PT_WRITE_D", #a) != 0) && \
				(strcmp("PTRACE_PEEKUSER", #a) != 0) && \
				(strcmp("PTRACE_POKEUSER", #a) != 0) ) { \
				log_ptrace(a, b, #a, __FILE__, __LINE__, _perrno, ret); \
			} \
			errno = _perrno; \
			ret == 0 ? 0 : ret; \
		})
	#define PTRACE_GETSET(a, b, c, d) ptrace_linux_getset((a), (b), (c), (d))
#endif

/* Linux ptrace returns long */
#define ptrace_return_t long

#define PT_SYSCALL_ARG3 0

void ptrace_os_read_fxreg();
void ptrace_os_write_fxreg();
void ptrace_os_option_set_syscall(pid_t pid);
void ptrace_os_option_set_thread(pid_t pid);
bool ptrace_os_check_syscall(pid_t pid, int *in_out_sig);
bool ptrace_os_wait_new_thread(pid_t *out_pid, int *out_status);
bool ptrace_os_check_new_thread(pid_t pid, int status, pid_t *out_pid);
bool ptrace_os_new_thread(pid_t tid, int status);
void ptrace_os_wait(pid_t tid);
void ptrace_os_continue_others();
int os_thread_kill(int tid, int sig);
long ptrace_os_continue(pid_t pid, pid_t tid, int step, int sig);
int ptrace_os_gen_thread(pid_t pid, pid_t tid);
void ptrace_os_stopped_single(char *str, bool debug);
long ptrace_linux_getset(long request, pid_t pid, int addr, void *data);
bool memory_os_region_info_gdb(uint64_t addr, char *out_buff,
			       size_t out_buf_size);
bool ptrace_os_read_auxv(char *out_buff, size_t out_buf_size, size_t offset,
                         size_t *size);
int elf_os_image(pid_t pid);
pid_t ptrace_os_get_wait_tid(pid_t pid);
int ptrace_os_get_tls_address(int64_t thread, uint64_t lm, uint64_t offset,
			      uintptr_t *tlsaddr);

#ifndef PT_GETREGS
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS (-12)
#endif
#define PT_GETREGS PTRACE_GETREGS
#endif

#ifndef PT_SETREGS
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS (-13)
#endif
#define PT_SETREGS PTRACE_SETREGS
#endif

#ifndef PT_GETFPREGS
#ifndef PTRACE_GETFPREGS
#define PTRACE_GETFPREGS (-14)
#endif
#define PT_GETFPREGS PTRACE_GETFPREGS
#endif

#ifndef PT_SETFPREGS
#ifndef PTRACE_SETFPREGS
#define PTRACE_SETFPREGS (-15)
#endif
#define PT_SETFPREGS PTRACE_SETFPREGS
#endif

#endif /* __DEEBE_LINUX_H */
