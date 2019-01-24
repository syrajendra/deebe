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
#ifndef DEEBE_THREAD_DB_PRIV_H
#define DEEBE_THREAD_DB_PRIV_H

#include <config.h>
#ifdef HAVE_THREAD_DB_H
#include <unistd.h>
#include <thread_db.h>

struct gdb_target_s;
extern int initialize_thread_db(pid_t pid, struct gdb_target_s *t);
extern void cleanup_thread_db();
extern int thread_db_get_tls_address(int64_t thread, uint64_t lm,
				     uint64_t offset, uintptr_t *tlsaddr);

struct ps_prochandle
{
  pid_t pid;
  struct gdb_target_s *target;
};

#ifdef __linux__
typedef enum
{
  PS_OK,		/* Generic "call succeeded".  */
  PS_ERR,		/* Generic error. */
  PS_BADPID,	/* Bad process handle.  */
  PS_BADLID,	/* Bad LWP identifier.  */
  PS_BADADDR,	/* Bad address.  */
  PS_NOSYM,		/* Could not find given symbol.  */
  PS_NOFREGS	/* FPU register set not available for given LWP.  */
} ps_err_e;

td_err_e (*td_init_fptr) (void);
td_err_e (*td_ta_new_fptr) (struct ps_prochandle * ps,
		    				td_thragent_t **ta);
td_err_e (*td_ta_map_lwp2thr_fptr) (const td_thragent_t *ta,
			    					lwpid_t lwpid,
			    					td_thrhandle_t *th);
td_err_e (*td_ta_thr_iter_fptr) (const td_thragent_t *ta,
			 					td_thr_iter_f *callback,
			 					void *cbdata_p,
			 					td_thr_state_e state,
			 					int ti_pri,
			 					sigset_t *ti_sigmask_p,
			 					unsigned int ti_user_flags);
td_err_e (*td_thr_get_info_fptr) (const td_thrhandle_t *th,
			  						td_thrinfo_t *infop);
td_err_e (*td_thr_tls_get_addr_fptr) (const td_thrhandle_t *th,
			      						psaddr_t map_address,
			      						size_t offset,
			      						psaddr_t *address);
td_err_e (*td_thr_tlsbase_fptr) (const td_thrhandle_t *th,
			 					unsigned long int modid,
			 					psaddr_t *base);
const char ** (*td_symbol_list_fptr) (void);
td_err_e (*td_ta_delete_fptr) (td_thragent_t *ta);
#endif

#endif
#endif
