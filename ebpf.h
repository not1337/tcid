/*
 * This file is part of the ebpf2c project
 *
 * (C) 2019 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the CC BY version 2.0 or, at
 * your choice, any later version of this license.
 *
 * This header is a convenience header as long as the bpf syscall is
 * not suported by standard libraries.
 */

#ifndef _EBPF_H_INCLUDED
#define _EBPF_H_INCLUDED

#define _GNU_SOURCE
#include <linux/bpf.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>

/*
 * See bpf(2) man page for details, except the "logsize" parameter of
 * bpf_prog_load. Either use 0 for no debug output or a real large
 * buffer size (e.g. 32K) for error debug output. Specifying as too
 * small log buffer will cause the load of an otherwise good program
 * to fail.
 */

static inline int bpf_create_map(enum bpf_map_type map_type,
	unsigned int key_size,unsigned int value_size,unsigned int max_entries)
{
	union bpf_attr attr=
	{
		.map_type    = map_type,
		.key_size    = key_size,
		.value_size  = value_size,
		.max_entries = max_entries
	};

	return syscall(SYS_bpf,BPF_MAP_CREATE,&attr,sizeof(attr));
}

static inline int bpf_lookup_elem(int fd,const void *key,void *value)
{
	union bpf_attr attr=
	{
		.map_fd = fd,
		.key    = ((u_int64_t)((unsigned long)key)),
		.value  = ((u_int64_t)((unsigned long)value)),
	};

	return syscall(SYS_bpf,BPF_MAP_LOOKUP_ELEM,&attr,sizeof(attr));
}

static inline int bpf_update_elem(int fd,const void *key,const void *value,
	u_int64_t flags)
{
	union bpf_attr attr=
	{
		.map_fd = fd,
		.key    = ((u_int64_t)((unsigned long)key)),
		.value  = ((u_int64_t)((unsigned long)value)),
		.flags  = flags,
	};

	return syscall(SYS_bpf,BPF_MAP_UPDATE_ELEM,&attr,sizeof(attr));
}

static inline int bpf_delete_elem(int fd,const void *key)
{
	union bpf_attr attr=
	{
		.map_fd = fd,
		.key    = ((u_int64_t)((unsigned long)key)),
	};

	return syscall(SYS_bpf,BPF_MAP_DELETE_ELEM,&attr,sizeof(attr));
}

static inline int bpf_get_next_key(int fd,const void *key,void *next_key)
{
	union bpf_attr attr=
	{
		.map_fd   = fd,
		.key      = ((u_int64_t)((unsigned long)key)),
		.next_key = ((u_int64_t)((unsigned long)next_key)),
	};

	return syscall(SYS_bpf,BPF_MAP_GET_NEXT_KEY,&attr,sizeof(attr));
}

static int bpf_prog_load(enum bpf_prog_type type,const struct bpf_insn *insns,
	int insn_cnt,const char *license,int logsize)
{
	int r;
	char *ptr;

	union bpf_attr attr=
	{
		.prog_type = type,
		.insns     = ((u_int64_t)((unsigned long)insns)),
		.insn_cnt  = insn_cnt,
		.license   = ((u_int64_t)((unsigned long)license)),
	};

	if(logsize)
	{
		if(!(ptr=malloc(logsize)))return -1;
		*ptr=0;
		attr.log_buf=(u_int64_t)((unsigned long)ptr);
		attr.log_size=logsize;
		attr.log_level=1;
	}

	if((r=syscall(SYS_bpf,BPF_PROG_LOAD,&attr,sizeof(attr)))==-1&&logsize)
	{
		r=errno;
		fprintf(stderr,"BPF ERROR TRACE:\n================\n%s\n",ptr);
		free(ptr);
		errno=r;
		return -1;
	}

	if(logsize)free(ptr);

	return r;
}

#endif
