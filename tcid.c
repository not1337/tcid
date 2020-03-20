/*
 * This file is part of the tcid project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#define _GNU_SOURCE
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/un.h>
#include <netlink/netlink.h>
#include <netlink/route/rule.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "tcid-ebpf.h"
#include "ebpf.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
#error "kernel headers are too old, this will not work"
#endif

static int tc_clsact_msg(struct nl_sock *nlsr,char *dev,int mode)
{
	int err=-1;
	struct nl_msg *msg;
	struct tcmsg *t;

	if(!(msg=nlmsg_alloc_simple(mode?RTM_NEWQDISC:RTM_DELQDISC,
		mode?NLM_F_EXCL|NLM_F_CREATE:0)))goto err1;
	if(!(t=nlmsg_reserve(msg,sizeof(struct tcmsg),0)))goto err2;
	memset(t,0,sizeof(struct tcmsg));
	t->tcm_family=AF_UNSPEC;
	t->tcm_parent=TC_H_CLSACT;
	t->tcm_handle=TC_H_MAKE(TC_H_CLSACT,0);
	if(!(t->tcm_ifindex=if_nametoindex(dev)))goto err2;
	NLA_PUT_STRING(msg,TCA_KIND,"clsact");
	if(nl_send_auto(nlsr,msg)<0)goto err2;
	if(nl_recvmsgs_default(nlsr)<0)goto err2;
	err=0;

nla_put_failure:
err2:	nlmsg_free(msg);
err1:	return err;
}

static int tc_bpfflt_msg(struct nl_sock *nlsr,char *dev,int mode,int dir,
	int prio,int fd,char *name)
{
	int err=-1;
	struct nl_msg *msg;
	struct tcmsg *t;
	struct nlattr *n;

	if(!(msg=nlmsg_alloc_simple(mode?RTM_NEWTFILTER:RTM_DELTFILTER,
		mode?NLM_F_EXCL|NLM_F_CREATE:0)))goto err1;
	if(!(t=nlmsg_reserve(msg,sizeof(struct tcmsg),0)))goto err2;
	memset(t,0,sizeof(struct tcmsg));
	t->tcm_family=AF_UNSPEC;
	t->tcm_parent=TC_H_MAKE(TC_H_CLSACT,
		dir?TC_H_MIN_EGRESS:TC_H_MIN_INGRESS);
	t->tcm_info=TC_H_MAKE(prio<<16,htobe16(mode?ETH_P_ALL:0));
	if(!(t->tcm_ifindex=if_nametoindex(dev)))goto err2;
	if(mode)
	{
		NLA_PUT_STRING(msg,TCA_KIND,"bpf");
		if(!(n=nla_nest_start(msg,TCA_OPTIONS)))goto err2;
		NLA_PUT_U32(msg,TCA_BPF_FD,fd);
		NLA_PUT_STRING(msg,TCA_BPF_NAME,name);
		NLA_PUT_U32(msg,TCA_BPF_FLAGS_GEN,TCA_CLS_FLAGS_SKIP_HW);
		NLA_PUT_U32(msg,TCA_BPF_FLAGS,TCA_BPF_FLAG_ACT_DIRECT);
		nla_nest_end(msg,n);
	}
	if(nl_send_auto(nlsr,msg)<0)goto err2;
	if(nl_recvmsgs_default(nlsr)<0)goto err2;
	err=0;

nla_put_failure:
err2:	nlmsg_free(msg);
err1:	return err;
}

static int jitenable(void)
{
	int fd;

	if((fd=open("/proc/sys/net/core/bpf_jit_enable",O_WRONLY|O_CLOEXEC))
		==-1)return -1;
	if(write(fd,"1\n",2)!=2)
	{
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
"Usage: tcid [<options>] <conf> [<conf> [...]]\n\n"
"<conf>                  <socket-priority>:<8021p-priority>\n"
"<socket-priority>       0-15\n"
"<8021p-priority>        0-7\n\n"
"Options:\n\n"
"-i <interface>          network device, e.g. eth0, mandatory\n"
"-f <pid-file>           pid file for daemon mode, default /run/tcid.pid\n"
"-s <control-socket>     optional listening unix domain socket path\n"
"-p <filter-priority>    tc filter preference, default 32767\n"
"-j                      enable BPF JIT (recommended)\n"
"-a                      create and remove clsact qdisc for device\n"
"-d                      enable daemon mode\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	struct nl_sock *nlsr;
	int sfd;
	int mapfd;
	int bpf;
	int c;
	int n;
	int s=-1;
	int jit=0;
	int clsact=0;
	int prio=32767;
	int dmn=0;
	int err=0;
	uint32_t key;
	uint32_t map[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	long v;
	char *end;
	char *ptr;
	char *dev=NULL;
	char *fn="/run/tcid.pid";
	char *cs=NULL;
	FILE *fp;
	struct pollfd p[3];
	sigset_t set;
	struct stat stb;
	struct sockaddr_un a;
	unsigned char data[16];

	while((c=getopt(argc,argv,"jai:p:df:s:"))!=-1)switch(c)
	{
	case 'j':
		jit=1;
		break;

	case 'a':
		clsact=1;
		break;

	case 'i':
		dev=optarg;
		break;

	case 'p':
		if((v=strtol(optarg,&end,0))<0||v>65535||*end)usage();
		prio=(int)v;
		break;

	case 'd':
		dmn=1;
		break;

	case 'f':
		fn=optarg;
		break;

	case 's':
		cs=optarg;
		break;

	default:usage();
	}

	if(!dev)usage();

	for(;optind<argc;optind++)
	{
		if(!(ptr=strchr(argv[optind],':')))usage();
		else *ptr++=0;
		if(!argv[optind][0]||!*ptr)usage();
		if((v=strtoll(argv[optind],&end,0))<0||v>15||*end)usage();
		key=(uint32_t)v;
		if((v=strtoll(ptr,&end,0))<0||v>7||*end)usage();
		map[key]=(uint32_t)v;
	}

	sigfillset(&set);
	sigprocmask(SIG_SETMASK,&set,NULL);
	sigemptyset(&set);
	sigaddset(&set,SIGINT);
	sigaddset(&set,SIGHUP);
	sigaddset(&set,SIGTERM);
	sigaddset(&set,SIGQUIT);
	if((sfd=signalfd(-1,&set,SFD_NONBLOCK|SFD_CLOEXEC))==-1)
	{
		perror("signalfd");
		goto err1;
	}

	if(cs)
	{
		if((s=socket(PF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0))
			==-1)
		{
			perror("socket");
			goto err2;
		}
		memset(&a,0,sizeof(a));
		a.sun_family=AF_UNIX;
		strncpy(a.sun_path,cs,sizeof(a.sun_path)-1);
		a.sun_path[sizeof(a.sun_path)-1]=0;
		if(!lstat(a.sun_path,&stb))
		{
			if(!S_ISSOCK(stb.st_mode))
			{
				fprintf(stderr,"%s: not a socket\n",a.sun_path);
				goto err3;
			}
			if(unlink(a.sun_path))
			{
				perror("unlink");
				goto err3;
			}
		}
		c=umask(077);
		if(bind(s,(struct sockaddr *)(&a),sizeof(a)))
		{
			perror("bind");
			goto err3;
		}
		umask(c);
		if(listen(s,10))
		{
			perror("listen");
			goto err4;
		}
	}

	if(jit)if(jitenable())
	{
		fprintf(stderr,"can't enable ebpf jit\n");
		goto err4;
	}

	if(!(nlsr=nl_socket_alloc()))
	{
		fprintf(stderr,"can't allocate netlink socket\n");
		goto err4;
	}

	if(nl_connect(nlsr,NETLINK_ROUTE)<0)
	{
		fprintf(stderr,"can't open netlink socket\n");
		goto err5;
	}

	if(clsact)if(tc_clsact_msg(nlsr,dev,1))
	{
		fprintf(stderr,"can't add clsact qdisc\n");
		goto err6;
	}

	if((mapfd=bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(u_int32_t),
		sizeof(u_int32_t),16))==-1)
	{
		fprintf(stderr,"can't create ebpf map\n");
		goto err7;
	}

	for(key=0;key<16;key++)if(bpf_update_elem(mapfd,&key,&map[key],BPF_ANY))
	{
		fprintf(stderr,"can't preset ebpf map\n");
		goto err8;
	}

	tc_8021p_push[TC_8021P_MAP_L].imm=mapfd;
	tc_8021p_push[TC_8021P_MAP_H].imm=0;
	if((bpf=bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS,tc_8021p_push,
		TC_8021P_PUSH_SIZE,"GPL",65536))==-1)
	{
		fprintf(stderr,"can't load ebpf program\n");
		goto err8;
	}

	if(tc_bpfflt_msg(nlsr,dev,1,1,prio,bpf,"tcid-egress-vlan-push"))
	{
		fprintf(stderr,"can't activate ebpf program\n");
		goto err9;
	}

	if(dmn)
	{
		if(daemon(0,0))
		{
			perror("daemon");
			goto err10;
		}
		if(!stat(fn,&stb))if(!S_ISREG(stb.st_mode))fn=NULL;
		if(fn)
		{
			if((fp=fopen(fn,"we")))
			{
				fprintf(fp,"%d\n",getpid());
				fclose(fp);
			}
			else fn=NULL;
		}
	}
	else fn=NULL;

	err=0;

	p[0].fd=sfd;
	p[0].events=POLLIN;
	p[1].fd=s;
	p[1].events=POLLIN;
	p[1].revents=0;
	p[2].events=POLLIN;
	p[2].revents=0;

	c=-1;
	n=(s==-1?1:2);

	while(1)
	{
		if(poll(p,n,c!=-1?100:-1)<1)
		{
			if(c!=-1)goto clscln;
			continue;
		}
		if(p[0].revents&POLLIN)break;
		if(p[1].revents&POLLIN)
		{
			if(c!=-1)close(c);
			c=accept4(s,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
			if(c!=-1)
			{
				p[2].fd=c;
				n=3;
			}
			else goto noacc;
			continue;
		}
		if(p[2].revents&POLLIN)
		{
			if(read(c,data,sizeof(data))!=sizeof(data))goto err;
			for(key=0;key<16;key++)
				if((data[key]>7&&data[key]!=0xff))goto err;
			for(key=0;key<16;key++)if(data[key]!=0xff)
				map[key]=data[key];
			for(key=0;key<16;key++)if(bpf_update_elem(mapfd,&key,
				&map[key],BPF_ANY))
			{
err:				data[0]=0;
				goto common;
			}
			data[0]=1;
common:			key=write(c,data,1);
clscln:			close(c);
			c=-1;
noacc:			n=2;
			p[2].revents=0;
		}
	}

	if(fn)unlink(fn);

err10:	tc_bpfflt_msg(nlsr,dev,0,1,prio,bpf,"tcid-egress-vlan-push");
err9:	close(bpf);
err8:	close(mapfd);
err7:	if(clsact)tc_clsact_msg(nlsr,dev,0);
err6:	nl_close(nlsr);
err5:	nl_socket_free(nlsr);
err4:	if(cs)unlink(a.sun_path);
err3:	if(cs)close(s);
err2:	close(sfd);
err1:	return err;
}
