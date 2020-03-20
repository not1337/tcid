/*
 * This file is part of the tcid project
 *
 * (C) 2020 Andreas Steinmetz, ast@domdv.de
 * The contents of this file is licensed under the GPL version 2 or, at
 * your choice, any later version of this license.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>

static void usage()
{
	fprintf(stderr,
		"Usage: tcic -s <control-socket> <conf> [<conf> [...]]\n\n"
		"<conf>                  <socket-priority>:<8021p-priority>\n"
		"<socket-priority>       0-15\n"
		"<8021p-priority>        0-7\n\n"
		"-s <control-socket>     tcid unix domain socket pathname\n");
	exit(1);
}

int main(int argc,char *argv[])
{
	int i;
	int s;
	long v;
	char *cs=NULL;
	char *end;
	char *ptr;
	struct sockaddr_un a;
	unsigned char data[16];

	memset(data,0xff,sizeof(data));

	while((i=getopt(argc,argv,"s:"))!=-1)switch(i)
	{
	case 's':
		cs=optarg;
		break;

	default:usage();
	}

	if(!cs||optind==argc)usage();

	for(;optind<argc;optind++)
	{
		if(!(ptr=strchr(argv[optind],':')))usage();
		*ptr++=0;
		if(!argv[optind][0]||!*ptr)usage();
		if((v=strtol(argv[optind],&end,0))<0||v>15||*end)usage();
		i=(int)v;
		if((v=strtol(ptr,&end,0))<0||v>7||*end)usage();
		data[i]=(unsigned char)v;
	}

	if((s=socket(PF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0))==-1)
	{
		perror("socket");
		return 1;
	}

	memset(&a,0,sizeof(a));
	a.sun_family=AF_UNIX;
	strncpy(a.sun_path,cs,sizeof(a.sun_path)-1);
	a.sun_path[sizeof(a.sun_path)-1]=0;
	if(connect(s,(struct sockaddr *)(&a),sizeof(a)))
	{
		perror("connect");
		close(s);
		return 1;
	}

	if(write(s,data,sizeof(data))!=sizeof(data))
	{
		perror("write");
		close(s);
		return 1;
	}

	if(read(s,data,1)!=1)
	{
		perror("read");
		close(s);
		return 1;
	}

	close(s);

	if(!data[0])
	{
		fprintf(stderr,"failed\n");
		return 1;
	}

	return 0;
}
