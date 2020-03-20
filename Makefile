# This file is part of the tcid project
# 
# (C) 2020 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
$(shell test -d ebpf2c-master)
ifeq ($(.SHELLSTATUS),0)
EBPFSRC=tcid.ebpf
EBPFHDR=ebpf2c-master/ebpf.h
CLEANLST=tcid tcid-ebpf.h ebpf.h tcic
else
EBPFSRC=
EBPFHDR=
CLEANLST=tcid tcic
endif

all: tcid tcic

tcid: tcid.c tcid-ebpf.h ebpf.h
	gcc `pkg-config --cflags libnl-route-3.0` -Wall -Os -s -o tcid tcid.c \
		`pkg-config --libs libnl-route-3.0`

tcic: tcic.c
	gcc -Wall -Os -o tcic tcic.c

tcid-ebpf.h: $(EBPFSRC)
	ebpf2c-master/ebpf2c tcid.ebpf tcid-ebpf.h

ebpf.h: $(EBPFHDR)
	cp ebpf2c-master/ebpf.h ebpf.h

clean:
	rm -f $(CLEANLST)
