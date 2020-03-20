   tcid, a simple daemon to add 802.1p priorities for the default VLAN
                        (c) 2020 Andreas Steinmetz

--------------------------------------------------------------------------


  A simple way to add 802.1p priorities for the default VLAN for Linux.
=========================================================================

Under Linux it is possible to set the 802.1p priorities for tagged
VLANs with either the 'vconfig' or the 'ip' utility. Unfortunately
there is an oversight for the untagged default VLAN. There is no way
except for creating the pseudo tagged VLAN 0 to set 802.1p priorities.
The latter method introduces on the one hand a slight overhead as
all packets are then tagged and may be problematic if some buggy
network equipment can't handle VLAN id 0 (think mobile laptop).

Well, there is help. tcid uses eBPF to add 802.1p priority to
packets when the user configured priority is not zero. Configuration
is similar to 'vconfig' and 'ip'. The same goes for the mapping
index value. The skb priority is used and thus the SO\_PRIORITY
socket option can be used as usual. If required, tcid can create
a unix domain control socket and the mappings can be changed on
the fly using the tcic utility.

For this to work you need a Linux platform with eBPF support
and at least the following kernel configuration enabled
(the list may not be complete):

CONFIG\_BPF
CONFIG\_BPF\_SYSCALL
CONFIG\_BPF\_JIT
CONFIG\_NET\_CLS\_ACT
CONFIG\_NET\_CLS\_BPF

Furthermore you need libnl (v3) including headers installed.

The tcid source tree includes files that belong to or are created by
ebpf2c, which is located here:

https://github.com/not1337/ebpf2c/

If you want to rebuild everything from scratch, download the ebpf2c
master and unzip the archive in this root directory, then build it.
Then you can do a 'make clean' in this root directory and rebuild
tcid from scratch.

If somebody wonders why 802.1p priority shall be used in the wonderful
new DSCP world - well, yes, DSCP is for IP only and ignores low
latency local non IP traffic. And even then there's encryption
problems - have a look at MACsec and you will find out that
the only way to priorize traffic is via SO\_PRIORITY and 802.1p,
as long as a non MACsec capable switch is used (and I would advise
everybody to use such a switch to prevent access to protected data
via switch backdoors). And no, IPSec is not an option, as long as
IPv6 link local traffic encryption is completely broken (there's some
more bad problems like IP only encryption).

tcid must run as root as some eBPF kernel code erroneously requires
CAP\_SYS\_ADMIN capability instead of CAP\_NET\_ADMIN capability
for networking stuff. And if CAP\_SYS\_ADMIN is required one
can as well just keep root. This is especially true if the code
is dead simple and, if no control socket is used, just waits for
a termination signal. Thus no harm done.

For a quick usage info, start tcid and tcic without options. The
tools should be mostly self explaining.

As a hint make sure that the tc filter preference for tcid is set
such that tcid is the last egress eBPF filter program processed for
the selected interface. Other eBPF programs may e.g. redirect packets
to other interfaces and if tcid would run before these the packets
would be redirected with possibly added VLAN headers... - for this
reason tcid causes termination of the tc filter program processing
which means all other eBPF programs that should run after tcid won't.

If tcid is the only process using egress eBPF for a network device
it is probably easier to use the '-a' option instead of creating
and removing the clsact qdisc qdisc for the device manually.

