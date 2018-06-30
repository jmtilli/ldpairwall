# ldpairwall

ldpairwall is a Linux user space application layer NAT middlebox for IPv4 using
L Data Plane (LDP).

The SYN proxy in the application layer NAT makes hybrid use of SYN cookies and
SYN cache. It also makes hybrid use of TCP sequence numbers and TCP timestamp
option. The SYN cookie implementation is particularly modern, and is expected
to lead to better performance, security and compatibility than most SYN cookie
implementations out there. That's assuming SYN cookies are needed, as the SYN
proxy uses also SYN cache, in contrast to the Linux iptables in-kernel SYN
proxy that merely uses SYN cookies.

Multithreading is not supported yet, but in the future will be, provided that
the network interface card (NIC) has multiple queues. Actually, the NIC queue
count needs to be adjusted to the same number as the number of threads before
starting up (ldpairwall does it automatically).

Performance should be great. With any recent good CPU, even as few as three
threads should achieve 40 Gbps link saturation when transferring large files.
That's when multithreading will be supported (it's not yet supported).

There is only one supported variant of airwall: ldpairwall. ldpairwall can be
used with netmap (using the `netmap:` prefix on inteface names) or without
netmap (by leaving out the prefix). For highest performance, the `netmap:`
prefixed use of ldpairwall is required. This requires netmap to compile the
sources and also the netmap kernel module must be installed.

# Prerequisites

You need to have flex and bison installed in order to compile this project.
Also, needless to say, compiler tools and GNU make must be available. To
actually communicate with real network interfaces, you also need netmap for the
highest performance possible, but more on that later. If low performance is
enough, ldpairwall can be used instead of nmairwall in the socket mode.

Also, pptk submodule must be initialized and updated.

```
git submodule init
git submodule update
```

# Compilation

To compile, type `make -j4` where the number after `-j` is the number of cores.

To run unit tests, run `make unit`. Note that using `-j` with `make unit` is
not recommended. Note also that this early development version has failing unit
tests.

# Netmap support

To compile with netmap support, edit the file `opts.mk` (generated as empty
file automatically after successful `make`), and add the lines:

```
WITH_NETMAP=yes
NETMAP_INCDIR=/home/YOURUSERNAME/netmap/sys
```

But before this, you need to clone netmap:

```
cd /home/YOURUSERNAME
git clone https://github.com/luigirizzo/netmap
cd netmap
./configure --no-drivers
make
insmod ./netmap.ko
```

Successfully compiling netmap requires that you have your kernel headers
installed.

# Netmap drivers

If you want higher performance, you can compile netmap with drivers:

```
cd /home/YOURUSERNAME
rm -rf netmap
git clone https://github.com/luigirizzo/netmap
cd netmap
./configure
make
rmmod netmap
rmmod ixgbe
rmmod i40e
insmod ./netmap.ko
insmod ./ixgbe-5.0.4/src/ixgbe.ko
insmod ./i40e-2.0.19/src/i40e.ko
```

Adjust paths as needed to have the correct version of the driver.

# Netmap with full kernel sources

Some netmap drivers require full kernel sources. On Ubuntu 16.04 LTS, they
can be installed in the following way: first, uncomment deb-src lines in
`/etc/apt/sources.list`. Then, type these commands:

```
cd /home/YOURUSERNAME
apt-get update
apt-get source linux-image-$(uname -r)
rm -rf netmap
git clone https://github.com/luigirizzo/netmap
cd netmap
./configure --kernel-sources=/home/WHATEVER/linux-hwe-4.8.0
rmmod netmap
insmod ./netmap.ko
```

Then, you may load for example netmap specific veth driver:

```
cd /home/YOURUSERNAME/netmap
rmmod veth
insmod ./veth.ko
```

# Testing with real network interfaces

Let's assume you have eth0 and eth1 inserted as an inline pair to an Ethernet
network. You want to NAT traffic between eth0 and eth1 and SYN proxy incoming
connections from eth1 into eth0.

First, you must start ldpairwall:
```
./airwall/ldpairwall netmap:eth0 netmap:eth1
```

Note that the order interfaces are specified matters. The first is the LAN
interface. The second is the WAN interface. Only connections from WAN to LAN
use application layer NAT, whereas connections from LAN to WAN use regular NAT.

If you don't have netmap installed or the netmap kernel module loaded, you may
do instead:
```
./airwall/ldpairwall eth0 eth1
```

...but note that in this variant, you must before remove any assigned addresses
from the eth0 and eth1 interfaces.

# Testing with network namespaces

Execute:

```
mkdir -p /etc/netns/ns1
echo "nameserver 10.150.2.100" > /etc/netns/ns1/resolv.conf
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
ifconfig veth0 up
ifconfig veth1 up
ifconfig veth2 up
ifconfig veth3 up
ethtool -K veth0 rx off tx off tso off gso off gro off lro off
ethtool -K veth1 rx off tx off tso off gso off gro off lro off
ethtool -K veth2 rx off tx off tso off gso off gro off lro off
ethtool -K veth3 rx off tx off tso off gso off gro off lro off
ip netns add ns1
ip netns add ns2
ip link set veth0 netns ns1
ip link set veth3 netns ns2
ip netns exec ns1 ip addr add 10.150.2.1/24 dev veth0
ip netns exec ns2 ip addr add 10.150.1.101/24 dev veth3
ip netns exec ns1 ip link set veth0 up
ip netns exec ns2 ip link set veth3 up
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip route add default via 10.150.1.1
```

Then run in one terminal window and leave it running:
```
./airwall/ldpairwall veth2 veth1
```

Or you may alternatively run:
```
./airwall/ldpairwall netmap:veth2 netmap:veth1
```

Then, execute netcat in two terminal windows:
```
ip netns exec ns1 nc -v -v -v -l -p 1234
ip netns exec ns2 nc -v -v -v 10.150.2.1 1234
```

Type something to both windows and see that the counterparty gets the same
text.

Try also in other direction in two terminal windows:
```
ip netns exec ns2 nc -v -v -v -l -p 1234
ip netns exec ns1 nc -v -v -v 10.150.2.100 1234
```

...but this other direction requires application level NAT, meaning connection
will be successful only after protocol and host has been detected. To allow
protocol and host detection, type this into netcat client:

```
GET / HTTP/1.1
Host: www1.example.com
```

To test the integrated HTTP CONNECT proxy, try this:
```
ip netns exec ns2 nc -v -v -v -l -p 1234
ip netns exec ns1 nc -v -v -v 10.150.2.100 4321
```

...and type this into the client:
```
CONNECT www1.example.com:1234 HTTP/1.1

```

After typing two newlines after CONNECT, you should see:
```
HTTP/1.1 200 OK

```

...and now you have a HTTP connection to the machine's port 1234 even though
you originally connected to a different port.

Test also the RGW mode of operation by using SSH, a non-AL-NAT-friendly
protocol:
```
ip netns exec ns2 nc -v -v -v -l -p 22
ip netns exec ns1 nc -v -v -v ssh.example.com 22
```

PCP client can also be used to open ports, for UDP:
```
ip netns exec ns2 ./airwall/pcpclient udp 40000 40000 86400
ip netns exec ns2 nc -v -v -v -u -l -p 40000
ip netns exec ns1 nc -v -v -v -u 10.150.2.100 40000
```

Or for TCP:
```
ip netns exec ns2 ./airwall/pcpclient tcp 40000 40000 86400
ip netns exec ns2 nc -v -v -v -l -p 40000
ip netns exec ns1 nc -v -v -v 10.150.2.100 40000
```
