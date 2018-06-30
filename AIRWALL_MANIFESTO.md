# The airwall manifesto

## Introduction

Network security vendors have, at an enormous cost and complexity, implemented
ever more complicated middleboxes claiming to offer security. The first of
these devices was a stateless packet filter. Then came stateful packet
filtering, often implemented with NAT. At the same time, simple systems to
detect intrusions into networks called intrusion detection systems evolved
capabilities to actively prevent intrusions, and now they're called intrusion
prevention systems. However, these traditional firewalls were not considered to
be secure enough, so intrusion prevention system technology was merged with
stateful packet filtering into next-generation firewalls.

However, the state of the art emperor has no clothes. It is impossible in a
middlebox to know what happens in an endpoint box. Examples of these problems
are various diverse implementations of the TCP URG bit, most of which violate
the protocol specification by treating one byte of data as out-of-band data,
although the URG bit was intended as an in-band urgent data notification
mechanism. Some implementations can later change the out-of-band byte into an
in-band byte if the application didn't see it as out-of-band data and later a
new byte of out-of-band data came, meaning there are two possibilities: either
the application saw the byte as out-of-band data or as an in-band data. By
using the URG bit 200 times, one can thus cause a need to fork the model of
what happens at the endpoint 200 times, causing the need for 2 to the power of
200 or 1606938044258990275541962092341162602522202993782792835301376 times
larger memory usage if all possible pathways need to be taken into account.

Firewalls have been uncapable of filtering out ransomware and other covert
remote access mechanisms, because authors of such programs know how firewalls
work, and they therefore masquerade the remote access traffic as outbound HTTP
or HTTPS traffic to a server controlled by the attacker.

All of this should make it clear that security should be an endpoint mechanism,
not a mechanism implemented in a middlebox. Endpoint security is not mutually
exclusive with centrally managed security, as the software in a computer can
these days be centrally managed.

Should all firewalls be removed from use, then? Unfortunately, the answer is
no. There is a shortage of IPv4 addresses, and deployment of IPv6 has been very
slow. The address shortage means NAT is required. However, implementations of
NAT should be tuned to prefer connectivity instead of preferring security.

## The airwall

We hypothesize the existence of a new kind of network function, called an
airwall. An airwall is a device the purpose of which is to enable connectivity,
in contrast to a firewall that is a device the purpose of which is to disable
connectivity except whenever explicitly allowed.

### Examples of airwall

Airwall devices already exist. An airwall can be an Ethernet switch, hub,
bridge or an IP router, or any computer configured to do these functions in
software. If passive devices are considered as well, an airwall can also be an
Ethernet cable.

## Protocol detection and AL-NAT

There is nothing new in an airwall, then. However, more interesting than
traditional devices are new kinds of airwall devices that support network
address translation (NAT). We define a new kind of NAT, called application
layer NAT (AL-NAT). This NAT works by first SYN proxying the incoming TCP
connection using SYN cookies, then when the client has verified its intention
to truly open the connection, advertising a limited window to the client.
Everytime a packet is received from the client, it is stored into a buffer and
the buffer contents are investigated. If the protocol of the buffer is detected
successfully and the protocol use contains a DNS name of the server, the
AL-NAT device will then open the other half of the connection, and send the
buffered data to the server. If the other half of the connection cannot be
opened, (RST response to SYN), an RST is created and sent to the client to
close the connection.

## AL-NAT-friendly protocols

In order to be AL-NAT friendly, a protocol must have the following
characteristics:

1. Client must send data without needing the server to send data to the client
first.

2. The data sent by the client must have the DNS name of the server in a
plaintext form.

### TLS with SNI

TLS nowadays has server name indication (SNI), as specified by RFC6066. This is
transmitted as cleartext, meaning any protocol using TLS that has application
level support for SNI works with AL-NAT. TLS also can be detected with
relative ease.

### HTTP

Some sites still use traditional HTTP. However, due to the existence of the
`Host:` header and due to the fact that a HTTP connection starts with the
client's request, traditional HTTP is AL-NAT friendly. HTTP also is easy to
detect.

## Non-AL-NAT-friendly protocols

### Plaintext SMTP, POP3 and IMAP

Plaintext SMTP, POP3 and IMAP connections are opened by a greeting of the
server, meaning these protocols are not AL-NAT-friendly. However, with mail
protocols slowly moving to the use of TLS, it may be the case that they
eventually will be AL-NAT-friendly. A STARTTLS proxy should be reasonably
easy to implement.

### SSH

SSH has reimplemented most of TLS in a custom implementation not used for any
other protocol. This custom implementation unfortunately does not specify the
server name anywhere as plaintext. Therefore, SSH is not AL-NAT-friendly.

## HTTP CONNECT proxy

The HTTP CONNECT method can be automatically detected, and the connection can
be proxied to an internal private host. This way, it is possible to connect to
every single port of every single host, provided the client application
supports using a HTTP CONNECT proxy.

In addition to HTTP CONNECT, a SOCKS4 proxy should be trivial to implement, a
SOCKS4a proxy slightly more complicated but still easy, and SOCKS5 much more
complicated.

## Private realm gateway

The private realm gateway (PRGW) mode of operation is supported. This means an
airwall acts as a DNS server, and allocates a state match rule for every DNS A
query. The state match rule will allow one incoming connection then and will
after that point of time be consumed away. If the state match rule is not
possible to create due to IPv4 address shortage, the DNS query will not be
responded to, causing the DNS client to retry.

## Wildcard connection open

If the protocol of the buffer cannot be detected for any reason, or if the
client is clearly waiting for the server to send a greeting, or if the protocol
detection has been configured off for the TCP destination port, a procedure
called wildcard open is performed. A NAT airwall is a dynamic host
configuration protocol (DHCP) client to the Internet service provider (ISP) and
a DHCP server for the local network, so as a DHCP server, it knows all its
clients. The airwall will send a TCP SYN packet to every single host in its
network. The first successful SYN+ACK response it sees to this TCP SYN packet
will be chosen for the remainder of the connection, and the other connections
are reseted with an RST.

This means that one can set up one server at port 22, and another server at
port 25, without any configuration of the airwall. As long as there is only one
server at a given port in the local network, the airwall will successfully
allow a connection to be opened.

(Note: this wildcard connection open has not been yet implemented in
ldpairwall.)

## UDP hole punching

UDP hole punching will be supported to allow one-to-one communication between
two hosts behind an airwall. This means mapping of UDP ports must not depend on
the destination address.

## Selecting port preferred by the client

For UDP hole punching and also for TCP connections, the local temporary port
selected by the client will be used if at all possible. In some cases, this
port request cannot be satisfied, and in this case, the NAT will translate the
port.

## NAT traversal via Universal Plug and Play (UPnP)

For maximum interoperability with existing software, NAT traversal can be also
supported via:

* Universal Plug and Play (UPnP) using SOAP (ugh!)
* Port Control Protocol (PCP) in RFC6887 style
* NAT Port Mapping Protocol (NAT-PMP) in RFC6886 style

...and nested NAT can be supported in RFC6970 style.

Unfortunately, the UPnP protocols are a bit complicated, meaning implementing
them won't be easy. miniupnp from Github (https://github.com/miniupnp/miniupnp)
can be used as an example.

(Note: these NAT traversal protocols are not yet supported in ldpairwall with
the exception of PCP.)
