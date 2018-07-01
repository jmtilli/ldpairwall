# Support for RFCs

The following RFCs are supported:

1. RFC 768
    * of course
2. RFC 791
    * of course
3. RFC 792
    * of course
4. RFC 793
    * of course
5. RFC 826
    * of course
6. RFC 894
    * of course
7. RFC 1034
    * for RGW interoperation with DNS
8. RFC 1035
    * for RGW interoperation with DNS
9. RFC 1122
    * mostly
10. RFC 1323
11. RFC 2018
12. RFC 2246
    * for TLS 1.0
13. RFC 2267
14. RFC 2827
15. RFC 4346
    * for TLS 1.1
16. RFC 4787
    * REQ 1: supported
    * REQ 2: supported, as always only one IPv4 address is used
    * REQ 3: supported
    * REQ 4: not supported, but this was only RECOMMENDED
    * REQ 5: supported, 5 minute timer is used as RECOMMENDED
    * REQ 6: supported, refresh for outbound and inbound is True
    * REQ 7: unknown, TODO: investigate
    * REQ 8: supported
    * REQ 9: supported
    * REQ 10: supported, no ALGs used
    * REQ 11: supported, the behaviour is deterministic
    * REQ 12: supported, ICMP does not terminate any mapping
    * REQ 13: not supported, TODO: implement, however: if uplink and downlink have same MTU, it works
    * REQ 14: not supported, TODO: implement, however: fragmentation is rare
17. RFC 5246
    * for TLS 1.2
18. RFC 5382
    * REQ 1: supported
    * REQ 2: unknown, TODO: investigate
    * REQ 3: supported
    * REQ 4: probably not supported
    * REQ 5: supported
    * REQ 6: supported, no ALGs used
    * REQ 7: supported
    * REQ 8: supported
    * REQ 9: supported
    * REQ 10: supported
19. RFC 5508
    * REQ 1: supported for ping
    * REQ 2: supported
    * REQ 3: not supported, TODO: implement; however, this is SHOULD, not MUST
    * REQ 4: supported
    * REQ 5: supported
    * REQ 6: ought to be supported, but however, ICMP error in response to ICMP may not be
    * REQ 7: ought to be supported
    * REQ 8: not supported, TODO: implement
    * REQ 9: this is MAY, so not a problem
    * REQ 10: ought to be supported
    * REQ 11: MAY drop, ok
20. RFC 6066
    * for TLS + SNI
21. RFC 6887
    * for PCP
22. RFC 7230
    * for HTTP/1.1
23. RFC 7231
    * for HTTP/1.1 CONNECT
24. RFC 7857
    * TCP state machine differs from RFC 7857, but however, this is SHOULD, not MUST
    * most other updates / clarifications are supported

The following RFCs should perhaps be supported in the future:

1. RFC 1928
    * for SOCKS proxy
2. RFC 2131
    * for DHCP
2. RFC 3360
3. RFC 5135
