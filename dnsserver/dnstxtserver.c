#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "dnshdr.h"

int main(int argc, char **argv)
{
  char pkt[1536];
  char answer[1536];
  int sockfd;
  struct sockaddr_in sin = {};
  struct sockaddr_storage ss = {};
  socklen_t sslen;
  ssize_t pktsize;
  int i;
  uint16_t remcnt;
  uint16_t aoff, aremcnt;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    perror("socket failed");
    abort();
  }
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(53);
  if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    perror("bind failed");
    abort();
  }
  for (;;)
  {
    char nambuf[8192] = {0};
    uint16_t off, qtype, qclass;
    sslen = sizeof(ss);
    pktsize = recvfrom(sockfd, pkt, sizeof(pkt), 0, (struct sockaddr*)&ss, &sslen);

    dns_set_id(answer, dns_id(pkt));
    dns_set_qr(answer, 1);
    dns_set_opcode(answer, dns_opcode(pkt));
    dns_set_opcode(answer, dns_opcode(pkt));
    dns_set_aa(answer, 1);
    dns_set_aa(answer, 1);
    dns_set_tc(answer, 0);
    dns_set_rd(answer, 0);
    dns_set_ra(answer, 0);
    dns_set_z(answer);
    dns_set_rcode(answer, 0);
    dns_set_qdcount(answer, 0);
    dns_set_ancount(answer, 0);
    dns_set_nscount(answer, 0);
    dns_set_arcount(answer, 0);

    //dns_next_init_an(answer, &aoff, &aremcnt);
    dns_next_init_qd(answer, &aoff, &remcnt, pktsize);

    dns_next_init_qd(pkt, &off, &remcnt, pktsize);
    while (dns_next(pkt, &off, &remcnt, pktsize, nambuf, sizeof(nambuf), &qtype, &qclass) == 0)
    {
      dns_set_qdcount(answer, dns_qdcount(answer) + 1);
      dns_put_next_qr(answer, &aoff, &aremcnt, sizeof(answer), nambuf, qtype, qclass);
    }

    dns_next_init_qd(pkt, &off, &remcnt, pktsize);
    while (dns_next(pkt, &off, &remcnt, pktsize, nambuf, sizeof(nambuf), &qtype, &qclass) == 0)
    {
      if (qclass == 1 && qtype == 1 && strcmp(nambuf, "foo.lan") == 0)
      {
        printf("%s\n", nambuf);
        dns_set_ancount(answer, dns_ancount(answer) + 1);
        dns_put_next(answer, &aoff, &aremcnt, sizeof(answer), "foo.lan", qtype, qclass, 0,
                     4, "\x01\x02\x03\x04");
      }
      if (qclass == 1 && qtype == 1 && strcmp(nambuf, "foo2.lan") == 0)
      {
        printf("%s\n", nambuf);
        dns_set_ancount(answer, dns_ancount(answer) + 1);
        dns_put_next(answer, &aoff, &aremcnt, sizeof(answer), "foo2.lan", 5, 1, 0,
                     10, "\04foo3\03lan\00");
        dns_set_ancount(answer, dns_ancount(answer) + 1);
        dns_put_next(answer, &aoff, &aremcnt, sizeof(answer), "foo3.lan", qtype, qclass, 0,
                     4, "\x01\x02\x03\x04");
      }
      if (qclass == 1 && qtype == 16 && strcmp(nambuf, "_cgtp.foo2.lan") == 0)
      {
        char *str = "\024foo.lan!10.150.1.101";
        printf("%s\n", nambuf);
        dns_set_ancount(answer, dns_ancount(answer) + 1);
        dns_put_next(answer, &aoff, &aremcnt, sizeof(answer), "_cgtp.foo2.lan", 5, 1, 0,
                     16, "\05_cgtp\04foo3\03lan\00");
        dns_set_ancount(answer, dns_ancount(answer) + 1);
        dns_put_next(answer, &aoff, &aremcnt, sizeof(answer), "_cgtp.foo3.lan", qtype, qclass, 0,
                     strlen(str), str);
      }
    }

    if (sendto(sockfd, answer, aoff, 0, (struct sockaddr*)&ss, sslen) < 0)
    {
      printf("sendto failed\n");
    }

    printf("Recvd and responded\n");
  }
  return 0;
}
