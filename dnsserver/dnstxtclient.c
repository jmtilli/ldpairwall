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
  char querya[1536] = {0};
  char querytxt[1536] = {0};
  char answer[1536] = {0};
  int sockfd;
  struct sockaddr_in sin = {};
  struct sockaddr_in ss = {};
  struct sockaddr_storage ss2 = {};
  socklen_t sslen, ss2len;
  uint16_t remcnt;
  uint16_t qoffa, qofftxt;
  uint16_t txid = rand()&0xFFFF;
  int answer_a = 0, answer_txt = 0;
  int txida;
  int txidtxt;
  int retrya = 0, retrytxt = 0;
  struct timeval tv;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    perror("socket failed");
    abort();
  }

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
    perror("Error");
  }

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(0);
  if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    perror("bind failed");
    abort();
  }
  ss.sin_family = AF_INET;
  ss.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ss.sin_port = htons(53);
  for (;;)
  {
    sslen = sizeof(ss);
    ss2len = sizeof(ss);

    txidtxt = txid++;
    dns_set_id(querytxt, txidtxt);
    dns_set_qr(querytxt, 0);
    dns_set_opcode(querytxt, 0);
    dns_set_tc(querytxt, 0);
    dns_set_rd(querytxt, 1);
    dns_set_z(querytxt);
    dns_set_rcode(querytxt, 0);
    dns_set_qdcount(querytxt, 0);
    dns_set_ancount(querytxt, 0);
    dns_set_nscount(querytxt, 0);
    dns_set_arcount(querytxt, 0);

    dns_next_init_qd(querytxt, &qofftxt, &remcnt, sizeof(querytxt));
    //dns_set_qdcount(querytxt, dns_qdcount(querytxt) + 1);
    //dns_put_next_qr(querytxt, &qofftxt, &remcnt, sizeof(querytxt), "foo2.lan", 1, 1);
    dns_set_qdcount(querytxt, dns_qdcount(querytxt) + 1);
    dns_put_next_qr(querytxt, &qofftxt, &remcnt, sizeof(querytxt), "_cgtp.foo2.lan", 16, 1);

    if (sendto(sockfd, querytxt, qofftxt, 0, (struct sockaddr*)&ss, sslen) < 0)
    {
      printf("sendto failed\n");
    }

    txida = txid++;
    dns_set_id(querya, txida);
    dns_set_qr(querya, 0);
    dns_set_opcode(querya, 0);
    dns_set_tc(querya, 0);
    dns_set_rd(querya, 1);
    dns_set_z(querya);
    dns_set_rcode(querya, 0);
    dns_set_qdcount(querya, 0);
    dns_set_ancount(querya, 0);
    dns_set_nscount(querya, 0);
    dns_set_arcount(querya, 0);

    dns_next_init_qd(querya, &qoffa, &remcnt, sizeof(querya));
    dns_set_qdcount(querya, dns_qdcount(querya) + 1);
    dns_put_next_qr(querya, &qoffa, &remcnt, sizeof(querya), "foo2.lan", 1, 1);
    //dns_set_qdcount(querya, dns_qdcount(querya) + 1);
    //dns_put_next_qr(querya, &qoffa, &remcnt, sizeof(querya), "_cgtp.foo2.lan", 16, 1);

    if (sendto(sockfd, querya, qoffa, 0, (struct sockaddr*)&ss, sslen) < 0)
    {
      printf("sendto failed\n");
    }
    
    while ((!answer_a || !answer_txt) && (retrya <= 4 || retrytxt <= 4))
    {
      int recvd;
      recvd = recvfrom(sockfd, answer, sizeof(answer), 0, (struct sockaddr*)&ss2, &ss2len);
      if (recvd < 0)
      {
        if (errno == EAGAIN)
        {
          if (!answer_a)
          {
            printf("resent A\n");
            if (sendto(sockfd, querya, qoffa, 0, (struct sockaddr*)&ss, sslen) < 0)
            {
              printf("sendto failed\n");
            }
            retrya++;
          }
          if (!answer_txt)
          {
            printf("resent TXT\n");
            if (sendto(sockfd, querytxt, qofftxt, 0, (struct sockaddr*)&ss, sslen) < 0)
            {
              printf("sendto failed\n");
            }
            retrytxt++;
          }
        }
        continue;
      }
  
      if (dns_id(answer) == txida && !answer_a)
      {
        uint16_t qtype;
        char databuf[8192];
        size_t datalen;
        if (recursive_resolve(answer, recvd, "foo2.lan", 1, &qtype,
                              databuf, sizeof(databuf), &datalen) == 0)
        {
          if (datalen == 4 && qtype == 1)
          {
            printf("%d.%d.%d.%d\n", (unsigned char)databuf[0],
              (unsigned char)databuf[1],
              (unsigned char)databuf[2],
              (unsigned char)databuf[3]);
          }
        }
        answer_a = 1;
      }
  
      if (dns_id(answer) == txidtxt && !answer_txt)
      {
        uint16_t qtype;
        char databuf[8192];
        size_t datalen;
        if (recursive_resolve(answer, recvd, "_cgtp.foo2.lan", 1, &qtype,
                              databuf, sizeof(databuf)-1, &datalen) == 0)
        {
          if (qtype == 16)
          {
            databuf[datalen] = '\0';
            printf("%s\n", databuf+1);
          }
        }
        answer_txt = 1;
      }
    }

    exit(1);
  }
  return 0;
}
