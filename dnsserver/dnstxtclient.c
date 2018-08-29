#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "dnshdr.h"

struct dst {
  uint32_t ip;
  char path[8192];
};

int resolv_patha(struct dst *dst)
{
  int sockfd;
  char pathfirst[8192];
  char querya[1536] = {0};
  char answer[1536] = {0};
  struct sockaddr_in sin = {};
  struct sockaddr_in ss = {};
  struct sockaddr_storage ss2 = {};
  socklen_t sslen = sizeof(ss), ss2len = sizeof(ss2);
  struct timeval tv;
  char *bang;
  uint16_t txid = rand()&0xFFFF;
  uint16_t txida;
  uint16_t qoffa;
  uint16_t remcnt;
  int answer_a = 0;
  int retrya = 0;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    return -errno;
  }

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
    close(sockfd);
    return -errno;
  }

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(0);
  if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    close(sockfd);
    return -errno;
  }

  ss.sin_family = AF_INET;
  ss.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ss.sin_port = htons(53);

  snprintf(pathfirst, sizeof(pathfirst), "%s", dst->path);
  bang = strchr(pathfirst, '!');
  if (bang && *bang)
  {
    *bang = '\0';
  }

  //printf("Resolving %s\n", pathfirst);

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
  dns_put_next_qr(querya, &qoffa, &remcnt, sizeof(querya), pathfirst, 1, 1);

  if (sendto(sockfd, querya, qoffa, 0, (struct sockaddr*)&ss, sslen) < 0)
  {
    //printf("sendto failed\n");
    close(sockfd);
    return -errno;
  }

  while ((!answer_a) && (retrya <= 4))
  {
    int recvd;
    recvd = recvfrom(sockfd, answer, sizeof(answer), 0, (struct sockaddr*)&ss2, &ss2len);
    if (recvd < 0)
    {
      if (errno == EAGAIN)
      {
        if (!answer_a)
        {
          //printf("resent A\n");
          if (sendto(sockfd, querya, qoffa, 0, (struct sockaddr*)&ss, sslen) < 0)
          {
            //printf("sendto failed\n");
            close(sockfd);
            return -errno;
          }
          retrya++;
        }
      }
      continue;
    }
  
    if (dns_id(answer) == txida && !answer_a)
    {
      uint16_t qtype;
      char databuf[8192];
      size_t datalen;
      if (recursive_resolve(answer, recvd, pathfirst, 1, &qtype,
                            databuf, sizeof(databuf), &datalen) == 0)
      {
        if (datalen == 4 && qtype == 1)
        {
          dst->ip = hdr_get32n(databuf);
#if 0
          printf("%d.%d.%d.%d\n", (unsigned char)databuf[0],
            (unsigned char)databuf[1],
            (unsigned char)databuf[2],
            (unsigned char)databuf[3]);
#endif
          close(sockfd);
          return 0;
        }
      }
      answer_a = 1;
    }
  }

  printf("Not found\n");
  
  return -ENOENT;
}

int get_dst(struct dst *dst, char *name)
{
  struct timeval tv;
  int sockfd;
  char namcgtp[8192] = {0};
  char querya[1536] = {0};
  char querytxt[1536] = {0};
  char answer[1536] = {0};
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

  snprintf(namcgtp, sizeof(namcgtp), "_cgtp.%s", name);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    return -errno;
  }

  tv.tv_sec = 1;
  tv.tv_usec = 0;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
    close(sockfd);
    return -errno;
  }

  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(0);
  if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    close(sockfd);
    return -errno;
  }

  ss.sin_family = AF_INET;
  ss.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ss.sin_port = htons(53);

  dst->ip = 0;
  dst->path[0] = '\0';

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
  dns_put_next_qr(querytxt, &qofftxt, &remcnt, sizeof(querytxt), namcgtp, 16, 1);

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
  dns_put_next_qr(querya, &qoffa, &remcnt, sizeof(querya), name, 1, 1);
  //dns_set_qdcount(querya, dns_qdcount(querya) + 1);
  //dns_put_next_qr(querya, &qoffa, &remcnt, sizeof(querya), "_cgtp.foo2.lan", 16, 1);

  if (sendto(sockfd, querytxt, qofftxt, 0, (struct sockaddr*)&ss, sslen) < 0)
  {
    //printf("sendto failed\n");
    close(sockfd);
    return -errno;
  }

  while ((!answer_txt) && (retrytxt <= 4))
  {
    int recvd;
    recvd = recvfrom(sockfd, answer, sizeof(answer), 0, (struct sockaddr*)&ss2, &ss2len);
    if (recvd < 0)
    {
      if (errno == EAGAIN)
      {
        if (!answer_txt)
        {
          //printf("resent TXT\n");
          if (sendto(sockfd, querytxt, qofftxt, 0, (struct sockaddr*)&ss, sslen) < 0)
          {
            //printf("sendto failed\n");
            close(sockfd);
            return -errno;
          }
          retrytxt++;
        }
      }
      continue;
    }
  
    if (dns_id(answer) == txidtxt && !answer_txt)
    {
      uint16_t qtype;
      char databuf[8192];
      size_t datalen;
      if (recursive_resolve(answer, recvd, namcgtp, 1, &qtype,
                            databuf, sizeof(databuf)-1, &datalen) == 0)
      {
        if (qtype == 16)
        {
          databuf[datalen] = '\0';
          snprintf(dst->path, sizeof(dst->path), "%s", databuf+1);
          //printf("%s\n", databuf+1);
          close(sockfd);
          return resolv_patha(dst);
        }
     }
      answer_txt = 1;
    }
  }

  if (sendto(sockfd, querya, qoffa, 0, (struct sockaddr*)&ss, sslen) < 0)
  {
    //printf("sendto failed\n");
    close(sockfd);
    return -errno;
  }

  while ((!answer_a) && (retrya <= 4))
  {
    int recvd;
    recvd = recvfrom(sockfd, answer, sizeof(answer), 0, (struct sockaddr*)&ss2, &ss2len);
    if (recvd < 0)
    {
      if (errno == EAGAIN)
      {
        if (!answer_a)
        {
          //printf("resent A\n");
          if (sendto(sockfd, querya, qoffa, 0, (struct sockaddr*)&ss, sslen) < 0)
          {
            //printf("sendto failed\n");
            close(sockfd);
            return -errno;
          }
          retrya++;
        }
      }
      continue;
    }
  
    if (dns_id(answer) == txida && !answer_a)
    {
      uint16_t qtype;
      char databuf[8192];
      size_t datalen;
      if (recursive_resolve(answer, recvd, name, 1, &qtype,
                            databuf, sizeof(databuf), &datalen) == 0)
      {
        if (datalen == 4 && qtype == 1)
        {
          dst->ip = hdr_get32n(databuf);
#if 0
          printf("%d.%d.%d.%d\n", (unsigned char)databuf[0],
            (unsigned char)databuf[1],
            (unsigned char)databuf[2],
            (unsigned char)databuf[3]);
#endif
          close(sockfd);
          return 0;
        }
      }
      answer_a = 1;
    }
  }

  close(sockfd);
  return -ENOENT;
}

int main(int argc, char **argv)
{
  struct dst dst;
  if (get_dst(&dst, "foo2.lan") != 0)
  {
    printf("Err\n");
    exit(1);
  }
  printf("IP %x\n", dst.ip);
  printf("bang path %s\n", dst.path);
  return 0;
}
