#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include "dnshdr.h"

struct dst {
  int family;
  union {
    uint32_t ip;
    unsigned char ipv6[16];
  } u;
  char path[8192];
};

uint32_t global_addr = 0;
pthread_mutex_t global_mtx = PTHREAD_MUTEX_INITIALIZER;

void global_addr_set(void)
{
  char *line = NULL;
  size_t n = 0;
  FILE *f;
  struct in_addr in;
  if (global_addr != 0)
  {
    return;
  }
  pthread_mutex_lock(&global_mtx);
  if (global_addr != 0)
  {
    pthread_mutex_unlock(&global_mtx);
    return;
  }
  f = fopen("/etc/resolv.conf", "r");
  if (f == NULL)
  {
    global_addr = (127<<24)|1;
    pthread_mutex_unlock(&global_mtx);
    return;
  }
  for (;;)
  {
    getline(&line, &n, f);
    if (strncmp(line, "nameserver ", 11) == 0 ||
        strncmp(line, "nameserver\t", 11) == 0)
    {
      char *srv = line+11;
      char *end = srv + strlen(srv) - 1;
      while (*srv == ' ' || *srv == '\t')
      {
        srv++;
      }
      while (*end == ' ' || *end == '\t')
      {
        *end = '\0';
        end--;
      }
      if (inet_aton(srv, &in) == 1)
      {
        global_addr = ntohl(in.s_addr);
        fclose(f);
        free(line);
        pthread_mutex_unlock(&global_mtx);
        return;
      }
    }
  }
  global_addr = (127<<24)|1;
  fclose(f);
  free(line);
  pthread_mutex_unlock(&global_mtx);
}

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
  char *bang, *colon;
  uint16_t txid = rand()&0xFFFF;
  uint16_t txida;
  uint16_t qoffa;
  uint16_t remcnt;
  struct in_addr in;
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

#if 0
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(0);
  if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    close(sockfd);
    return -errno;
  }
#endif

  global_addr_set();

  ss.sin_family = AF_INET;
  ss.sin_addr.s_addr = htonl(global_addr);
  ss.sin_port = htons(53);

  snprintf(pathfirst, sizeof(pathfirst), "%s", dst->path);
  bang = strchr(pathfirst, '!');
  if (bang && *bang)
  {
    *bang = '\0';
  }
  colon = strchr(pathfirst, ':');
  if (colon && *colon)
  {
    *colon = '\0';
  }

  if (inet_aton(pathfirst, &in))
  {
    dst->family = AF_INET;
    dst->u.ip = ntohl(in.s_addr);
    close(sockfd);
    return 0;
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
          dst->family = AF_INET;
          dst->u.ip = hdr_get32n(databuf);
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

  //printf("Not found\n"); // FIXME rm
  
  close(sockfd);
  return -ENXIO;
}

int get_dst(struct dst *dst, int try_ipv6, char *name)
{
  struct timeval tv;
  int sockfd;
  char namcgtp[8192] = {0};
  char querya[1536] = {0};
  char queryaaaa[1536] = {0};
  char querytxt[1536] = {0};
  char answer[1536] = {0};
  struct sockaddr_in sin = {};
  struct sockaddr_in ss = {};
  struct sockaddr_storage ss2 = {};
  socklen_t sslen, ss2len;
  uint16_t remcnt;
  uint16_t qoffa, qofftxt, qoffaaaa;
  uint16_t txid = rand()&0xFFFF;
  int answer_a = 0, answer_txt = 0, answer_aaaa = 0, answer_a_ok = 0;
  int txida;
  int txidtxt;
  int txidaaaa;
  int retrya = 0, retrytxt = 0, retryaaaa = 0;
  uint16_t qtype;
  char databuf[8192];
  size_t datalen;

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

#if 0
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(0);
  if (bind(sockfd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    close(sockfd);
    return -errno;
  }
#endif

  global_addr_set();

  ss.sin_family = AF_INET;
  ss.sin_addr.s_addr = htonl(global_addr);
  ss.sin_port = htons(53);

  dst->family = 0;
  dst->u.ip = 0;
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

  txidaaaa = txid++;
  dns_set_id(queryaaaa, txidaaaa);
  dns_set_qr(queryaaaa, 0);
  dns_set_opcode(queryaaaa, 0);
  dns_set_tc(queryaaaa, 0);
  dns_set_rd(queryaaaa, 1);
  dns_set_z(queryaaaa);
  dns_set_rcode(queryaaaa, 0);
  dns_set_qdcount(queryaaaa, 0);
  dns_set_ancount(queryaaaa, 0);
  dns_set_nscount(queryaaaa, 0);
  dns_set_arcount(queryaaaa, 0);

  dns_next_init_qd(queryaaaa, &qoffaaaa, &remcnt, sizeof(queryaaaa));
  dns_set_qdcount(queryaaaa, dns_qdcount(queryaaaa) + 1);
  dns_put_next_qr(queryaaaa, &qoffaaaa, &remcnt, sizeof(queryaaaa), name, 28, 1);

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
  if (try_ipv6 &&
      sendto(sockfd, queryaaaa, qoffaaaa, 0, (struct sockaddr*)&ss, sslen) < 0)
  {
    //printf("sendto failed\n");
    close(sockfd);
    return -errno;
  }
  if (!try_ipv6)
  {
    answer_aaaa = 1;
  }

  while ((!answer_a || !answer_aaaa) && (retrya <= 4 || retryaaaa <= 4))
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
        if (!answer_aaaa)
        {
          //printf("resent AAAA\n");
          if (sendto(sockfd, queryaaaa, qoffaaaa, 0, (struct sockaddr*)&ss, sslen) < 0)
          {
            //printf("sendto failed\n");
            close(sockfd);
            return -errno;
          }
          retryaaaa++;
        }
      }
      continue;
    }
  
    if (dns_id(answer) == txida && !answer_a)
    {
      if (recursive_resolve(answer, recvd, name, 1, &qtype,
                            databuf, sizeof(databuf), &datalen) == 0)
      {
        if (datalen == 4 && qtype == 1)
        {
          dst->family = AF_INET;
          dst->u.ip = hdr_get32n(databuf);
#if 0
          printf("%d.%d.%d.%d\n", (unsigned char)databuf[0],
            (unsigned char)databuf[1],
            (unsigned char)databuf[2],
            (unsigned char)databuf[3]);
#endif
          answer_a_ok = 1;
        }
      }
      answer_a = 1;
    }
    if (dns_id(answer) == txidaaaa && !answer_aaaa)
    {
      if (recursive_resolve(answer, recvd, name, 1, &qtype,
                            databuf, sizeof(databuf), &datalen) == 0)
      {
        if (datalen == 16 && qtype == 28)
        {
          dst->family = AF_INET6;
          memcpy(dst->u.ipv6, databuf, 16);
          close(sockfd);
          return 0;
        }
      }
      answer_aaaa = 1;
    }
  }

  close(sockfd);
  if (answer_a_ok)
  {
    return 0;
  }
  return -ENXIO;
}

size_t bytes_iovs(struct iovec *iovs, size_t sz)
{
  size_t total = 0;
  size_t i;
  for (i = 0; i < sz; i++)
  {
    total += iovs[i].iov_len;
  }
  return total;
}

size_t reduce_iovs(struct iovec *iovs, size_t sz, size_t reduction)
{
  size_t i;
  struct iovec *iov;
  for (i = 0; i < sz; i++)
  {
    iov = &iovs[i];
    if (iov->iov_len > reduction)
    {
      iov->iov_len -= reduction;
      iov->iov_base = ((char*)iov->iov_base) + reduction;
      return i;
    }
    else if (iov->iov_len == reduction)
    {
      iov->iov_len -= reduction;
      iov->iov_base = ((char*)iov->iov_base) + reduction;
      return i+1;
    }
    else
    {
      reduction -= iov->iov_len;
      iov->iov_base = ((char*)iov->iov_base) + iov->iov_len;
      iov->iov_len = 0;
    }
  }
  return i;
}

ssize_t writev_all(int sockfd, struct iovec *iovs, size_t sz)
{
  size_t bytes_written = 0;
  ssize_t ret;
  size_t reduceret = 0;
  if (sz == 0)
  {
    return 0;
  }
  for (;;)
  {
    ret = writev(sockfd, iovs + reduceret, sz - reduceret);
    if (ret > 0)
    {
      bytes_written += ret;
      reduceret = reduce_iovs(iovs, sz, ret);
      if (reduceret == sz)
      {
        return bytes_written;
      }
    }
    else if (ret <= 0)
    {
      if (ret == 0)
      {
        errno = EPIPE; // Let's give some errno
      }
      if (ret < 0 && errno == EINTR)
      {
        continue;
      }
      else if (bytes_written > 0)
      {
        return bytes_written;
      }
      else
      {
        return -1;
      }
    }
  }
}

const char conbegin[] = "CONNECT ";
const char colon[] = ":";
const char interim[] = " HTTP/1.1\r\nHost: ";
const char crlfcrlf[] = "\r\n\r\n";
const char httpslash[] = "HTTP/";
const char twohundred[] = "200";

int connect_ex_dst(int sockfd, struct dst *dst, uint16_t port)
{
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  char *namptr;
  char *endptr;
  char *colonptr;
  char portint[16] = {0};
  struct iovec iovsnocolon_src[] = {
    {.iov_base = (char*)conbegin, .iov_len = sizeof(conbegin)-1},
    {.iov_base = NULL, .iov_len = 0}, // [1]
    {.iov_base = (char*)interim, .iov_len = sizeof(interim)-1},
    {.iov_base = NULL, .iov_len = 0}, // [3]
    {.iov_base = (char*)crlfcrlf, .iov_len = sizeof(crlfcrlf)-1},
  };
  struct iovec iovsnocolon[5];
  struct iovec iovs_src[] = {
    {.iov_base = (char*)conbegin, .iov_len = sizeof(conbegin)-1},
    {.iov_base = NULL, .iov_len = 0}, // [1]
    {.iov_base = (char*)colon, .iov_len = sizeof(colon)-1},
    {.iov_base = portint, .iov_len = 0}, // [3]
    {.iov_base = (char*)interim, .iov_len = sizeof(interim)-1},
    {.iov_base = NULL, .iov_len = 0}, // [5]
    {.iov_base = (char*)colon, .iov_len = sizeof(colon)-1},
    {.iov_base = portint, .iov_len = 0}, // [7]
    {.iov_base = (char*)crlfcrlf, .iov_len = sizeof(crlfcrlf)-1},
  };
  struct iovec iovs[9];
  size_t httpslashcnt = 0;
  ssize_t bytes_expected;
  ssize_t bytes_written;
  size_t majcnt = 0;
  size_t dot_seen = 0;
  size_t spseen = 0;
  size_t sp2seen = 0;
  size_t mincnt = 0;
  size_t crlfcrlfcnt = 0;
  size_t twohundredcnt = 0;
  ssize_t read_ret;
  char ch;
  const int gw_port = 8080;
  char *portptr;
  unsigned long portul;
  uint16_t used_port;

  namptr = dst->path;
  endptr = strchr(namptr, '!');
  if (endptr == NULL)
  {
    if (dst->family == AF_INET6)
    {
      sin6.sin6_family = AF_INET6;
      sin6.sin6_port = htons(port);
      memcpy(sin6.sin6_addr.s6_addr, dst->u.ipv6, 16);
      if (connect(sockfd, (const struct sockaddr*)&sin6, sizeof(sin6)) < 0)
      {
        return -1;
      }
      return 0;
    }
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = htonl(dst->u.ip);
    if (connect(sockfd, (const struct sockaddr*)&sin, sizeof(sin)) < 0)
    {
      return -1;
    }
    return 0;
  }
  *endptr = '\0';
  portptr = strchr(namptr, ':');
  if (portptr)
  {
    char *portendptr = NULL;
    portul = strtoul(portptr+1, &portendptr, 10);
    if (portptr[1] == '\0' || *portendptr != '\0')
    {
      errno = ENXIO;
      return -1;
    }
    if (portul > 65535)
    {
      errno = ENXIO;
      return -1;
    }
    used_port = portul;
  }
  else
  {
    used_port = gw_port;
  }
  if (sin.sin_family == AF_INET6)
  {
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(used_port);
    memcpy(sin6.sin6_addr.s6_addr, dst->u.ipv6, 16);
    if (connect(sockfd, (const struct sockaddr*)&sin6, sizeof(sin6)) < 0)
    {
      return -1;
    }
  }
  else
  {
    sin.sin_family = AF_INET;
    sin.sin_port = htons(used_port);
    sin.sin_addr.s_addr = htonl(dst->u.ip);
    if (connect(sockfd, (const struct sockaddr*)&sin, sizeof(sin)) < 0)
    {
      return -1;
    }
  }
  namptr = endptr + 1;
  while (namptr)
  {
    endptr = strchr(namptr, '!');
    if (endptr)
    {
      *endptr = '\0';
    }
    colonptr = strchr(namptr, ':');
    if (!endptr && colonptr)
    {
      errno = ENXIO;
      return -1; // Last hop may not have a port specified
    }
    if (colonptr)
    {
      memcpy(&iovsnocolon, &iovsnocolon_src, sizeof(iovsnocolon_src));
      iovsnocolon[1].iov_base = namptr;
      iovsnocolon[1].iov_len = strlen(namptr);
      iovsnocolon[3].iov_base = namptr;
      iovsnocolon[3].iov_len = strlen(namptr);
      bytes_expected = bytes_iovs(iovsnocolon, 5);
      bytes_written = writev_all(sockfd, iovsnocolon, 5);
      if (bytes_written != bytes_expected)
      {
        return -1;
      }
    }
    else
    {
      if (endptr)
      {
        snprintf(portint, sizeof(portint), "%d", (int)gw_port);
      }
      else
      {
        snprintf(portint, sizeof(portint), "%d", (int)port);
      }
      memcpy(&iovs, &iovs_src, sizeof(iovs_src));
      iovs[1].iov_base = namptr;
      iovs[1].iov_len = strlen(namptr);
      iovs[3].iov_len = strlen(portint);
      iovs[5].iov_base = namptr;
      iovs[5].iov_len = strlen(namptr);
      iovs[7].iov_len = strlen(portint);
      bytes_expected = bytes_iovs(iovs, 9);
      bytes_written = writev_all(sockfd, iovs, 9);
      if (bytes_written != bytes_expected)
      {
        return -1;
      }
    }
    for (;;)
    {
      read_ret = read(sockfd, &ch, 1);
      if (read_ret < 0)
      {
        return -1;
      }
      if (read_ret == 0) 
      {
        errno = EBADMSG;
        return -1;
      }
      if (read_ret > 1) 
      {
        abort();
      }
      if (httpslashcnt < 5)
      {
        if (httpslash[httpslashcnt] == ch)
        {
          httpslashcnt++;
        }
        else
        {
          errno = EBADMSG;
          return -1;
        }
      }
      else if (!spseen)
      {
        if (isdigit(ch))
        {
          if (dot_seen)
          {
            mincnt++;
          }
          else
          {
            majcnt++;
          }
          continue;
        }
        if (ch == '.' && !dot_seen)
        {
          dot_seen = 1;
        }
        if (ch == ' ')
        {
          if (majcnt == 0 || mincnt == 0)
          {
            errno = EBADMSG;
            return -1;
          }
          spseen = 1;
        }
      }
      else if (!sp2seen)
      {
        if (twohundredcnt < 3 && twohundred[twohundredcnt] == ch)
        {
          twohundredcnt++;
        }
        else if (ch == ' ')
        {
          sp2seen = 1;
        }
        else
        {
          errno = EBADMSG;
          return -1;
        }
      }
      if (crlfcrlf[crlfcrlfcnt] == ch)
      {
        crlfcrlfcnt++;
      }
      if (crlfcrlfcnt == 4)
      {
        if (twohundredcnt != 3 || !sp2seen)
        {
          errno = EBADMSG;
          return -1;
        }
        break;
      }
    }
    if (endptr)
    {
      namptr = endptr + 1;
    }
    else
    {
      namptr = NULL;
    }
  }
  return 0;
}

int socket_ex_ipv4(char *name, uint16_t port)
{
  struct dst dst;
  int sockfd;
  if (get_dst(&dst, 0, name) != 0)
  {
    errno = ENXIO;
    return -1;
  }
  if (dst.family != AF_INET)
  {
    abort();
  }
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    return -1;
  }
  if (connect_ex_dst(sockfd, &dst, port) != 0)
  {
    close(sockfd);
    return -1;
  }
  return sockfd;
}

int socket_ex(char *name, uint16_t port)
{
  struct dst dst;
  int sockfd;
  if (get_dst(&dst, 1, name) != 0)
  {
    errno = ENXIO;
    return -1;
  }
  if (dst.family == AF_INET6 && dst.path[0] == '\0')
  {
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
      return socket_ex_ipv4(name, port);
    }
    if (connect_ex_dst(sockfd, &dst, port) != 0)
    {
      close(sockfd);
      return socket_ex_ipv4(name, port);
    }
    return sockfd;
  }
  if (dst.family != AF_INET)
  {
    abort();
  }
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
  {
    return -1;
  }
  if (connect_ex_dst(sockfd, &dst, port) != 0)
  {
    close(sockfd);
    return -1;
  }
  return sockfd;
}

int connect_ex(int sockfd, char *name, uint16_t port)
{
  struct dst dst;
  if (get_dst(&dst, 0, name) != 0)
  {
    errno = ENXIO;
    return -1;
  }
  return connect_ex_dst(sockfd, &dst, port);
}

int main(int argc, char **argv)
{
  int sockfd;
  int port;
  if (argc != 3)
  {
    printf("Usage: %s foo2.lan 80\n", argv[0]);
    return 1;
  }
  port = atoi(argv[2]);
  sockfd = socket_ex(argv[1], port);
  if (sockfd < 0)
  {
    perror("Err");
    return 1;
  }
  printf("Connection successful\n");
  return 0;
}
