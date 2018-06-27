#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static inline uint16_t hdr_get16h(const void *buf)
{
  uint16_t res;
  memcpy(&res, buf, sizeof(res));
  return res;
}

static inline void hdr_set16h(void *buf, uint16_t val)
{
  memcpy(buf, &val, sizeof(val));
}

static inline void hdr_set32h(void *buf, uint32_t val)
{
  memcpy(buf, &val, sizeof(val));
}

static inline uint16_t hdr_get16n(const void *buf)
{
  return ntohs(hdr_get16h(buf));
}

static inline void hdr_set16n(void *buf, uint16_t val)
{
  hdr_set16h(buf, htons(val));
}

static inline void hdr_set32n(void *buf, uint32_t val)
{
  hdr_set32h(buf, htonl(val));
}

static inline uint16_t dns_id(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[0]);
}
static inline void dns_set_id(void *vdns, uint16_t id)
{
  unsigned char *cdns = vdns;
  hdr_set16n(&cdns[0], id);
}
static inline uint8_t dns_qr(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<7));
}
static inline void dns_set_qr(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= ~(1<<7);
  cdns[2] |= (!!bit)<<7;
}
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
static inline uint8_t dns_opcode(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return (cdns[2] & 0x78) >> 3;
}
static inline void dns_set_opcode(void *vdns, uint8_t bits)
{
  unsigned char *cdns = vdns;
  cdns[2] &= ~0x78;
  cdns[2] |= (bits&0xF)<<3;
}
static inline uint8_t dns_aa(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<2));
}
static inline void dns_set_aa(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= ~(1<<2);
  cdns[2] |= (!!bit)<<2;
}
static inline uint8_t dns_tc(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<1));
}
static inline void dns_set_tc(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= ~(1<<1);
  cdns[2] |= (!!bit)<<1;
}
static inline uint8_t dns_rd(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[2] & (1<<0));
}
static inline void dns_set_rd(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[2] &= ~(1<<0);
  cdns[2] |= (!!bit)<<0;
}
static inline uint8_t dns_ra(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return !!(cdns[3] & (1<<7));
}
static inline void dns_set_ra(void *vdns, uint8_t bit)
{
  unsigned char *cdns = vdns;
  cdns[3] &= ~(1<<7);
  cdns[3] |= (!!bit)<<7;
}
static inline uint8_t dns_z(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return (cdns[3] & 0x70) >> 4;
}
static inline void dns_set_z(void *vdns)
{
  unsigned char *cdns = vdns;
  cdns[3] &= ~0x70;
}
static inline uint8_t dns_rcode(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return (cdns[3] & 0x0F);
}
static inline void dns_set_rcode(void *vdns, uint8_t bits)
{
  unsigned char *cdns = vdns;
  cdns[3] &= ~0x0F;
  cdns[3] |= (bits&0x0F);
}
static inline uint8_t dns_qdcount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[4]);
}
static inline uint8_t dns_ancount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[6]);
}
static inline uint8_t dns_nscount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[8]);
}
static inline uint8_t dns_arcount(const void *vdns)
{
  unsigned const char *cdns = vdns;
  return hdr_get16n(&cdns[10]);
}
static inline void dns_set_qdcount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[4], val);
}
static inline void dns_set_ancount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[6], val);
}
static inline void dns_set_nscount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[8], val);
}
static inline void dns_set_arcount(void *vdns, uint16_t val)
{
  unsigned char *cdns = vdns;
  return hdr_set16n(&cdns[10], val);
}

static inline void dns_next_init_an(void *vdns, uint16_t *off, uint16_t *remcnt)
{
  dns_set_ancount(vdns, *remcnt);
  *off = 12; 
}
static inline void dns_next_init_ns(void *vdns, uint16_t *off, uint16_t *remcnt)
{
  dns_set_nscount(vdns, *remcnt);
}
static inline void dns_next_init_ar(void *vdns, uint16_t *off, uint16_t *remcnt)
{
  dns_set_arcount(vdns, *remcnt);
}

static inline void dns_next_init_qd(void *vdns, uint16_t *off, uint16_t *remcnt,
                                    uint16_t plen)
{
  if (plen < 12)
  {
    abort();
  }
  *off = 12;
  *remcnt = dns_qdcount(vdns);
}

static inline int dns_put_next(void *vdns, uint16_t *off, uint16_t *remcnt,
                               uint16_t plen,
                               char *buf,
                               uint16_t qtype, uint16_t qclass, uint32_t ttl,
                               uint16_t rdlength, void *rdata)
{
  unsigned char *cdns = vdns;
  char *chr;
  for (;;)
  {
    chr = strchr(buf, '.');
    if (chr == NULL)
    {
      chr = buf+strlen(buf);
    }
    if (*off + 1 + (chr-buf) > plen)
    {
      return -EFAULT;
    }
    cdns[(*off)++] = chr-buf;
    memcpy(&cdns[*off], buf, chr-buf);
    (*off) += chr-buf;
    if (chr == buf)
    {
      break;
    }
    if (*chr == '\0')
    {
      buf = chr;
    }
    else
    {
      buf = chr+1;
    }
  }
  if (*off + 10 + rdlength > plen)
  {
    return -EFAULT;
  }
  hdr_set16n(&cdns[(*off)], qtype);
  hdr_set16n(&cdns[(*off)+2], qclass);
  hdr_set32n(&cdns[(*off)+4], ttl);
  hdr_set16n(&cdns[(*off)+8], rdlength);
  memcpy(&cdns[(*off)+10], rdata, rdlength);
  (*off) += 10+rdlength;
  return 0;
}

static inline int dns_put_next_qr(void *vdns, uint16_t *off, uint16_t *remcnt,
                                  uint16_t plen,
                                  char *buf,
                                  uint16_t qtype, uint16_t qclass)
{
  unsigned char *cdns = vdns;
  char *chr;
  for (;;)
  {
    chr = strchr(buf, '.');
    if (chr == NULL)
    {
      chr = buf+strlen(buf);
    }
    if (*off + 1 + (chr-buf) > plen)
    {
      return -EFAULT;
    }
    cdns[(*off)++] = chr-buf;
    memcpy(&cdns[*off], buf, chr-buf);
    (*off) += chr-buf;
    if (chr == buf)
    {
      break;
    }
    if (*chr == '\0')
    {
      buf = chr;
    }
    else
    {
      buf = chr+1;
    }
  }
  if (*off + 4 > plen)
  {
    return -EFAULT;
  }
  hdr_set16n(&cdns[(*off)], qtype);
  hdr_set16n(&cdns[(*off)+2], qclass);
  (*off) += 4;
  return 0;
}

static inline int dns_next(void *vdns, uint16_t *off, uint16_t *remcnt,
                           uint16_t plen,
                           char *buf, size_t bufsiz, uint16_t *qtype,
                           uint16_t *qclass)
{
  unsigned char *cdns = vdns;
  uint16_t tocopy;
  uint16_t labsiz, laboff;
  size_t strlentmp;
  *buf = '\0';
  if (*remcnt == 0)
  {
    return -ENOENT;
  }
  while (*off < plen && *remcnt)
  {
    labsiz = cdns[(*off)++];
    if (labsiz == 0)
    {
      break;
    }
    if ((labsiz & 0xc0) == 0xc0)
    {
      labsiz &= ~0xc0;
      labsiz <<= 8;
      if (*off >= plen)
      {
        return -EFAULT;
      }
      labsiz |= cdns[(*off)++];
      if (labsiz >= plen)
      {
        return -EFAULT;
      }
      laboff = labsiz + 1;
      labsiz = cdns[laboff - 1];
    }
    else
    {
      laboff = *off;
    }
    if (laboff + labsiz >= plen) // have to have room for '\0'
    {
      return -EFAULT;
    }
    tocopy = labsiz;
    strlentmp = strlen(buf);
    if (tocopy+strlentmp+2 > bufsiz)
    {
      return -EFAULT;
    }
    (*off) += labsiz;
    memcpy(buf+strlentmp, &cdns[laboff], tocopy);
    memcpy(buf+strlentmp+tocopy, ".\0", 2);
    strlentmp += tocopy + 1;
  }
  if (*off + 4 > plen)
  {
    return -EFAULT;
  }
  *qtype = hdr_get16n(&cdns[(*off)]);
  *qclass = hdr_get16n(&cdns[(*off)+2]);
  (*off) += 4;
  strlentmp = strlen(buf);
  buf[strlentmp-1] = '\0';
  (*remcnt)--;
  return 0;
}

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
      if (qclass == 1 && qtype == 1)
      {
        dns_set_ancount(answer, dns_ancount(answer) + 1);
        dns_put_next(answer, &aoff, &aremcnt, sizeof(answer), nambuf, qtype, qclass, 0,
                     4, "\x01\x02\x03\x04");
      }
      printf("%s\n", nambuf);
    }

    if (sendto(sockfd, answer, aoff, 0, (struct sockaddr*)&ss, sslen) < 0)
    {
      printf("sendto failed\n");
    }

    printf("Recvd %zu bytes\n", (size_t)pktsize);
    for (i = 0; i < pktsize; i++)
    {
      printf("\\x%.2x", (unsigned char)pkt[i]);
    }
    printf("\n");
  }
  return 0;
}
