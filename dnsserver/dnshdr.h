#ifndef _DNSHDR_H_
#define _DNSHDR_H_

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

static inline uint32_t hdr_get32h(const void *buf)
{
  uint32_t res;
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

static inline uint32_t hdr_get32n(const void *buf)
{
  return ntohl(hdr_get32h(buf));
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

static inline void dns_next_init_qd(const void *vdns, uint16_t *off, uint16_t *remcnt,
                                    uint16_t plen)
{
  if (plen < 12)
  {
    abort();
  }
  *off = 12;
  *remcnt = dns_qdcount(vdns);
}

static inline void dns_next_init_an_ask(const void *vdns, uint16_t *off, uint16_t *remcnt,
                                        uint16_t plen)
{
  if (plen < *off)
  {
    abort();
  }
  *remcnt = dns_ancount(vdns);
}

static inline int dns_next_an_ask(const void *vdns, uint16_t *off, uint16_t *remcnt,
                                  uint16_t plen,
                                  char *buf, size_t bufsiz, uint16_t *qtype,
                                  uint16_t *qclass, uint32_t *ttl,
                                  char *datbuf, size_t datbufsiz, size_t *datbuflen)
{
  const unsigned char *cdns = vdns;
  uint16_t tocopy;
  uint16_t labsiz, laboff;
  uint16_t datsiz, datoff, datrem;
  size_t strlentmp;
  int jmp = 0;
  *buf = '\0';
  *datbuf = '\0';
  if (*remcnt == 0)
  {
    return -ENOENT;
  }
  laboff = *off;
  while (*off < plen && *remcnt)
  {
    labsiz = cdns[laboff++];
    //printf("labsiz %d at off %d\n", (int)labsiz, (int)laboff);
    if (!jmp)
    {
      (*off)++;
    }
    if (labsiz == 0)
    {
      break;
    }
    if ((labsiz & 0xc0) == 0xc0)
    {
      labsiz &= ~0xc0;
      labsiz <<= 8;
      if (laboff >= plen)
      {
        return -EFAULT;
      }
      labsiz |= cdns[laboff++];
      if (!jmp)
      {
        (*off)++;
      }
      if (labsiz >= plen)
      {
        return -EFAULT;
      }
      laboff = labsiz + 1;
      labsiz = cdns[laboff - 1];
      jmp = 1;
    }
    else
    {
      //laboff = *off;
      if (!jmp)
      {
        (*off) += labsiz;
      }
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
    memcpy(buf+strlentmp, &cdns[laboff], tocopy);
    memcpy(buf+strlentmp+tocopy, ".\0", 2);
    //printf("buf now %s\n", buf);
    strlentmp += tocopy + 1;
    laboff += labsiz;
  }
  if (*off + 10 > plen)
  {
    return -EFAULT;
  }
  *qtype = hdr_get16n(&cdns[(*off)]);
  *qclass = hdr_get16n(&cdns[(*off)+2]);
  *ttl = hdr_get32n(&cdns[(*off)+4]);
  datrem = hdr_get16n(&cdns[(*off)+8]);
  (*off) += 10;
  if (*qtype != 5)
  {
    uint16_t tocopy = datrem;
    if (tocopy+2 > datbufsiz)
    {
      return -EFAULT;
    }
    memcpy(datbuf, &cdns[*off], tocopy);
    *datbuflen = datrem;
  }
  else
  {
    datoff = *off;
    jmp = 0;
    while (*off < plen && *remcnt)
    {
      if (!datrem)
      {
        return -EFAULT;
      }
      datsiz = cdns[datoff++];
      //printf("datsiz %d at off %d\n", (int)datsiz, (int)datoff);
      if (!jmp)
      {
        (*off)++;
      }
      if (datsiz == 0)
      {
        break;
      }
      if ((datsiz & 0xc0) == 0xc0)
      {
        datsiz &= ~0xc0;
        datsiz <<= 8;
        if (datoff >= plen)
        {
          return -EFAULT;
        }
        datsiz |= cdns[datoff++];
        if (!jmp)
        {
          (*off)++;
        }
        if (datsiz >= plen)
        {
          return -EFAULT;
        }
        datoff = datsiz + 1;
        datsiz = cdns[datoff - 1];
        jmp = 1;
      }
      else
      {
        //datoff = *off;
        if (!jmp)
        {
          (*off) += datsiz;
        }
      }
      if (datoff + datsiz >= plen) // have to have room for '\0'
      {
        return -EFAULT;
      }
      tocopy = datsiz;
      strlentmp = strlen(datbuf);
      if (tocopy+strlentmp+2 > bufsiz)
      {
        return -EFAULT;
      }
      memcpy(datbuf+strlentmp, &cdns[datoff], tocopy);
      memcpy(datbuf+strlentmp+tocopy, ".\0", 2);
      //printf("datbuf now %s\n", datbuf);
      strlentmp += tocopy + 1;
      datoff += datsiz;
    }
    strlentmp = strlen(datbuf);
    *datbuflen = strlentmp;
    datbuf[strlentmp-1] = '\0';
  }
  (*remcnt)--;
  return 0;
}

static inline int dns_put_next(void *vdns, uint16_t *off, uint16_t *remcnt,
                               uint16_t plen,
                               char *buf,
                               uint16_t qtype, uint16_t qclass, uint32_t ttl,
                               uint16_t rdlength, void *rdata)
{
  unsigned char *cdns = vdns;
  char *chr;
  if (*off + strlen(buf)+2 + 10 + rdlength > plen)
  {
    return -EFAULT;
  }
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
  if (*off + strlen(buf)+2 + 4 > plen)
  {
    return -EFAULT;
  }
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

static inline int dns_next(const void *vdns, uint16_t *off, uint16_t *remcnt,
                           uint16_t plen,
                           char *buf, size_t bufsiz, uint16_t *qtype,
                           uint16_t *qclass)
{
  const unsigned char *cdns = vdns;
  uint16_t tocopy;
  uint16_t labsiz, laboff;
  size_t strlentmp;
  int jmp = 0;
  *buf = '\0';
  if (*remcnt == 0)
  {
    return -ENOENT;
  }
  laboff = *off;
  while (*off < plen && *remcnt)
  {
    labsiz = cdns[laboff++];
    //printf("labsiz %d at off %d\n", (int)labsiz, (int)laboff);
    if (!jmp)
    {
      (*off)++;
    }
    if (labsiz == 0)
    {
      break;
    }
    if ((labsiz & 0xc0) == 0xc0)
    {
      labsiz &= ~0xc0;
      labsiz <<= 8;
      if (laboff >= plen)
      {
        return -EFAULT;
      }
      labsiz |= cdns[laboff++];
      if (!jmp)
      {
        (*off)++;
      }
      if (labsiz >= plen)
      {
        return -EFAULT;
      }
      laboff = labsiz + 1;
      labsiz = cdns[laboff - 1];
      jmp = 1;
    }
    else
    {
      //laboff = *off;
      if (!jmp)
      {
        (*off) += labsiz;
      }
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
    memcpy(buf+strlentmp, &cdns[laboff], tocopy);
    memcpy(buf+strlentmp+tocopy, ".\0", 2);
    //printf("buf now %s\n", buf);
    strlentmp += tocopy + 1;
    laboff += labsiz;
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

int recursive_resolve(const char *pkt, size_t recvd, const char *name,
                      uint16_t qclassexp, uint16_t *qtypeptr,
                      char *databuf, size_t databufsiz, size_t *datalen)
{
  uint16_t aoff, answer_aoff;
  uint16_t remcnt;
  int i;
  uint32_t ttl;
  const int recursion_limit = 100;
  char nambuf[8192];
  char nextbuf[8192];
  uint16_t qtype, qclass;
  size_t vallen;
  dns_next_init_qd(pkt, &aoff, &remcnt, recvd);
  if (dns_next(pkt, &aoff, &remcnt, recvd, nambuf, sizeof(nambuf), &qtype, &qclass) == 0)
  {
    if (strcmp(nambuf, name) != 0)
    {
      return -ENOENT;
    }
  }
  else
  {
    return -ENOENT;
  }
  snprintf(nextbuf, sizeof(nextbuf), "%s.", name);
  if (dns_next(pkt, &aoff, &remcnt, recvd, nambuf, sizeof(nambuf), &qtype, &qclass) == 0)
  {
    return -EFAULT;
  }
  answer_aoff = aoff;
  dns_next_init_an_ask(pkt, &aoff, &remcnt, recvd);
  for (i = 0; i < recursion_limit; i++)
  {
    aoff = answer_aoff;
    dns_next_init_an_ask(pkt, &aoff, &remcnt, recvd);
    for (;;)
    {
      vallen = 0;
      if (dns_next_an_ask(pkt, &aoff, &remcnt, recvd, nambuf, sizeof(nambuf), &qtype, &qclass, &ttl,
                          databuf, databufsiz, &vallen) != 0)
      {
        return -ENOENT;
      }
      if (strcmp(nambuf, nextbuf) != 0)
      {
        continue;
      }
      if (qclass != qclassexp)
      {
        return -ENOENT;
      }
      if (qtype == 5)
      {
        snprintf(nextbuf, sizeof(nextbuf), "%s.", databuf);
        //printf("got cname %s\n", nextbuf);
        break;
      }
      if (qtype != 5)
      {
        *qtypeptr = qtype;
        *datalen = vallen;
        return 0;
      }
    }
  }
  return -ENOENT;
}

#endif
