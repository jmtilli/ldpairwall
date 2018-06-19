#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

struct hostname_ctx {
  int len;
  int truncated;
  char hostname[256];
};

void hostname_ctx_init(struct hostname_ctx *nam)
{
  nam->len = 0;
  nam->truncated = 0;
  nam->hostname[0] = '\0';
}

struct http_ctx {
  int request_method_seen;
  int request_method_len;
  int uri_seen;
  int uri_len;
  int verdict;
  int chars_httpslash_seen;
  int major_digits_seen;
  int period_seen;
  int minor_digits_seen;
  int lf_seen;
  int host_num_seen;
  int hostname_seen;
  //int hostname_truncated;
  //char hostname[256];
  int crlfcrlf_lfcnt;
};

void http_ctx_init(struct http_ctx *ctx)
{
  ctx->request_method_seen = 0;
  ctx->request_method_len = 0;
  ctx->uri_seen = 0;
  ctx->uri_len = 0;
  ctx->verdict = -EAGAIN;
  ctx->chars_httpslash_seen = 0;
  ctx->major_digits_seen = 0;
  ctx->period_seen = 0;
  ctx->minor_digits_seen = 0;
  ctx->lf_seen = 0;
  ctx->host_num_seen = 0;
  ctx->hostname_seen = 0;
  //ctx->hostname[0] = '\0';
  //ctx->hostname_truncated = 0;
  ctx->crlfcrlf_lfcnt = 0;
}

static inline int istoken(char ch)
{
  return ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' ||
         ch == '\'' || ch == '*' || ch == '+' || ch == '-' || ch == '.' ||
         ch == '^' || ch == '_' || ch == '`' || ch == '|' || ch == '~' ||
         isdigit(ch) || isalpha(ch);
}

static inline int isurichar(char ch)
{
  return ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' ||
         ch == '\'' || ch == '*' || ch == '+' || ch == '-' || ch == '.' ||
         ch == '^' || ch == '_' || ch == '`' || ch == '|' || ch == '~' ||
         isdigit(ch) || isalpha(ch) || ch == '/';
}

int http_ctx_feed(struct http_ctx *ctx, const void *data, size_t sz,
                  struct hostname_ctx *nam)
{
  const unsigned char *udata = data;
  if (sz == 0 || ctx->verdict != -EAGAIN)
  {
    return ctx->verdict;
  }
  while (!ctx->request_method_seen)
  {
    unsigned char uch;
    if (sz == 0)
    {
      return ctx->verdict;
    }
    uch = udata[0];
    if (istoken(uch))
    {
      ctx->request_method_len++;
      sz--;
      udata++;
    }
    else if (uch != ' ')
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    else
    {
      ctx->request_method_seen = 1;
      if (ctx->request_method_len == 0)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
      sz--;
      udata++;
    }
  }
  while (!ctx->uri_seen)
  {
    unsigned char uch;
    if (sz == 0)
    {
      return ctx->verdict;
    }
    uch = udata[0];
    if (isurichar(uch))
    {
      ctx->uri_len++;
      sz--;
      udata++;
    }
    else if (uch != ' ')
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    else
    {
      ctx->uri_seen = 1;
      if (ctx->uri_len == 0)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
      sz--;
      udata++;
    }
  }
  while (ctx->chars_httpslash_seen < 5)
  {
    unsigned char uch;
    if (sz == 0)
    {
      return ctx->verdict;
    }
    uch = udata[0];
    if (uch == "HTTP/"[ctx->chars_httpslash_seen])
    {
      ctx->chars_httpslash_seen++;
      sz--;
      udata++;
    }
    else
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
  }
  while (!ctx->period_seen)
  {
    unsigned char uch;
    if (sz == 0)
    {
      return ctx->verdict;
    }
    uch = udata[0];
    if (uch == '.')
    {
      ctx->period_seen = 1;
      sz--;
      udata++;
      if (ctx->major_digits_seen == 0)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
    }
    else if (isdigit(uch))
    {
      ctx->major_digits_seen++;
      sz--;
      udata++;
    }
    else
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
  }
  while (!ctx->lf_seen)
  {
    unsigned char uch;
    if (sz == 0)
    {
      return ctx->verdict;
    }
    uch = udata[0];
    if (uch == '\r')
    {
      sz--;
      udata++;
    }
    else if (uch == '\n')
    {
      if (ctx->minor_digits_seen == 0)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
      ctx->lf_seen = 1;
      sz--;
      udata++;
    }
    else if (isdigit(uch))
    {
      ctx->minor_digits_seen++;
      sz--;
      udata++;
    }
    else
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
  }
  while (ctx->crlfcrlf_lfcnt < 2)
  {
    while (ctx->host_num_seen < 5)
    {
      unsigned char uch;
      if (sz == 0)
      {
        return ctx->verdict;
      }
      uch = udata[0];
      if (ctx->host_num_seen == -1)
      {
        if (uch == '\n')
        {
          ctx->host_num_seen = 0;
          ctx->crlfcrlf_lfcnt++;
        }
        sz--;
        udata++;
      }
      else if (uch == "HOST:"[ctx->host_num_seen] ||
               uch == "host:"[ctx->host_num_seen])
      {
        ctx->crlfcrlf_lfcnt = 0;
        ctx->host_num_seen++;
        sz--;
        udata++;
      }
      else if (!istoken(uch))
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
      else
      {
        if (uch != '\r' && uch != '\n')
        {
          ctx->crlfcrlf_lfcnt = 0;
        }
        ctx->host_num_seen = -1;
        sz--;
        udata++;
      }
    }
    // RFE could flag whitespace in middle of hostname as error
    for (;;)
    {
      unsigned char uch;
      if (sz == 0)
      {
        return ctx->verdict;
      }
      uch = udata[0];
      if (uch == ' ' || uch == '\t')
      {
        sz--;
        udata++;
      }
      else if (ctx->hostname_seen >= sizeof(nam->hostname) - 1 && uch != '\r' && uch != '\n')
      {
        sz--;
        udata++;
        ctx->hostname_seen++;
        nam->truncated = 1;
        nam->hostname[sizeof(nam->hostname)-1] = '\0';
      }
      else if (uch != '\r' && uch != '\n')
      {
        nam->hostname[ctx->hostname_seen] = uch;
        ctx->hostname_seen++;
        sz--;
        udata++;
        ctx->crlfcrlf_lfcnt = 0;
      }
      else if (uch == '\r')
      {
        sz--;
        udata++;
      }
      else if (uch == '\n')
      {
        ctx->host_num_seen = 0;
        ctx->verdict = 0;
        ctx->crlfcrlf_lfcnt++;
        nam->len = ctx->hostname_seen;
        if (ctx->hostname_seen < sizeof(nam->hostname) - 1)
        {
          nam->hostname[ctx->hostname_seen] = '\0';
        }
        else
        {
          nam->hostname[sizeof(nam->hostname)-1] = '\0';
        }
        return ctx->verdict;
      }
    }
  }
  ctx->verdict = -ENOTSUP;
  return ctx->verdict;
}

struct ssl_name_ctx {
  uint8_t type;
  uint16_t name_len;
  uint16_t processed;
  //uint16_t real_name_len;
  //char nam[256];
  //int truncated;
};

struct ssl_ext_ctx {
  uint16_t type;
  uint16_t ext_len;
  uint16_t processed;
  uint16_t name_list_len;
  struct ssl_name_ctx nam;
};

void ssl_name_ctx_reinit(struct ssl_name_ctx *ctx)
{
  ctx->type = 0;
  ctx->name_len = 0;
  ctx->processed = 0;
  //ctx->truncated = 0;
}

void ssl_name_ctx_init(struct ssl_name_ctx *ctx)
{
  ssl_name_ctx_reinit(ctx);
  //ctx->real_name_len = 0;
}

// Return: # of bytes processed
ssize_t ssl_name_ctx_feed(struct ssl_name_ctx *ctx, const void *data, size_t sz,
                          struct hostname_ctx *nam)
{
  size_t orig_sz = sz;
  const unsigned char *udata = data;
  while (ctx->processed < 1)
  {
    if (sz == 0)
    {
      return orig_sz - sz;
    }
    ctx->type <<= 8;
    ctx->type |= udata[0];
    sz--;
    udata++;
    ctx->processed++;
  }
  while (ctx->processed < 3)
  {
    if (sz == 0)
    {
      return orig_sz - sz;
    }
    ctx->name_len <<= 8;
    ctx->name_len |= udata[0];
    sz--;
    udata++;
    ctx->processed++;
  }
  if (ctx->type != 0)
  {
    if (sz >= ctx->name_len)
    {
      sz -= ctx->name_len;
      ctx->processed += ctx->name_len;
      udata += ctx->name_len;
      return orig_sz - sz;
    }
    ctx->processed += sz;
    udata += sz;
    sz = 0;
    return orig_sz - sz;
  }
  if (ctx->processed - 3 + sz >= ctx->name_len)
  {
    if (ctx->name_len < sizeof(nam->hostname))
    {
      uint32_t tocopy = ctx->name_len - (ctx->processed-3);
      memcpy(&nam->hostname[ctx->processed - 3], udata, tocopy);
      nam->hostname[ctx->processed - 3 + tocopy] = '\0';
      nam->truncated = 0;
      nam->len = ctx->name_len;
    }
    else if (sizeof(nam->hostname)-1 > (ctx->processed-3))
    {
      memcpy(&nam->hostname[ctx->processed - 3], udata,
             sizeof(nam->hostname)-1-(ctx->processed-3));
      nam->hostname[sizeof(nam->hostname)-1] = '\0';
      nam->truncated = 1;
      nam->len = ctx->name_len;
    }
    else
    {
      nam->hostname[sizeof(nam->hostname)-1] = '\0';
      nam->truncated = 1;
      nam->len = ctx->name_len;
    }
    ctx->processed += ctx->name_len;
    sz -= ctx->name_len;
    udata += ctx->name_len;
    return orig_sz - sz;
  }
  if (ctx->processed - 3 + sz < sizeof(nam->hostname))
  {
    memcpy(&nam->hostname[ctx->processed - 3], udata, sz);
  }
  else if (sizeof(nam->hostname)-1 > (ctx->processed-3))
  {
    memcpy(&nam->hostname[ctx->processed - 3], udata,
           sizeof(nam->hostname)-1-(ctx->processed-3));
  }
  ctx->processed += sz;
  udata += sz;
  sz = 0;
  return orig_sz - sz;
}

void ssl_ext_ctx_init(struct ssl_ext_ctx *ctx)
{
  ctx->type = 0;
  ctx->ext_len = 0;
  ctx->name_list_len = 0;
  ctx->processed = 0;
  ssl_name_ctx_init(&ctx->nam);
}

void ssl_ext_ctx_reinit(struct ssl_ext_ctx *ctx)
{
  ctx->type = 0;
  ctx->ext_len = 0;
  ctx->name_list_len = 0;
  ctx->processed = 0;
  ssl_name_ctx_reinit(&ctx->nam);
}

// Return: # of bytes processed
ssize_t ssl_ext_ctx_feed(struct ssl_ext_ctx *ctx, const void *data, size_t sz,
                         struct hostname_ctx *nam)
{
  size_t orig_sz = sz;
  const unsigned char *udata = data;
  while (ctx->processed < 2)
  {
    if (sz == 0)
    {
      return orig_sz - sz;
    }
    ctx->type <<= 8;
    ctx->type |= udata[0]; // FIXME type or ext_len first?
    sz--;
    udata++;
    ctx->processed++;
  }
  while (ctx->processed < 4)
  {
    if (sz == 0)
    {
      return orig_sz - sz;
    }
    ctx->ext_len <<= 8;
    ctx->ext_len |= udata[0];
    sz--;
    udata++;
    ctx->processed++;
  }
  if (ctx->type != 0)
  {
    if (sz >= ctx->ext_len)
    {
      sz -= ctx->ext_len;
      ctx->processed += ctx->ext_len;
      udata += ctx->ext_len;
      return orig_sz - sz;
    }
    ctx->processed += sz;
    udata += sz;
    sz = 0;
    return orig_sz - sz;
  }
  while (ctx->processed < 6)
  {
    if (sz == 0)
    {
      return orig_sz - sz;
    }
    ctx->name_list_len <<= 8;
    ctx->name_list_len |= udata[0];
    sz--;
    udata++;
    ctx->processed++;
  }
  uint16_t toprocess;
  toprocess = ctx->name_list_len + 6;
  if (toprocess > ctx->ext_len + 4)
  {
    toprocess = ctx->ext_len + 4;
  }
  while (sz > 0 && ctx->processed < toprocess)
  {
    ssize_t ret;
    size_t thismax;
    thismax = sz;
    if (thismax > toprocess - ctx->processed)
    {
      thismax = toprocess - ctx->processed;
    }
    ret = ssl_name_ctx_feed(&ctx->nam, udata, thismax, nam);
    sz -= ret;
    udata += ret;
    ctx->processed += ret;
    if (sz > 0)
    {
      ssl_name_ctx_reinit(&ctx->nam);
    }
  }
  return orig_sz - sz;
}

struct ssl_ctx {
  size_t bytesFed;
  int verdict;
  uint32_t handshake_len;
  uint32_t client_hello_len;
  uint8_t sid_len;
  uint16_t cs_len;
  uint16_t cm_len;
  uint16_t ext_len;
  uint16_t version; // (major << 8) | minor
  struct ssl_ext_ctx ext;
};

struct ssl_fragment_ctx {
  uint16_t fragsiz;
  uint8_t hdr_bytes_processed;
  uint16_t version;
  uint16_t last_version;
  int verdict;
  struct ssl_ctx hello;
};

void ssl_ctx_init(struct ssl_ctx *ctx)
{
  ctx->bytesFed = 0;
  ctx->verdict = -EAGAIN;
  ctx->handshake_len = 0;
  ctx->client_hello_len = 0;
  ctx->version = 0;
  ctx->sid_len = 0;
  ctx->cs_len = 0;
  ctx->cm_len = 0;
  ctx->ext_len = 0;
  ssl_ext_ctx_init(&ctx->ext);
}

void ssl_fragment_ctx_init(struct ssl_fragment_ctx *ctx)
{
  ctx->fragsiz = 0;
  ctx->hdr_bytes_processed = 0;
  ctx->version = 0;
  ctx->last_version = 0;
  ctx->verdict = -EAGAIN;
  ssl_ctx_init(&ctx->hello);
}

void ssl_fragment_ctx_reset(struct ssl_fragment_ctx *ctx)
{
  ctx->fragsiz = 0;
  ctx->hdr_bytes_processed = 0;
  ctx->version = 0;
}

int ssl_ctx_feed(struct ssl_ctx *ctx, uint16_t exp_vers,
                 const void *data, size_t sz, struct hostname_ctx *nam)
{
  const unsigned char *udata = data;
  if (sz == 0 || ctx->verdict != -EAGAIN)
  {
    return ctx->verdict;
  }
  if (ctx->bytesFed == 0)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (udata[0] != 1)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  while (ctx->bytesFed < 4)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    ctx->handshake_len <<= 8;
    ctx->handshake_len |= udata[0];
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  if (ctx->handshake_len > (1<<16))
  {
    ctx->verdict = -ENOTSUP;
    return ctx->verdict;
  }
  while (ctx->bytesFed < 6)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->version <<= 8;
    ctx->version |= udata[0];
    ctx->bytesFed++;
    udata++;
    sz--;
  }
#if 0
  if (ctx->version != exp_vers)
  {
    ctx->verdict = -ENOTSUP;
    return ctx->verdict;
  }
#endif
  if (ctx->version != 0x0301 && ctx->version != 0x0302 && /* TLS 1.0, 1.1 */
      ctx->version != 0x0303 /* TLS 1.2 & 1.3 */)
  {
    ctx->verdict = -ENOTSUP;
    return ctx->verdict;
  }
  while (ctx->bytesFed < 6+32 && sz)
  {
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  if (ctx->bytesFed < 6+32+1)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->sid_len = udata[0];
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  if (ctx->sid_len > 32)
  {
    ctx->verdict = -ENOTSUP;
    return ctx->verdict;
  }
  while (ctx->bytesFed < 6+32+1+ctx->sid_len)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  while (ctx->bytesFed < 6+32+1+ctx->sid_len+2)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->cs_len <<= 8;
    ctx->cs_len |= udata[0];
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  while (ctx->bytesFed < 6+32+1+ctx->sid_len+2+ctx->cs_len)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  while (ctx->bytesFed < 6+32+1+ctx->sid_len+2+ctx->cs_len+1)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->cm_len <<= 8;
    ctx->cm_len |= udata[0];
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  while (ctx->bytesFed < 6+32+1+ctx->sid_len+2+ctx->cs_len+1+ctx->cm_len)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  while (ctx->bytesFed < 6+32+1+ctx->sid_len+2+ctx->cs_len+1+ctx->cm_len+2)
  {
    if (sz == 0)
    {
      return ctx->verdict;
    }
    if (ctx->bytesFed >= ctx->handshake_len + 4)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->ext_len <<= 8;
    ctx->ext_len |= udata[0];
    ctx->bytesFed++;
    udata++;
    sz--;
  }
  uint32_t sofar = 6+32+1+ctx->sid_len+2+ctx->cs_len+1+ctx->cm_len+2+ctx->ext_len;
  while (sz > 0 && ctx->bytesFed < sofar) // FIXME condition incorrect
  {
    ssize_t ret;
    size_t tofeed;
    tofeed = sz;
    if (tofeed > ctx->bytesFed - sofar)
    {
      tofeed = ctx->bytesFed - sofar;
      if (tofeed == 0)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
    }
    if (tofeed > ctx->bytesFed - (ctx->handshake_len + 4))
    {
      tofeed = ctx->bytesFed - (ctx->handshake_len + 4);
      if (tofeed == 0)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
    }
    nam->len = 0;
    ret = ssl_ext_ctx_feed(&ctx->ext, udata, tofeed, nam);
    ctx->bytesFed += ret;
    sz -= ret;
    udata += ret;
    if (sz > 0)
    {
      ssl_ext_ctx_reinit(&ctx->ext);
    }
#if 1
    if (nam->len > 0)
    {
      ctx->verdict = 0;
      return ctx->verdict;
    }
#endif
  }

#if 0
  if (ctx->ext.nam.real_name_len > 0)
  {
    ctx->verdict = 0;
    return ctx->verdict;
  }
#endif

  if (ctx->bytesFed == sofar)
  {
    ctx->verdict = -ENOTSUP;
  }
  return ctx->verdict;
}


int ssl_fragment_ctx_feed(struct ssl_fragment_ctx *ctx,
                          const void *data, size_t sz,
                          struct hostname_ctx *nam)
{
  const unsigned char *udata = data;
  int hello_verdict;

  if (sz == 0 || ctx->verdict != -EAGAIN)
  {
    return ctx->verdict;
  }

  for (;;)
  {
    if (ctx->hdr_bytes_processed == 0)
    {
      if (sz == 0)
      {
        return ctx->verdict;
      }
      if (udata[0] != 22)
      {
        ctx->verdict = -ENOTSUP;
        return ctx->verdict;
      }
      ctx->hdr_bytes_processed++;
      udata++;
      sz--;
    }
    while (ctx->hdr_bytes_processed < 3)
    {
      if (sz == 0)
      {
        return ctx->verdict;
      }
      ctx->version <<= 8;
      ctx->version |= udata[0];
      ctx->hdr_bytes_processed++;
      udata++;
      sz--;
    }
  
    if (ctx->version != 0x0301 && ctx->version != 0x0302 && /* TLS 1.0, 1.1 */
        ctx->version != 0x0303 /* TLS 1.2 & 1.3 */)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    if (ctx->last_version && ctx->last_version != ctx->version)
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
    ctx->last_version = ctx->version;
  
    while (ctx->hdr_bytes_processed < 5)
    {
      if (sz == 0)
      {
        return ctx->verdict;
      }
      ctx->fragsiz <<= 8;
      ctx->fragsiz |= udata[0];
      ctx->hdr_bytes_processed++;
      udata++;
      sz--;
    }
    if (ctx->fragsiz > (1<<14))
    {
      ctx->verdict = -ENOTSUP;
      return ctx->verdict;
    }
  
    hello_verdict = ssl_ctx_feed(&ctx->hello, ctx->last_version, udata,
                                 sz <= ctx->fragsiz
                                 ? sz
                                 : ctx->fragsiz, nam);
    if (hello_verdict != -EAGAIN)
    {
      ctx->verdict = hello_verdict;
      return hello_verdict;
    }
    if (sz <= ctx->fragsiz)
    {
      return -EAGAIN;
    }
    sz -= ctx->fragsiz;
    udata += ctx->fragsiz;
    printf("calling ssl_fragment_ctx_reset\n");
    ssl_fragment_ctx_reset(ctx);
  }
}

void gen_1b_fragment(const void *hldata, int i, char fragment[6])
{
  const unsigned char *hludata = hldata;
  fragment[0] = 0x16;
  fragment[1] = 0x03;
  fragment[2] = 0x01;
  fragment[3] = 0;
  fragment[4] = 1;
  fragment[5] = hludata[i];
}

void http_test(void)
{
  struct http_ctx ctx = {};
  struct hostname_ctx nam = {};
  char *str1 = "GET / HTTP/1.1\r\nHost: www.google.fi\r\n\r\n";
  char *str2 = "GET / HTTP/1.1\r\nA: B\r\nHost: www.google.fi\r\n\r\n";
  char *str3 = "GET / HTTP/1.1\r\nA: B\r\n\r\nHost: www.google.fi\r\n\r\n";
  size_t i;
  int ret;

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  printf("1: %d\n", http_ctx_feed(&ctx, str1, strlen(str1), &nam));
  printf("%s\n", nam.hostname);

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  printf("2: %d\n", http_ctx_feed(&ctx, str2, strlen(str2), &nam));
  printf("%s\n", nam.hostname);

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  printf("3: %d\n", http_ctx_feed(&ctx, str3, strlen(str3), &nam));
  printf("%s\n", nam.hostname);

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < strlen(str1); i++)
  {
    ret = http_ctx_feed(&ctx, &str1[i], 1, &nam);
    if (ret != -EAGAIN)
    {
      printf("1: %d\n", ret);
      printf("%s\n", nam.hostname);
      break;
    }
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < strlen(str2); i++)
  {
    ret = http_ctx_feed(&ctx, &str2[i], 1, &nam);
    if (ret != -EAGAIN)
    {
      printf("2: %d\n", ret);
      printf("%s\n", nam.hostname);
      break;
    }
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < strlen(str3); i++)
  {
    ret = http_ctx_feed(&ctx, &str3[i], 1, &nam);
    if (ret != -EAGAIN)
    {
      printf("3: %d\n", ret);
      printf("%s\n", nam.hostname);
      break;
    }
  }
}

int main(int argc, char **argv)
{
  char fragment[6] = {0};
  char nosni[] = {
    0x16,0x03,0x01,0x00,0xab,0x01,0x00,0x00,
    0xa7,0x03,0x03,0xcf,0xb5,0x6a,0x3b,0x6f,
    0x38,0x2a,0x70,0xeb,0xee,0x7c,0x50,0x8b,
    0xbc,0xd0,0xea,0xcb,0xc6,0x7a,0xef,0x51,
    0xa3,0x59,0x67,0x6c,0x70,0xb9,0x76,0x75,
    0x78,0x3d,0xc5,0x00,0x00,0x38,0xc0,0x2c,
    0xc0,0x30,0x00,0x9f,0xcc,0xa9,0xcc,0xa8,
    0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0x00,0x9e,
    0xc0,0x24,0xc0,0x28,0x00,0x6b,0xc0,0x23,
    0xc0,0x27,0x00,0x67,0xc0,0x0a,0xc0,0x14,
    0x00,0x39,0xc0,0x09,0xc0,0x13,0x00,0x33,
    0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c,
    0x00,0x35,0x00,0x2f,0x00,0xff,0x01,0x00,
    0x00,0x46,0x00,0x0b,0x00,0x04,0x03,0x00,
    0x01,0x02,0x00,0x0a,0x00,0x0a,0x00,0x08,
    0x00,0x1d,0x00,0x17,0x00,0x19,0x00,0x18,
    0x00,0x23,0x00,0x00,0x00,0x16,0x00,0x00,
    0x00,0x17,0x00,0x00,0x00,0x0d,0x00,0x20,
    0x00,0x1e,0x06,0x01,0x06,0x02,0x06,0x03,
    0x05,0x01,0x05,0x02,0x05,0x03,0x04,0x01,
    0x04,0x02,0x04,0x03,0x03,0x01,0x03,0x02,
    0x03,0x03,0x02,0x01,0x02,0x02,0x02,0x03,
  };
  char nosnihl[] = {
    0x01,0x00,0x00,
    0xa7,0x03,0x03,0xcf,0xb5,0x6a,0x3b,0x6f,
    0x38,0x2a,0x70,0xeb,0xee,0x7c,0x50,0x8b,
    0xbc,0xd0,0xea,0xcb,0xc6,0x7a,0xef,0x51,
    0xa3,0x59,0x67,0x6c,0x70,0xb9,0x76,0x75,
    0x78,0x3d,0xc5,0x00,0x00,0x38,0xc0,0x2c,
    0xc0,0x30,0x00,0x9f,0xcc,0xa9,0xcc,0xa8,
    0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0x00,0x9e,
    0xc0,0x24,0xc0,0x28,0x00,0x6b,0xc0,0x23,
    0xc0,0x27,0x00,0x67,0xc0,0x0a,0xc0,0x14,
    0x00,0x39,0xc0,0x09,0xc0,0x13,0x00,0x33,
    0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c,
    0x00,0x35,0x00,0x2f,0x00,0xff,0x01,0x00,
    0x00,0x46,0x00,0x0b,0x00,0x04,0x03,0x00,
    0x01,0x02,0x00,0x0a,0x00,0x0a,0x00,0x08,
    0x00,0x1d,0x00,0x17,0x00,0x19,0x00,0x18,
    0x00,0x23,0x00,0x00,0x00,0x16,0x00,0x00,
    0x00,0x17,0x00,0x00,0x00,0x0d,0x00,0x20,
    0x00,0x1e,0x06,0x01,0x06,0x02,0x06,0x03,
    0x05,0x01,0x05,0x02,0x05,0x03,0x04,0x01,
    0x04,0x02,0x04,0x03,0x03,0x01,0x03,0x02,
    0x03,0x03,0x02,0x01,0x02,0x02,0x02,0x03,
  };
  char withsni[] = {
0x16,0x03,0x01,0x00,0xbd,0x01,0x00,0x00,0xb9,0x03,0x03,0x8a,0x80,0x22,0x0f,0x8d
,0x60,0x13,0x99,0x8b,0x4b,0xfa,0x96,0xba,0x7a,0xeb,0x81,0x60,0x80,0xe4,0xc7,0x9e
,0xd0,0x4e,0x18,0x4e,0xc5,0xd5,0x74,0x17,0x23,0xb1,0xa1,0x00,0x00,0x38,0xc0,0x2c
,0xc0,0x30,0x00,0x9f,0xcc,0xa9,0xcc,0xa8,0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0x00,0x9e
,0xc0,0x24,0xc0,0x28,0x00,0x6b,0xc0,0x23,0xc0,0x27,0x00,0x67,0xc0,0x0a,0xc0,0x14
,0x00,0x39,0xc0,0x09,0xc0,0x13,0x00,0x33,0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c
,0x00,0x35,0x00,0x2f,0x00,0xff,0x01,0x00,0x00,0x58,0x00,0x00,0x00,0x0e,0x00,0x0c
,0x00,0x00,0x09,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74,0x00,0x0b,0x00,0x04
,0x03,0x00,0x01,0x02,0x00,0x0a,0x00,0x0a,0x00,0x08,0x00,0x1d,0x00,0x17,0x00,0x19
,0x00,0x18,0x00,0x23,0x00,0x00,0x00,0x16,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x0d
,0x00,0x20,0x00,0x1e,0x06,0x01,0x06,0x02,0x06,0x03,0x05,0x01,0x05,0x02,0x05,0x03
,0x04,0x01,0x04,0x02,0x04,0x03,0x03,0x01,0x03,0x02,0x03,0x03,0x02,0x01,0x02,0x02
,0x02,0x03
  };
  char withsnihl[] = {
0x01,0x00,0x00,0xb9,0x03,0x03,0x8a,0x80,0x22,0x0f,0x8d
,0x60,0x13,0x99,0x8b,0x4b,0xfa,0x96,0xba,0x7a,0xeb,0x81,0x60,0x80,0xe4,0xc7,0x9e
,0xd0,0x4e,0x18,0x4e,0xc5,0xd5,0x74,0x17,0x23,0xb1,0xa1,0x00,0x00,0x38,0xc0,0x2c
,0xc0,0x30,0x00,0x9f,0xcc,0xa9,0xcc,0xa8,0xcc,0xaa,0xc0,0x2b,0xc0,0x2f,0x00,0x9e
,0xc0,0x24,0xc0,0x28,0x00,0x6b,0xc0,0x23,0xc0,0x27,0x00,0x67,0xc0,0x0a,0xc0,0x14
,0x00,0x39,0xc0,0x09,0xc0,0x13,0x00,0x33,0x00,0x9d,0x00,0x9c,0x00,0x3d,0x00,0x3c
,0x00,0x35,0x00,0x2f,0x00,0xff,0x01,0x00,0x00,0x58,0x00,0x00,0x00,0x0e,0x00,0x0c
,0x00,0x00,0x09,0x6c,0x6f,0x63,0x61,0x6c,0x68,0x6f,0x73,0x74,0x00,0x0b,0x00,0x04
,0x03,0x00,0x01,0x02,0x00,0x0a,0x00,0x0a,0x00,0x08,0x00,0x1d,0x00,0x17,0x00,0x19
,0x00,0x18,0x00,0x23,0x00,0x00,0x00,0x16,0x00,0x00,0x00,0x17,0x00,0x00,0x00,0x0d
,0x00,0x20,0x00,0x1e,0x06,0x01,0x06,0x02,0x06,0x03,0x05,0x01,0x05,0x02,0x05,0x03
,0x04,0x01,0x04,0x02,0x04,0x03,0x03,0x01,0x03,0x02,0x03,0x03,0x02,0x01,0x02,0x02
,0x02,0x03
  };
  struct ssl_fragment_ctx fragctx;
  size_t i;
  struct hostname_ctx nam;

  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);

  printf("%d\n", ssl_fragment_ctx_feed(&fragctx, withsni, sizeof(withsni), &nam));
  printf("%s\n", nam.hostname);

  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);

  printf("%d\n", ssl_fragment_ctx_feed(&fragctx, nosni, sizeof(nosni), &nam));
  printf("%s\n", nam.hostname);

  printf("---\n");
  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < sizeof(withsnihl); i++)
  {
    gen_1b_fragment(withsnihl, i, fragment);
    int ret = ssl_fragment_ctx_feed(&fragctx, fragment, sizeof(fragment), &nam);
    if (ret != -EAGAIN)
    {
      printf("%d\n", ret);
      printf("%s\n", nam.hostname);
      break;
    }
    ssl_fragment_ctx_reset(&fragctx);
  }

  printf("===\n");
  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < sizeof(nosnihl); i++)
  {
    gen_1b_fragment(nosnihl, i, fragment);
    int ret = ssl_fragment_ctx_feed(&fragctx, fragment, sizeof(fragment), &nam);
    if (ret != -EAGAIN)
    {
      printf("%d\n", ret);
      printf("%s\n", nam.hostname);
      break;
    }
    ssl_fragment_ctx_reset(&fragctx);
  }

  printf("HTTP\n");

  http_test();

  return 0;
}
