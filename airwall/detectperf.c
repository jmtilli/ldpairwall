#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/time.h>
#include "detect.h"

static void http_test(void)
{
  struct http_ctx ctx = {};
  struct hostname_ctx nam = {};
  char strsimple[] =
    "GET /foo/bar/baz/barf/quux.html HTTP/1.1\r\n"
    "Host: www.google.fi\r\n"
    "User-Agent: Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36\r\n"
    "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "Referer: http://www.google.fi/quux/barf/baz/bar/foo.html\r\n"
    "Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1;\r\n"
    "\r\n";
  char str[] =
    "GET /foo/bar/baz/barf/quux.html HTTP/1.1\r\n"
    "User-Agent: Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36\r\n"
    "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "Referer: http://www.google.fi/quux/barf/baz/bar/foo.html\r\n"
    "Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1;\r\n"
    "Host: www.google.fi\r\n"
    "\r\n";
  size_t i;
  int ret;
  struct timeval tv1, tv2;

  printf("size %zu\n", sizeof(str)-1);

  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    http_ctx_init(&ctx);
    hostname_ctx_init(&nam);
    ret = http_ctx_feed(&ctx, str, sizeof(str)-1, &nam);
    if (ret != 0)
    {
      abort();
    }
    if (strcmp(nam.hostname, "www.google.fi") != 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  printf("%g us\n", (tv2.tv_usec-tv1.tv_usec)/1e6 + (tv2.tv_sec-tv1.tv_sec));

  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    http_ctx_init(&ctx);
    hostname_ctx_init(&nam);
    ret = http_ctx_feed(&ctx, strsimple, sizeof(strsimple)-1, &nam);
    if (ret != 0)
    {
      abort();
    }
    if (strcmp(nam.hostname, "www.google.fi") != 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  printf("simple: %g us\n", (tv2.tv_usec-tv1.tv_usec)/1e6 + (tv2.tv_sec-tv1.tv_sec));
}

static void http_proto_test(void)
{
  struct proto_detect_ctx ctx = {};
  char strsimple[] =
    "GET /foo/bar/baz/barf/quux.html HTTP/1.1\r\n"
    "Host: www.google.fi\r\n"
    "User-Agent: Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36\r\n"
    "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "Referer: http://www.google.fi/quux/barf/baz/bar/foo.html\r\n"
    "Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1;\r\n"
    "\r\n";
  char str[] =
    "GET /foo/bar/baz/barf/quux.html HTTP/1.1\r\n"
    "User-Agent: Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36\r\n"
    "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "Referer: http://www.google.fi/quux/barf/baz/bar/foo.html\r\n"
    "Cookie: PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1;\r\n"
    "Host: www.google.fi\r\n"
    "\r\n";
  size_t i;
  int ret;
  struct timeval tv1, tv2;

  printf("size %zu\n", sizeof(str)-1);

  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    proto_detect_ctx_init(&ctx);
    ret = proto_detect_feed(&ctx, str, 0, sizeof(str)-1, NULL);
    if (ret != 0)
    {
      abort();
    }
    if (strcmp(ctx.hostctx.hostname, "www.google.fi") != 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  printf("proto: %g us\n", (tv2.tv_usec-tv1.tv_usec)/1e6 + (tv2.tv_sec-tv1.tv_sec));

  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    proto_detect_ctx_init(&ctx);
    ret = proto_detect_feed(&ctx, strsimple, 0, sizeof(strsimple)-1, NULL);
    if (ret != 0)
    {
      abort();
    }
    if (strcmp(ctx.hostctx.hostname, "www.google.fi") != 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  printf("protosimple: %g us\n", (tv2.tv_usec-tv1.tv_usec)/1e6 + (tv2.tv_sec-tv1.tv_sec));
}

int main(int argc, char **argv)
{
  char withsni[] = {
(char)0x16,(char)0x03,(char)0x01,(char)0x00,(char)0xbd,(char)0x01,(char)0x00,(char)0x00,(char)0xb9,(char)0x03,(char)0x03,(char)0x8a,(char)0x80,(char)0x22,(char)0x0f,(char)0x8d
,(char)0x60,(char)0x13,(char)0x99,(char)0x8b,(char)0x4b,(char)0xfa,(char)0x96,(char)0xba,(char)0x7a,(char)0xeb,(char)0x81,(char)0x60,(char)0x80,(char)0xe4,(char)0xc7,(char)0x9e
,(char)0xd0,(char)0x4e,(char)0x18,(char)0x4e,(char)0xc5,(char)0xd5,(char)0x74,(char)0x17,(char)0x23,(char)0xb1,(char)0xa1,(char)0x00,(char)0x00,(char)0x38,(char)0xc0,(char)0x2c
,(char)0xc0,(char)0x30,(char)0x00,(char)0x9f,(char)0xcc,(char)0xa9,(char)0xcc,(char)0xa8,(char)0xcc,(char)0xaa,(char)0xc0,(char)0x2b,(char)0xc0,(char)0x2f,(char)0x00,(char)0x9e
,(char)0xc0,(char)0x24,(char)0xc0,(char)0x28,(char)0x00,(char)0x6b,(char)0xc0,(char)0x23,(char)0xc0,(char)0x27,(char)0x00,(char)0x67,(char)0xc0,(char)0x0a,(char)0xc0,(char)0x14
,(char)0x00,(char)0x39,(char)0xc0,(char)0x09,(char)0xc0,(char)0x13,(char)0x00,(char)0x33,(char)0x00,(char)0x9d,(char)0x00,(char)0x9c,(char)0x00,(char)0x3d,(char)0x00,(char)0x3c
,(char)0x00,(char)0x35,(char)0x00,(char)0x2f,(char)0x00,(char)0xff,(char)0x01,(char)0x00,(char)0x00,(char)0x58,(char)0x00,(char)0x00,(char)0x00,(char)0x0e,(char)0x00,(char)0x0c
,(char)0x00,(char)0x00,(char)0x09,(char)0x6c,(char)0x6f,(char)0x63,(char)0x61,(char)0x6c,(char)0x68,(char)0x6f,(char)0x73,(char)0x74,(char)0x00,(char)0x0b,(char)0x00,(char)0x04
,(char)0x03,(char)0x00,(char)0x01,(char)0x02,(char)0x00,(char)0x0a,(char)0x00,(char)0x0a,(char)0x00,(char)0x08,(char)0x00,(char)0x1d,(char)0x00,(char)0x17,(char)0x00,(char)0x19
,(char)0x00,(char)0x18,(char)0x00,(char)0x23,(char)0x00,(char)0x00,(char)0x00,(char)0x16,(char)0x00,(char)0x00,(char)0x00,(char)0x17,(char)0x00,(char)0x00,(char)0x00,(char)0x0d
,(char)0x00,(char)0x20,(char)0x00,(char)0x1e,(char)0x06,(char)0x01,(char)0x06,(char)0x02,(char)0x06,(char)0x03,(char)0x05,(char)0x01,(char)0x05,(char)0x02,(char)0x05,(char)0x03
,(char)0x04,(char)0x01,(char)0x04,(char)0x02,(char)0x04,(char)0x03,(char)0x03,(char)0x01,(char)0x03,(char)0x02,(char)0x03,(char)0x03,(char)0x02,(char)0x01,(char)0x02,(char)0x02
,(char)0x02,(char)0x03
  };
  struct proto_detect_ctx ctx = {};
  struct ssl_fragment_ctx fragctx;
  size_t i;
  struct timeval tv1, tv2;
  struct hostname_ctx nam;
  int ret;

  printf("withsni size %zu\n", sizeof(withsni));

  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    ssl_fragment_ctx_init(&fragctx);
    hostname_ctx_init(&nam);
  
    ret = ssl_fragment_ctx_feed(&fragctx, withsni, sizeof(withsni), &nam);
    if (ret != 0)
    {
      abort();
    }
    if (strcmp(nam.hostname, "localhost") != 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  printf("SSL: %g us\n", (tv2.tv_usec-tv1.tv_usec)/1e6 + (tv2.tv_sec-tv1.tv_sec));

  gettimeofday(&tv1, NULL);
  for (i = 0; i < 1000*1000; i++)
  {
    proto_detect_ctx_init(&ctx);

    ret = proto_detect_feed(&ctx, withsni, 0, sizeof(withsni), NULL);
    if (ret != 0)
    {
      abort();
    }
    if (strcmp(nam.hostname, "localhost") != 0)
    {
      abort();
    }
  }
  gettimeofday(&tv2, NULL);
  printf("SSL proto: %g us\n", (tv2.tv_usec-tv1.tv_usec)/1e6 + (tv2.tv_sec-tv1.tv_sec));

  printf("HTTP\n");

  http_test();

  printf("HTTP proto\n");

  http_proto_test();

  return 0;
}
