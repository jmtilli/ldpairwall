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

int main(int argc, char **argv)
{
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

  printf("HTTP\n");

  http_test();

  return 0;
}
