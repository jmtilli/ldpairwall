#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "detect.h"

static void gen_1b_fragment(const void *hldata, int i, char fragment[6])
{
  const unsigned char *hludata = hldata;
  fragment[0] = 0x16;
  fragment[1] = 0x03;
  fragment[2] = 0x01;
  fragment[3] = 0;
  fragment[4] = 1;
  fragment[5] = (char)hludata[i];
}

static void http_connect_test(void)
{
  struct http_ctx ctx = {};
  struct hostname_ctx nam = {};
  char *str0 = "CONNECT example.host.com:22 HTTP/1.1\r\n\r\n";
  char *str1 = "CONNECT example.host.com:22 HTTP/1.1\r\nHost: www.google.fi\r\n\r\n";
  char *str2 = "CONNECT example.host.com:22 HTTP/1.1\r\nA: B\r\nHost: www.google.fi\r\n\r\n";
  char *str3 = "CONNECT example.host.com:22 HTTP/1.1\r\nA: B\r\n\r\nHost: www.google.fi\r\n\r\n";
  char *str3_reqonly = "CONNECT example.host.com:22 HTTP/1.1\r\nA: B\r\n\r\n";
  int ret;

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str0, strlen(str0), &nam);
  printf("0: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    printf("ret err\n");
    abort();
  }
  if (strcmp(nam.hostname, "example.host.com:22") != 0)
  {
    printf("host err\n");
    abort();
  }
  if (nam.is_http_connect_num_bytes != strlen(str0))
  {
    printf("num err %d %d\n", nam.is_http_connect_num_bytes, (int)strlen(str0));
    abort();
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str1, strlen(str1), &nam);
  printf("1: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    printf("ret err\n");
    abort();
  }
  if (strcmp(nam.hostname, "example.host.com:22") != 0)
  {
    printf("host err\n");
    abort();
  }
  if (nam.is_http_connect_num_bytes != strlen(str1))
  {
    printf("num err %d %d\n", nam.is_http_connect_num_bytes, (int)strlen(str1));
    abort();
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str2, strlen(str2), &nam);
  printf("2: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "example.host.com:22") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != strlen(str2))
  {
    abort();
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str3, strlen(str3), &nam);
  printf("3: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "example.host.com:22") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != strlen(str3_reqonly))
  {
    abort();
  }
}

static void http_test(void)
{
  struct http_ctx ctx = {};
  struct hostname_ctx nam = {};
  char *str1 = "GET / HTTP/1.1\r\nHost: www.google.fi\r\n\r\n";
  char *str2 = "GET / HTTP/1.1\r\nA: B\r\nHost: www.google.fi\r\n\r\n";
  char *str3 = "GET / HTTP/1.1\r\nA: B\r\n\r\nHost: www.google.fi\r\n\r\n";
  char *strnocr = "GET / HTTP/1.1\nHost: www.google.fi\n\n";
  size_t i;
  int ret;

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, strnocr, strlen(strnocr), &nam);
  printf("nocr: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "www.google.fi") != 0)
  {
    abort();
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str1, strlen(str1), &nam);
  printf("1: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "www.google.fi") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != 0)
  {
    abort();
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str2, strlen(str2), &nam);
  printf("2: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "www.google.fi") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != 0)
  {
    abort();
  }

  http_ctx_init(&ctx);
  hostname_ctx_init(&nam);
  ret = http_ctx_feed(&ctx, str3, strlen(str3), &nam);
  printf("3: %d\n", ret);
  printf("%s\n", nam.hostname);
  if (ret != -95)
  {
    abort();
  }
  if (strcmp(nam.hostname, "") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != 0)
  {
    abort();
  }

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
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "www.google.fi") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != 0)
  {
    abort();
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
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "www.google.fi") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != 0)
  {
    abort();
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
  if (ret != -95)
  {
    abort();
  }
  if (strcmp(nam.hostname, "") != 0)
  {
    abort();
  }
  if (nam.is_http_connect_num_bytes != 0)
  {
    abort();
  }
}

int main(int argc, char **argv)
{
  char fragment[6] = {0};
  char nosni[] = {
    (char)0x16,(char)0x03,(char)0x01,(char)0x00,(char)0xab,(char)0x01,(char)0x00,(char)0x00,
    (char)0xa7,(char)0x03,(char)0x03,(char)0xcf,(char)0xb5,(char)0x6a,(char)0x3b,(char)0x6f,
    (char)0x38,(char)0x2a,(char)0x70,(char)0xeb,(char)0xee,(char)0x7c,(char)0x50,(char)0x8b,
    (char)0xbc,(char)0xd0,(char)0xea,(char)0xcb,(char)0xc6,(char)0x7a,(char)0xef,(char)0x51,
    (char)0xa3,(char)0x59,(char)0x67,(char)0x6c,(char)0x70,(char)0xb9,(char)0x76,(char)0x75,
    (char)0x78,(char)0x3d,(char)0xc5,(char)0x00,(char)0x00,(char)0x38,(char)0xc0,(char)0x2c,
    (char)0xc0,(char)0x30,(char)0x00,(char)0x9f,(char)0xcc,(char)0xa9,(char)0xcc,(char)0xa8,
    (char)0xcc,(char)0xaa,(char)0xc0,(char)0x2b,(char)0xc0,(char)0x2f,(char)0x00,(char)0x9e,
    (char)0xc0,(char)0x24,(char)0xc0,(char)0x28,(char)0x00,(char)0x6b,(char)0xc0,(char)0x23,
    (char)0xc0,(char)0x27,(char)0x00,(char)0x67,(char)0xc0,(char)0x0a,(char)0xc0,(char)0x14,
    (char)0x00,(char)0x39,(char)0xc0,(char)0x09,(char)0xc0,(char)0x13,(char)0x00,(char)0x33,
    (char)0x00,(char)0x9d,(char)0x00,(char)0x9c,(char)0x00,(char)0x3d,(char)0x00,(char)0x3c,
    (char)0x00,(char)0x35,(char)0x00,(char)0x2f,(char)0x00,(char)0xff,(char)0x01,(char)0x00,
    (char)0x00,(char)0x46,(char)0x00,(char)0x0b,(char)0x00,(char)0x04,(char)0x03,(char)0x00,
    (char)0x01,(char)0x02,(char)0x00,(char)0x0a,(char)0x00,(char)0x0a,(char)0x00,(char)0x08,
    (char)0x00,(char)0x1d,(char)0x00,(char)0x17,(char)0x00,(char)0x19,(char)0x00,(char)0x18,
    (char)0x00,(char)0x23,(char)0x00,(char)0x00,(char)0x00,(char)0x16,(char)0x00,(char)0x00,
    (char)0x00,(char)0x17,(char)0x00,(char)0x00,(char)0x00,(char)0x0d,(char)0x00,(char)0x20,
    (char)0x00,(char)0x1e,(char)0x06,(char)0x01,(char)0x06,(char)0x02,(char)0x06,(char)0x03,
    (char)0x05,(char)0x01,(char)0x05,(char)0x02,(char)0x05,(char)0x03,(char)0x04,(char)0x01,
    (char)0x04,(char)0x02,(char)0x04,(char)0x03,(char)0x03,(char)0x01,(char)0x03,(char)0x02,
    (char)0x03,(char)0x03,(char)0x02,(char)0x01,(char)0x02,(char)0x02,(char)0x02,(char)0x03,
  };
  char nosnihl[] = {
    (char)0x01,(char)0x00,(char)0x00,
    (char)0xa7,(char)0x03,(char)0x03,(char)0xcf,(char)0xb5,(char)0x6a,(char)0x3b,(char)0x6f,
    (char)0x38,(char)0x2a,(char)0x70,(char)0xeb,(char)0xee,(char)0x7c,(char)0x50,(char)0x8b,
    (char)0xbc,(char)0xd0,(char)0xea,(char)0xcb,(char)0xc6,(char)0x7a,(char)0xef,(char)0x51,
    (char)0xa3,(char)0x59,(char)0x67,(char)0x6c,(char)0x70,(char)0xb9,(char)0x76,(char)0x75,
    (char)0x78,(char)0x3d,(char)0xc5,(char)0x00,(char)0x00,(char)0x38,(char)0xc0,(char)0x2c,
    (char)0xc0,(char)0x30,(char)0x00,(char)0x9f,(char)0xcc,(char)0xa9,(char)0xcc,(char)0xa8,
    (char)0xcc,(char)0xaa,(char)0xc0,(char)0x2b,(char)0xc0,(char)0x2f,(char)0x00,(char)0x9e,
    (char)0xc0,(char)0x24,(char)0xc0,(char)0x28,(char)0x00,(char)0x6b,(char)0xc0,(char)0x23,
    (char)0xc0,(char)0x27,(char)0x00,(char)0x67,(char)0xc0,(char)0x0a,(char)0xc0,(char)0x14,
    (char)0x00,(char)0x39,(char)0xc0,(char)0x09,(char)0xc0,(char)0x13,(char)0x00,(char)0x33,
    (char)0x00,(char)0x9d,(char)0x00,(char)0x9c,(char)0x00,(char)0x3d,(char)0x00,(char)0x3c,
    (char)0x00,(char)0x35,(char)0x00,(char)0x2f,(char)0x00,(char)0xff,(char)0x01,(char)0x00,
    (char)0x00,(char)0x46,(char)0x00,(char)0x0b,(char)0x00,(char)0x04,(char)0x03,(char)0x00,
    (char)0x01,(char)0x02,(char)0x00,(char)0x0a,(char)0x00,(char)0x0a,(char)0x00,(char)0x08,
    (char)0x00,(char)0x1d,(char)0x00,(char)0x17,(char)0x00,(char)0x19,(char)0x00,(char)0x18,
    (char)0x00,(char)0x23,(char)0x00,(char)0x00,(char)0x00,(char)0x16,(char)0x00,(char)0x00,
    (char)0x00,(char)0x17,(char)0x00,(char)0x00,(char)0x00,(char)0x0d,(char)0x00,(char)0x20,
    (char)0x00,(char)0x1e,(char)0x06,(char)0x01,(char)0x06,(char)0x02,(char)0x06,(char)0x03,
    (char)0x05,(char)0x01,(char)0x05,(char)0x02,(char)0x05,(char)0x03,(char)0x04,(char)0x01,
    (char)0x04,(char)0x02,(char)0x04,(char)0x03,(char)0x03,(char)0x01,(char)0x03,(char)0x02,
    (char)0x03,(char)0x03,(char)0x02,(char)0x01,(char)0x02,(char)0x02,(char)0x02,(char)0x03,
  };
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
  char withsnihl[] = {
(char)0x01,(char)0x00,(char)0x00,(char)0xb9,(char)0x03,(char)0x03,(char)0x8a,(char)0x80,(char)0x22,(char)0x0f,(char)0x8d
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
  struct ssl_fragment_ctx fragctx;
  size_t i, j;
  struct hostname_ctx nam;
  int ret;

  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);

  ret = ssl_fragment_ctx_feed(&fragctx, withsni, sizeof(withsni), &nam);
  printf("%d (expected 0)\n", ret);
  printf("%s (expected localhost)\n", nam.hostname);

  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);

  ret = ssl_fragment_ctx_feed(&fragctx, nosni, sizeof(nosni), &nam);
  printf("%d (expected -95)\n", ret);
  printf("%s (expected )\n", nam.hostname);

  printf("---\n");
  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < sizeof(withsnihl); i++)
  {
    gen_1b_fragment(withsnihl, i, fragment);
    ret = ssl_fragment_ctx_feed(&fragctx, fragment, sizeof(fragment), &nam);
    if (ret != -EAGAIN)
    {
      printf("%d (expected 0)\n", ret);
      printf("%s (exptected localhost)\n", nam.hostname);
      break;
    }
    //ssl_fragment_ctx_reset(&fragctx); // FIXME should this be automatic?
  }
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "localhost") != 0)
  {
    abort();
  }

  printf("===\n");
  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < sizeof(nosnihl); i++)
  {
    gen_1b_fragment(nosnihl, i, fragment);
    ret = ssl_fragment_ctx_feed(&fragctx, fragment, sizeof(fragment), &nam);
    if (ret != -EAGAIN)
    {
      printf("%d (expected -95)\n", ret);
      printf("%s (expected )\n", nam.hostname);
      break;
    }
    //ssl_fragment_ctx_reset(&fragctx); // FIXME should this be automatic?
  }
  if (ret != -95)
  {
    abort();
  }
  if (strcmp(nam.hostname, "") != 0)
  {
    abort();
  }

  printf("###\n");
  ssl_fragment_ctx_init(&fragctx);
  hostname_ctx_init(&nam);
  for (i = 0; i < sizeof(withsnihl); i++)
  {
    gen_1b_fragment(withsnihl, i, fragment);
    for (j = 0; j < sizeof(fragment); j++)
    {
        ret = ssl_fragment_ctx_feed(&fragctx, fragment+j, 1, &nam);
        if (ret != -EAGAIN)
        {
          printf("%d (expected 0)\n", ret);
          printf("%s (expected localhost)\n", nam.hostname);
          goto out;
        }
    }
    //ssl_fragment_ctx_reset(&fragctx);
  }
out:
  if (ret != 0)
  {
    abort();
  }
  if (strcmp(nam.hostname, "localhost") != 0)
  {
    abort();
  }

  printf("HTTP\n");

  http_test();

  http_connect_test();

  return 0;
}
