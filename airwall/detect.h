#ifndef _DETECT_H_
#define _DETECT_H_

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

void hostname_ctx_init(struct hostname_ctx *nam);

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

void http_ctx_init(struct http_ctx *ctx);

int http_ctx_feed(struct http_ctx *ctx, const void *data, size_t sz,
                  struct hostname_ctx *nam);

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

void ssl_name_ctx_reinit(struct ssl_name_ctx *ctx);

void ssl_name_ctx_init(struct ssl_name_ctx *ctx);

// Return: # of bytes processed
ssize_t ssl_name_ctx_feed(struct ssl_name_ctx *ctx, const void *data, size_t sz,
                          struct hostname_ctx *nam);

void ssl_ext_ctx_init(struct ssl_ext_ctx *ctx);

void ssl_ext_ctx_reinit(struct ssl_ext_ctx *ctx);

// Return: # of bytes processed
ssize_t ssl_ext_ctx_feed(struct ssl_ext_ctx *ctx, const void *data, size_t sz,
                         struct hostname_ctx *nam);

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

void ssl_ctx_init(struct ssl_ctx *ctx);

void ssl_fragment_ctx_init(struct ssl_fragment_ctx *ctx);

void ssl_fragment_ctx_reset(struct ssl_fragment_ctx *ctx);

int ssl_ctx_feed(struct ssl_ctx *ctx, uint16_t exp_vers,
                 const void *data, size_t sz, struct hostname_ctx *nam);


int ssl_fragment_ctx_feed(struct ssl_fragment_ctx *ctx,
                          const void *data, size_t sz,
                          struct hostname_ctx *nam);

struct proto_detect_ctx {
  uint32_t init_data_sz;
  char init_data[4096];
  uint32_t max_bitmask;
  uint64_t init_bitmask[4096/64];
  uint32_t init_data_fed;
  struct hostname_ctx hostctx;
  struct ssl_fragment_ctx fragctx;
  struct http_ctx httpctx;
  uint32_t acked;
};

static inline void proto_detect_ctx_init(struct proto_detect_ctx *ctx)
{
  ctx->init_data_sz = sizeof(ctx->init_data);
  memset(ctx->init_bitmask, 0, sizeof(ctx->init_bitmask));
  ctx->max_bitmask = 0;
  ctx->init_data_fed = 0;
  ctx->max_bitmask = 0;
  ctx->acked = 0;
  hostname_ctx_init(&ctx->hostctx);
  ssl_fragment_ctx_init(&ctx->fragctx);
  http_ctx_init(&ctx->httpctx);
}

int proto_detect_feed(struct proto_detect_ctx *ctx,
                      const void *data, size_t start_off, size_t sz,
                      uint32_t *ack);

#endif
