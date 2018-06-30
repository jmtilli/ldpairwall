#ifndef _THREETUPLE_H_
#define _THREETUPLE_H_

#include <stdint.h>
#include "hashtable.h"
#include "timerlink.h"
#include "udpporter.h"

struct threetuplepayload {
  uint16_t mss;
  uint8_t wscaleshift;
  uint8_t sack_supported:1;
  uint8_t mss_set:1;
  uint8_t sack_set:1;
  uint8_t wscaleshift_set:1;
  uint32_t local_ip;
  uint16_t local_port;
};

struct threetupleentry {
  struct hash_list_node node;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } ip;
  uint16_t port;
  uint8_t proto;
  uint8_t port_allocated:1;
  uint8_t consumable:1;
  uint8_t port_valid:1;
  uint8_t proto_valid:1;
  uint8_t inthost_set:1;
  uint8_t nonce_set:1;
  uint8_t version:4;
  struct timer_link timer;
  char nonce[96/8];
  struct threetuplepayload payload;
};

struct threetupleinthostcount {
  struct hash_list_node node;
  uint32_t local_ip;
  uint32_t count;
};

struct threetuplectx {
  struct hash_table tbl;
  struct hash_table int_tbl;
  struct udp_porter *porter;
  struct udp_porter *udp_porter;
};

void int_tbl_rm(struct threetuplectx *ctx, uint32_t local_ip);

int int_tbl_add(struct threetuplectx *ctx, uint32_t local_ip, uint32_t limit);

int threetuplectx_add(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64);

int threetuplectx_add6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64);

int threetuplectx_modify(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64);

int threetuplectx_modify_noadd_nonce(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port, 
  const void *nonce, uint64_t *old_expiry, uint16_t *old_ext_port);

int threetuplectx_modify_nonce(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port, 
  const void *nonce, uint64_t *old_expiry, uint32_t limit);

int threetuplectx_modify6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64);

int threetuplectx_delete(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid);

int threetuplectx_delete_nonce(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  uint32_t local_ip,
  uint16_t local_port, 
  const void *nonce, uint64_t *old_expiry, uint16_t *old_ext_port);

int threetuplectx_delete6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid);

int threetuplectx_find(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload);

int threetuplectx_find6(
  struct threetuplectx *ctx,
  const void *ipv6, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload);

int threetuplectx_consume(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload);

int threetuplectx_consume6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  const void *ipv6, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload);

void threetuplectx_flush(struct threetuplectx *ctx, struct timer_linkheap *heap);

void threetuplectx_flush_ip(struct threetuplectx *ctx, struct timer_linkheap *heap, uint32_t ip);

void threetuplectx_flush_ip6(struct threetuplectx *ctx, struct timer_linkheap *heap, const void *ipv6);

void threetuplectx_init(struct threetuplectx *ctx,
                        struct udp_porter *porter, struct udp_porter *udp_porter);

void threetuplectx_free(struct threetuplectx *ctx, struct timer_linkheap *heap);


#endif
