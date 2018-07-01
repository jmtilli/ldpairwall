#ifndef _THREETUPLE2_H_
#define _THREETUPLE2_H_

#include <stdint.h>
#include "hashtable.h"
#include "timerlink.h"
#include "udpporter.h"

struct threetuple2entry {
  struct hash_list_node nat_node;
  struct hash_list_node local_node;
  struct timer_link timer;
  uint32_t nat_ip;
  uint32_t local_ip;
  uint16_t nat_port;
  uint16_t local_port;
  uint8_t proto;
  uint8_t port_allocated:1;
  uint8_t consumable:1;
  uint8_t inthost_set:1;
  uint8_t nonce_set:1;
  char nonce[96/8];
};

struct threetuple2inthostcount {
  struct hash_list_node node;
  uint32_t local_ip;
  uint32_t count;
};

struct threetuple2ctx {
  struct hash_table nat_tbl;
  struct hash_table local_tbl;
  struct hash_table int_tbl;
  struct udp_porter *porter;
  struct udp_porter *udp_porter;
};

void int_tbl2_rm(struct threetuple2ctx *ctx, uint32_t local_ip);

int int_tbl2_add(struct threetuple2ctx *ctx, uint32_t local_ip, uint32_t limit);

int threetuple2ctx_add(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto,
  uint32_t local_ip, uint16_t local_port,
  uint64_t expire_time64);

int threetuple2ctx_modify_noadd_nonce(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  int port_allocated,
  uint8_t proto,
  uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce, uint64_t *old_expiry, uint16_t *old_ext_port,
  uint32_t *old_ext_ip);

int threetuple2ctx_add_nonce(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto,
  uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port, 
  const void *nonce, uint64_t *old_expiry, uint32_t limit);

int threetuple2ctx_delete_nonce(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  uint8_t proto,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce, uint64_t *old_expiry, uint16_t *old_ext_port,
  uint32_t *old_ext_ip);

int threetuple2ctx_consume(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto,
  uint32_t *local_ip, uint16_t *local_port);

void threetuple2ctx_init(struct threetuple2ctx *ctx,
                        struct udp_porter *porter, struct udp_porter *udp_porter);

void threetuple2ctx_free(struct threetuple2ctx *ctx, struct timer_linkheap *heap);


#endif
