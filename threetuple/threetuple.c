#include <stdint.h>
#include <errno.h>
#include "siphash.h"
#include "hashseed.h"
#include "hashtable.h"
#include "containerof.h"
#include "threetuple.h"


static inline uint32_t threetuple_iphash(uint32_t ip)
{
  return siphash64(hash_seed_get(), ip);
}

static inline uint32_t threetuple_ip6hash(const void *ipv6)
{
  return siphash_buf(hash_seed_get(), ipv6, 16);
}

static inline uint32_t threetuple_hash(struct threetupleentry *e)
{
  if (e->version == 4)
  {
    return threetuple_iphash(e->ip.ipv4);
  }
  else
  {
    return threetuple_ip6hash(&e->ip);
  }
}


static uint32_t threetuple_hash_fn(struct hash_list_node *node, void *userdata)
{
  struct threetupleentry *e = CONTAINER_OF(node, struct threetupleentry, node);
  return threetuple_hash(e);
}

#define RGW_TIMEOUT_SECS 2

static void threetuplectx_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct threetupleentry *e =
    CONTAINER_OF(timer, struct threetupleentry, timer);
  uint32_t hashval = threetuple_hash(e);
  struct threetuplectx *ctx = ud;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  if (e->port_allocated)
  {
    if (!e->proto_valid)
    {
      deallocate_udp_port(ctx->porter, e->port, 0);
      deallocate_udp_port(ctx->udp_porter, e->port, 0);
    }
    else if (e->proto == 6)
    {
      deallocate_udp_port(ctx->porter, e->port, 0);
    }
    else if (e->proto == 17)
    {
      deallocate_udp_port(ctx->udp_porter, e->port, 0);
    }
    else
    {
      abort();
    }
  }
  free(e);
}

int threetuplectx_add(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64)
{
  struct threetupleentry *e = malloc(sizeof(*e));
  uint32_t hashval;
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }

#if 0
  if (allocate_port)
  {
    if (proto == 0)
    {
      allocate_udp_port(ctx->porter, port, payload->local_ip, payload->local_port, 0);
      allocate_udp_port(ctx->udp_porter, port, payload->local_ip, payload->local_port, 0);
    }
    else if (proto == 6)
    {
      allocate_udp_port(ctx->porter, port, payload->local_ip, payload->local_port, 0);
    }
    else if (proto == 17)
    {
      allocate_udp_port(ctx->udp_porter, port, payload->local_ip, payload->local_port, 0);
    }
    else
    {
      abort();
    }
  }
#endif
  e->nonce_set = 0;
  e->port_allocated = port_allocated;
  e->consumable = consumable;
  e->version = 4;
  e->ip.ipv4 = ip;
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  e->timer.userdata = ctx;
  e->timer.fn = threetuplectx_expiry_fn;
  e->timer.time64 = time64 + RGW_TIMEOUT_SECS*1000ULL*1000ULL;
  hashval = threetuple_hash(e);
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e2 =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e2->version == e->version && e2->ip.ipv4 == ip &&
        (e2->port == port || !e2->port_valid) &&
        (e2->proto == proto || !e2->proto_valid))
    {
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      free(e);
      return -EEXIST;
    }
  }
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_add6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64)
{
  struct threetupleentry *e = malloc(sizeof(*e));
  uint32_t hashval;
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  e->nonce_set = 0;
  e->port_allocated = port_allocated;
  e->consumable = consumable;
  e->version = 6;
  memcpy(&e->ip, ipv6, 16);
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  e->timer.userdata = ctx;
  e->timer.fn = threetuplectx_expiry_fn;
  e->timer.time64 = time64 + RGW_TIMEOUT_SECS*1000ULL*1000ULL;
  hashval = threetuple_hash(e);
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e2 =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e2->version == e->version && memcmp(&e2->ip, ipv6, 16) == 0 &&
        (e2->port == port || !e2->port_valid) &&
        (e2->proto == proto || !e2->proto_valid))
    {
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      free(e);
      return -EEXIST;
    }
  }
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_modify(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      if (e->port_allocated != port_allocated)
      {
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      e->consumable = consumable;
      e->payload = *payload;
      e->timer.time64 = time64 + RGW_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(heap, &e->timer);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  struct threetupleentry *e = malloc(sizeof(*e));
  e->nonce_set = 0;
  e->consumable = consumable;
  e->port_allocated = port_allocated;
  e->version = 4;
  e->ip.ipv4 = ip;
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  e->timer.userdata = ctx;
  e->timer.fn = threetuplectx_expiry_fn;
  e->timer.time64 = time64 + RGW_TIMEOUT_SECS*1000ULL*1000ULL;
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_modify_noadd_nonce(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce,
  uint64_t *old_expiry,
  uint16_t *old_ext_port)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
    abort();
  }
  if (!proto_valid)
  {
    proto = 0;
    abort();
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid &&
        e->payload.local_ip == local_ip && e->payload.local_port == local_port)
    {
      if (e->port_allocated != port_allocated || !e->nonce_set ||
          memcmp(e->nonce, nonce, 96/8) != 0)
      {
        if (old_expiry)
        {
          *old_expiry = e->timer.time64;
        }
        if (old_ext_port)
        {
          *old_ext_port = e->port;
        }
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      e->consumable = consumable;
      e->payload = *payload;
      e->timer.time64 = expire_time64;
      timer_linkheap_modify(heap, &e->timer);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      if (old_ext_port)
      {
        *old_ext_port = e->port;
      }
      return 0;
    }
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      if (e->port_allocated != port_allocated || !e->nonce_set ||
          memcmp(e->nonce, nonce, 96/8) != 0 ||
          e->payload.local_ip != local_ip ||
          e->payload.local_port != local_port)
      {
        if (old_expiry)
        {
          *old_expiry = e->timer.time64;
        }
        if (old_ext_port)
        {
          *old_ext_port = e->port;
        }
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      e->consumable = consumable;
      e->payload = *payload;
      e->timer.time64 = expire_time64;
      timer_linkheap_modify(heap, &e->timer);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      if (old_ext_port)
      {
        *old_ext_port = e->port;
      }
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_modify_nonce(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce,
  uint64_t *old_expiry)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
    abort();
  }
  if (!proto_valid)
  {
    proto = 0;
    abort();
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid &&
        e->payload.local_ip == local_ip && e->payload.local_port == local_port)
    {
      if (e->port_allocated != port_allocated || !e->nonce_set ||
          memcmp(e->nonce, nonce, 96/8) != 0)
      {
        if (old_expiry)
        {
          *old_expiry = e->timer.time64;
        }
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      e->consumable = consumable;
      e->payload = *payload;
      e->timer.time64 = expire_time64;
      timer_linkheap_modify(heap, &e->timer);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      if (e->port_allocated != port_allocated || !e->nonce_set ||
          memcmp(e->nonce, nonce, 96/8) != 0 ||
          e->payload.local_ip != local_ip ||
          e->payload.local_port != local_port)
      {
        if (old_expiry)
        {
          *old_expiry = e->timer.time64;
        }
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      e->consumable = consumable;
      e->payload = *payload;
      e->timer.time64 = expire_time64;
      timer_linkheap_modify(heap, &e->timer);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  struct threetupleentry *e = malloc(sizeof(*e));
  memcpy(e->nonce, nonce, 96/8);
  e->nonce_set = 1;
  e->consumable = consumable;
  e->port_allocated = port_allocated;
  e->version = 4;
  e->ip.ipv4 = ip;
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  e->timer.userdata = ctx;
  e->timer.fn = threetuplectx_expiry_fn;
  e->timer.time64 = expire_time64;
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_modify6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload, uint64_t time64)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      if (e->port_allocated != port_allocated)
      {
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      e->consumable = consumable;
      e->payload = *payload;
      e->timer.time64 = time64 + RGW_TIMEOUT_SECS*1000ULL*1000ULL;
      timer_linkheap_modify(heap, &e->timer);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  struct threetupleentry *e = malloc(sizeof(*e));
  e->nonce_set = 0;
  e->consumable = consumable;
  e->port_allocated = port_allocated;
  e->version = 6;
  memcpy(&e->ip, ipv6, 16);
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  e->timer.userdata = ctx;
  e->timer.fn = threetuplectx_expiry_fn;
  e->timer.time64 = time64 + RGW_TIMEOUT_SECS*1000ULL*1000ULL;
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_find(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      if (payload)
      {
        *payload = e->payload;
      }
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_consume(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      if (payload)
      {
        *payload = e->payload;
      }
      if (e->consumable)
      {
        hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
        timer_linkheap_remove(heap, &e->timer);
        if (e->port_allocated)
        {
          if (!e->proto_valid)
          {
            deallocate_udp_port(ctx->porter, port, 0);
            deallocate_udp_port(ctx->udp_porter, port, 0);
          }
          else if (e->proto == 6)
          {
            deallocate_udp_port(ctx->porter, port, 0);
          }
          else if (e->proto == 17)
          {
            deallocate_udp_port(ctx->udp_porter, port, 0);
          }
          else
          {
            abort();
          }
        }
        free(e);
      }
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_find6(
  struct threetuplectx *ctx,
  const void *ipv6, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      if (payload)
      {
        *payload = e->payload;
      }
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_consume6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  const void *ipv6, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      if (payload)
      {
        *payload = e->payload;
      }
      if (e->consumable)
      {
        hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
        timer_linkheap_remove(heap, &e->timer);
        if (e->port_allocated)
        {
          if (!e->proto_valid)
          {
            deallocate_udp_port(ctx->porter, port, 0);
            deallocate_udp_port(ctx->udp_porter, port, 0);
          }
          else if (e->proto == 6)
          {
            deallocate_udp_port(ctx->porter, port, 0);
          }
          else if (e->proto == 17)
          {
            deallocate_udp_port(ctx->udp_porter, port, 0);
          }
          else
          {
            abort();
          }
        }
        free(e);
      }
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_delete(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      timer_linkheap_remove(heap, &e->timer);
      if (e->port_allocated)
      {
        if (!e->proto_valid)
        {
          deallocate_udp_port(ctx->porter, port, 0);
          deallocate_udp_port(ctx->udp_porter, port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, port, 0);
        }
        else
        {
          abort();
        }
      }
      free(e);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_delete_nonce(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce,
  uint64_t *old_expiry,
  uint16_t *old_ext_port)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    abort();
  }
  if (!proto_valid)
  {
    abort();
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->proto == proto &&
        e->proto_valid == proto_valid &&
        e->payload.local_port == local_port)
    {
      if (!e->nonce_set || memcmp(e->nonce, nonce, 96/8) != 0 ||
          e->payload.local_ip != local_ip)
      {
        if (old_expiry)
        {
          *old_expiry = e->timer.time64;
        }
        if (old_ext_port)
        {
          *old_ext_port = e->port;
        }
        hash_table_unlock_bucket(&ctx->tbl, hashval);
        return -EACCES;
      }
      hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      timer_linkheap_remove(heap, &e->timer);
      if (e->port_allocated)
      {
        if (!e->proto_valid)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else
        {
          abort();
        }
      }
      if (old_ext_port)
      {
        *old_ext_port = e->port;
      }
      free(e);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_delete6(
  struct threetuplectx *ctx,
  struct timer_linkheap *heap,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      timer_linkheap_remove(heap, &e->timer);
      if (e->port_allocated)
      {
        if (!e->proto_valid)
        {
          deallocate_udp_port(ctx->porter, port, 0);
          deallocate_udp_port(ctx->udp_porter, port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, port, 0);
        }
        else
        {
          abort();
        }
      }
      free(e);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

void threetuplectx_flush(struct threetuplectx *ctx, struct timer_linkheap *heap)
{
  unsigned bucket;
  struct hash_list_node *x, *n;
  for (bucket = 0; bucket < ctx->tbl.bucketcnt; bucket++)
  {
    hash_table_lock_bucket(&ctx->tbl, bucket);
    HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(&ctx->tbl, n, x, bucket)
    {
      struct threetupleentry *e =
        CONTAINER_OF(n, struct threetupleentry, node);
      hash_table_delete_already_bucket_locked(&ctx->tbl, n);
      timer_linkheap_remove(heap, &e->timer);
      if (e->port_allocated)
      {
        if (!e->proto_valid)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else
        {
          abort();
        }
      }
      free(e);
    }
    hash_table_unlock_bucket(&ctx->tbl, bucket);
  }
}

void threetuplectx_flush_ip(struct threetuplectx *ctx, struct timer_linkheap *heap, uint32_t ip)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *x, *n;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(&ctx->tbl, n, x, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(n, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, n);
      timer_linkheap_remove(heap, &e->timer);
      if (e->port_allocated)
      {
        if (!e->proto_valid)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else
        {
          abort();
        }
      }
      free(e);
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
}

void threetuplectx_flush_ip6(struct threetuplectx *ctx, struct timer_linkheap *heap, const void *ipv6)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *x, *n;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(&ctx->tbl, n, x, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(n, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, n);
      timer_linkheap_remove(heap, &e->timer);
      if (e->port_allocated)
      {
        if (!e->proto_valid)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, e->port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, e->port, 0);
        }
        else
        {
          abort();
        }
      }
      free(e);
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
}

void threetuplectx_init(struct threetuplectx *ctx,
                        struct udp_porter *porter,
                        struct udp_porter *udp_porter)
{
  if (hash_table_init_locked(&ctx->tbl, 256, threetuple_hash_fn, NULL, 0))
  {
    abort();
  }
  ctx->porter = porter;
  ctx->udp_porter = udp_porter;
}

void threetuplectx_free(struct threetuplectx *ctx, struct timer_linkheap *heap)
{
  struct hash_list_node *node, *tmp;
  unsigned bucket;
  HASH_TABLE_FOR_EACH_SAFE(&ctx->tbl, bucket, node, tmp)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    hash_table_delete(&ctx->tbl, node, threetuple_hash(e));
    timer_linkheap_remove(heap, &e->timer);
    free(e);
  }
  hash_table_free(&ctx->tbl);
}
