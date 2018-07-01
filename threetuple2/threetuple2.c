#include <stdint.h>
#include <errno.h>
#include "siphash.h"
#include "hashseed.h"
#include "hashtable.h"
#include "containerof.h"
#include "threetuple2.h"

static inline uint32_t threetuple2_iphash(uint32_t ip)
{
  return siphash64(hash_seed_get(), ip);
}

static inline uint32_t threetuple2_hash(uint32_t ip, uint16_t port, uint8_t proto)
{
  uint64_t val64;
  val64 = (((uint64_t)ip)<<32) | (((uint64_t)port)<<8) | proto;
  return siphash64(hash_seed_get(), val64);
}

static inline uint32_t threetuple2_local_hash(struct threetuple2entry *e)
{
  return threetuple2_hash(e->local_ip, e->local_port, e->proto);
}

static inline uint32_t threetuple2_nat_hash(struct threetuple2entry *e)
{
  return threetuple2_hash(e->nat_ip, e->nat_port, e->proto);
}

static inline uint32_t int_tbl2_hash(struct threetuple2inthostcount *e)
{
  return threetuple2_iphash(e->local_ip);
}


static uint32_t threetuple2_local_hash_fn(struct hash_list_node *node, void *userdata)
{
  struct threetuple2entry *e = CONTAINER_OF(node, struct threetuple2entry, local_node);
  return threetuple2_local_hash(e);
}

static uint32_t threetuple2_nat_hash_fn(struct hash_list_node *node, void *userdata)
{
  struct threetuple2entry *e = CONTAINER_OF(node, struct threetuple2entry, nat_node);
  return threetuple2_nat_hash(e);
}

static uint32_t int_tbl2_hash_fn(struct hash_list_node *node, void *userdata)
{
  struct threetuple2inthostcount *e =
    CONTAINER_OF(node, struct threetuple2inthostcount, node);
  return int_tbl2_hash(e);
}

#define RGW_TIMEOUT_SECS 2

static struct threetuple2entry *threetuple2ctx_find_nat(
  struct threetuple2ctx *ctx,
  uint32_t nat_ip,
  uint16_t nat_port,
  uint8_t proto)
{
  struct hash_list_node *node;
  uint32_t hashval = threetuple2_hash(nat_ip, nat_port, proto);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->nat_tbl, node, hashval)
  {
    struct threetuple2entry *e =
      CONTAINER_OF(node, struct threetuple2entry, nat_node);
    if (e->nat_ip == nat_ip && e->nat_port == nat_port &&
        e->proto == proto)
    {
      return e;
    }
  }
  return NULL;
}


static void threetuple2ctx_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct threetuple2entry *e =
    CONTAINER_OF(timer, struct threetuple2entry, timer);
  struct threetuple2ctx *ctx = ud;
  hash_table_delete_already_bucket_locked(&ctx->nat_tbl, &e->nat_node);
  hash_table_delete_already_bucket_locked(&ctx->local_tbl, &e->local_node);
  if (e->inthost_set)
  {
    int_tbl2_rm(ctx, e->local_ip);
  }
  if (e->port_allocated)
  {
    if (e->proto == 0)
    {
      deallocate_udp_port(ctx->porter, e->nat_port, 0);
      deallocate_udp_port(ctx->udp_porter, e->nat_port, 0);
    }
    else if (e->proto == 6)
    {
      deallocate_udp_port(ctx->porter, e->nat_port, 0);
    }
    else if (e->proto == 17)
    {
      deallocate_udp_port(ctx->udp_porter, e->nat_port, 0);
    }
    else
    {
      abort();
    }
  }
  free(e);
}

int threetuple2ctx_consume(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  uint32_t ip, uint16_t port, uint8_t proto,
  uint32_t *local_ip, uint16_t *local_port)
{
  struct threetuple2entry *e;
  e = threetuple2ctx_find_nat(ctx, ip, port, proto);
  if (e)
  {
    goto ok;
  }
  e = threetuple2ctx_find_nat(ctx, ip, port, 0);
  if (e)
  {
    goto ok;
  }
  e = threetuple2ctx_find_nat(ctx, ip, 0, proto);
  if (e)
  {
    goto ok;
  }
  e = threetuple2ctx_find_nat(ctx, ip, 0, 0);
  if (e)
  {
    goto ok;
  }
  return -ENOENT;

ok:
  if (local_port)
  {
    *local_port = e->local_port;
  }
  if (local_ip)
  {
    *local_ip = e->local_ip;
  }
  if (e->consumable)
  {
    hash_table_delete_already_bucket_locked(&ctx->nat_tbl, &e->nat_node);
    hash_table_delete_already_bucket_locked(&ctx->local_tbl, &e->local_node);
    timer_linkheap_remove(heap, &e->timer);
    if (e->inthost_set)
    {
      int_tbl2_rm(ctx, e->local_ip);
    }
    if (e->port_allocated)
    {
      if (e->proto == 0)
      {
        deallocate_udp_port(ctx->porter, e->nat_port, 0);
        deallocate_udp_port(ctx->udp_porter, e->nat_port, 0);
      }
      else if (e->proto == 6)
      {
        deallocate_udp_port(ctx->porter, e->nat_port, 0);
      }
      else if (e->proto == 17)
      {
        deallocate_udp_port(ctx->udp_porter, e->nat_port, 0);
      }
      else
      {
        abort();
      }
    }
    free(e);
  }
  return 0;
}

int threetuple2ctx_delete_nonce(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  uint8_t proto,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce, uint64_t *old_expiry, uint16_t *old_ext_port,
  uint32_t *old_ext_ip)
{
  struct hash_list_node *node;
  uint32_t hashval = threetuple2_hash(local_ip, local_port, proto);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->local_tbl, node, hashval)
  {
    struct threetuple2entry *e =
      CONTAINER_OF(node, struct threetuple2entry, local_node);
    if (e->local_ip == local_ip && e->local_port == local_port &&
        e->proto == proto)
    {
      if (!e->nonce_set || memcmp(e->nonce, nonce, 96/8) != 0)
      {
        if (old_expiry)
        {
          *old_expiry = e->timer.time64;
        }
        if (old_ext_port)
        {
          *old_ext_port = e->nat_port;
        }
        if (old_ext_ip)
        {
          *old_ext_ip = e->nat_ip;
        }
        return -EACCES;
      }
      if (old_ext_port)
      {
        *old_ext_port = e->nat_port;
      }
      if (old_ext_ip)
      {
        *old_ext_ip = e->nat_ip;
      }
      hash_table_delete_already_bucket_locked(&ctx->nat_tbl, &e->nat_node);
      hash_table_delete_already_bucket_locked(&ctx->local_tbl, &e->local_node);
      timer_linkheap_remove(heap, &e->timer);
      if (e->inthost_set)
      {
        int_tbl2_rm(ctx, e->local_ip);
      }
      if (e->port_allocated)
      {
        if (e->proto == 0)
        {
          deallocate_udp_port(ctx->porter, e->nat_port, 0);
          deallocate_udp_port(ctx->udp_porter, e->nat_port, 0);
        }
        else if (e->proto == 6)
        {
          deallocate_udp_port(ctx->porter, e->nat_port, 0);
        }
        else if (e->proto == 17)
        {
          deallocate_udp_port(ctx->udp_porter, e->nat_port, 0);
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
  return -ENOENT;
}

int threetuple2ctx_add(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto,
  uint32_t local_ip, uint16_t local_port,
  uint64_t expire_time64)
{
  if (threetuple2ctx_find_nat(ctx, ip, 0, 0))
  {
    return -EEXIST;
  }
  if (threetuple2ctx_find_nat(ctx, ip, 0, proto))
  {
    return -EEXIST;
  }
  if (threetuple2ctx_find_nat(ctx, ip, port, 0))
  {
    return -EEXIST;
  }
  if (threetuple2ctx_find_nat(ctx, ip, port, proto))
  {
    return -EEXIST;
  }
  struct threetuple2entry *e = malloc(sizeof(*e));
  memset(e, 0, sizeof(*e));
  e->nonce_set = 0;
  e->inthost_set = 0;
  e->consumable = consumable;
  e->port_allocated = port_allocated;
  e->nat_ip = ip;
  e->nat_port = port;
  e->local_ip = local_ip;
  e->local_port = local_port;
  e->proto = proto;
  e->timer.userdata = ctx;
  e->timer.fn = threetuple2ctx_expiry_fn;
  e->timer.time64 = expire_time64;
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->local_tbl, &e->local_node, threetuple2_local_hash(e));
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->nat_tbl, &e->nat_node, threetuple2_nat_hash(e));
  return 0;
}

int threetuple2ctx_modify_noadd_nonce(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  int port_allocated,
  uint8_t proto,
  uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce, uint64_t *old_expiry, uint16_t *old_ext_port,
  uint32_t *old_ext_ip)
{
  struct hash_list_node *node;
  uint32_t hashval = threetuple2_hash(local_ip, local_port, proto);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->local_tbl, node, hashval)
  {
    struct threetuple2entry *e =
      CONTAINER_OF(node, struct threetuple2entry, local_node);
    if (e->local_ip == local_ip && e->local_port == local_port &&
        e->proto == proto)
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
          *old_ext_port = e->nat_port;
        }
        if (old_ext_ip)
        {
          *old_ext_ip = e->nat_ip;
        }
        return -EACCES;
      }
      e->timer.time64 = expire_time64;
      timer_linkheap_modify(heap, &e->timer);
      if (old_ext_port)
      {
        *old_ext_port = e->nat_port;
      }
      if (old_ext_ip)
      {
        *old_ext_ip = e->nat_ip;
      }
      return 0;
    }
  }
  return -ENOENT;
}

int threetuple2ctx_add_nonce(
  struct threetuple2ctx *ctx,
  struct timer_linkheap *heap,
  int consumable,
  int port_allocated,
  uint32_t ip, uint16_t port, uint8_t proto,
  uint64_t expire_time64,
  uint32_t local_ip,
  uint16_t local_port,
  const void *nonce, uint64_t *old_expiry, uint32_t limit)
{
  struct hash_list_node *node;
  uint32_t hashval = threetuple2_hash(local_ip, local_port, proto);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->local_tbl, node, hashval)
  {
    struct threetuple2entry *e =
      CONTAINER_OF(node, struct threetuple2entry, local_node);
    if (e->local_ip == local_ip && e->local_port == local_port &&
        e->proto == proto)
    {
      return -EEXIST;
    }
  }
  if (int_tbl2_add(ctx, local_ip, limit) != 0)
  {
    return -EMFILE;
  }
  struct threetuple2entry *e = malloc(sizeof(*e));
  memset(e, 0, sizeof(*e));
  memcpy(e->nonce, nonce, 96/8);
  e->nonce_set = 1;
  e->inthost_set = 1;
  e->consumable = consumable;
  e->port_allocated = port_allocated;
  e->nat_ip = ip;
  e->nat_port = port;
  e->local_ip = local_ip;
  e->local_port = local_port;
  e->proto = proto;
  e->timer.userdata = ctx;
  e->timer.fn = threetuple2ctx_expiry_fn;
  e->timer.time64 = expire_time64;
  timer_linkheap_add(heap, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->local_tbl, &e->local_node, threetuple2_local_hash(e));
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->nat_tbl, &e->nat_node, threetuple2_nat_hash(e));
  return 0;
}

void threetuple2ctx_init(struct threetuple2ctx *ctx,
                        struct udp_porter *porter,
                        struct udp_porter *udp_porter)
{
  if (hash_table_init_locked(&ctx->nat_tbl, 8192, threetuple2_nat_hash_fn, NULL, 0))
  {
    abort();
  }
  if (hash_table_init_locked(&ctx->local_tbl, 8192, threetuple2_local_hash_fn, NULL, 0))
  {
    abort();
  }
  if (hash_table_init(&ctx->int_tbl, 256, int_tbl2_hash_fn, NULL))
  {
    abort();
  }
  ctx->porter = porter;
  ctx->udp_porter = udp_porter;
}

void threetuple2ctx_free(struct threetuple2ctx *ctx, struct timer_linkheap *heap)
{
  struct hash_list_node *node, *tmp;
  unsigned bucket;
  HASH_TABLE_FOR_EACH_SAFE(&ctx->nat_tbl, bucket, node, tmp)
  {
    struct threetuple2entry *e =
      CONTAINER_OF(node, struct threetuple2entry, nat_node);
    hash_table_delete(&ctx->nat_tbl, &e->nat_node, threetuple2_nat_hash(e));
    hash_table_delete(&ctx->local_tbl, &e->local_node, threetuple2_local_hash(e));
    timer_linkheap_remove(heap, &e->timer);
    free(e);
  }
  HASH_TABLE_FOR_EACH_SAFE(&ctx->int_tbl, bucket, node, tmp)
  {
    struct threetuple2inthostcount *e =
      CONTAINER_OF(node, struct threetuple2inthostcount, node);
    hash_table_delete(&ctx->int_tbl, node, int_tbl2_hash(e));
    free(e);
  }
  hash_table_free(&ctx->nat_tbl);
  hash_table_free(&ctx->local_tbl);
  hash_table_free(&ctx->int_tbl);
}

void int_tbl2_rm(struct threetuple2ctx *ctx, uint32_t local_ip)
{
  struct hash_list_node *node;
  uint32_t hashval = threetuple2_iphash(local_ip);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->int_tbl, node, hashval)
  {
    struct threetuple2inthostcount *cnte =
      CONTAINER_OF(node, struct threetuple2inthostcount, node);
    if (cnte->local_ip == local_ip)
    {
      if (cnte->count == 0)
      {
        abort();
      }
      cnte->count--;
      return;
    }
  }
  abort();
}

int int_tbl2_add(struct threetuple2ctx *ctx, uint32_t local_ip, uint32_t limit)
{
  struct hash_list_node *node;
  uint32_t hashval = threetuple2_iphash(local_ip);
  struct threetuple2inthostcount *cnte;
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->int_tbl, node, hashval)
  {
    cnte = CONTAINER_OF(node, struct threetuple2inthostcount, node);
    if (cnte->local_ip == local_ip)
    {
      if (cnte->count >= limit)
      {
        return -EPERM;
      }
      cnte->count++;
      return 0;
    }
  }
  if (limit == 0)
  {
    return -EPERM;
  }
  cnte = malloc(sizeof(*cnte));
  cnte->local_ip = local_ip;
  cnte->count = 1;
  hash_table_add_nogrow(&ctx->int_tbl, &cnte->node, hashval);
  return 0;
}
