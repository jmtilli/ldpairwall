#ifndef _REASSHL_H_
#define _REASSHL_H_

#include <stdint.h>
#include "rbcombo.h"
#include "hashtable.h"
#include "siphash.h"
#include "hashseed.h"
#include "timerlink.h"
#include "time64.h"

struct reasshlentry {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t ip_id;
  uint8_t proto;
  struct hash_list_node node;
  struct linked_list_node listnode;
  struct rbcomboctx combo;
  uint32_t mem_cur;
  uint64_t time64;
};

static inline void
reasshlentry_init(struct reasshlentry *e)
{
  rbcomboctx_init(&e->combo);
}

static inline void
reasshlentry_free(struct reasshlentry *e, struct allocif *loc)
{
  rbcomboctx_free(loc, &e->combo);
}

static inline uint32_t
reasshlhash_separate(uint32_t src_ip, uint64_t dst_ip,
                     uint16_t ip_id, uint8_t proto)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_u64(&ctx, (((uint64_t)src_ip)<<32) | dst_ip);
  siphash_feed_u64(&ctx, (((uint64_t)ip_id)<<8) | proto);
  return siphash_get(&ctx);
}

static inline uint32_t
reasshlhash(struct reasshlentry *entry)
{
  return reasshlhash_separate(entry->src_ip, entry->dst_ip,
                              entry->ip_id, entry->proto);
}

uint32_t reasshlhash_fn(struct hash_list_node *node, void *ud);

struct reasshlctx {
  struct hash_table hash;
  struct linked_list_head list;
  size_t mem_limit;
  size_t mem_cur;
  struct timer_link timer;
  struct timer_linkheap *heap;
  uint32_t timeout_secs;
  uint32_t timer_secs;
};

struct packet *reasshlctx_add(struct reasshlctx *hl, struct allocif *loc,
                              void *pktdata, size_t pktsz, uint64_t time64);

void reasshlctx_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td);

static inline void reasshlctx_init(struct reasshlctx *hl, size_t limit,
                                   struct timer_linkheap *heap, struct allocif *loc,
                                   uint32_t timeout_secs, uint32_t timer_secs)
{
  if (hash_table_init(&hl->hash, 8192, reasshlhash_fn, NULL) != 0)
  {
    abort();
  }
  linked_list_head_init(&hl->list);
  hl->timeout_secs = timeout_secs;
  hl->timer_secs = timer_secs;
  hl->mem_cur = 0;
  hl->mem_limit = limit;
  hl->heap = heap;
  hl->timer.time64 = gettime64() + timer_secs*1000ULL*1000ULL;
  hl->timer.fn = reasshlctx_expiry_fn;
  hl->timer.userdata = loc;
  timer_linkheap_add(heap, &hl->timer);
}

#endif
