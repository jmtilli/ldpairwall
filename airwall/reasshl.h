#ifndef _REASSHL_H_
#define _REASSHL_H_

#include <stdint.h>
#include "combo.h"
#include "hashtable.h"
#include "siphash.h"
#include "hashseed.h"
#include "timerlink.h"
#include "time64.h"

#define REASS_TIMEOUT_SECS 60
#define REASS_TIMER_SECS 1

struct reasshlentry {
  struct hash_list_node node;
  struct linked_list_node listnode;
  struct comboctx combo;
  uint32_t mem_cur;
  uint64_t time64;
};

static inline void
reasshlentry_init(struct reasshlentry *e)
{
  comboctx_init(&e->combo);
}

static inline void
reasshlentry_free(struct reasshlentry *e, struct allocif *loc)
{
  comboctx_free(loc, &e->combo);
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
  if (entry->combo.rfc_active)
  {
    return reasshlhash_separate(entry->combo.u.rfc->src_ip, entry->combo.u.rfc->dst_ip,
                                entry->combo.u.rfc->ip_id, entry->combo.u.rfc->proto);
  }
  return reasshlhash_separate(entry->combo.u.reass.src_ip, entry->combo.u.reass.dst_ip,
                              entry->combo.u.reass.ip_id, entry->combo.u.reass.proto);
}

uint32_t reasshlhash_fn(struct hash_list_node *node, void *ud);

struct reasshlctx {
  struct hash_table hash;
  struct linked_list_head list;
  size_t mem_limit;
  size_t mem_cur;
  struct timer_link timer;
  struct timer_linkheap *heap;
};

struct packet *reasshlctx_add(struct reasshlctx *hl, struct allocif *loc,
                              void *pktdata, size_t pktsz, uint64_t time64);

void reasshlctx_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td);

static inline void reasshlctx_init(struct reasshlctx *hl, size_t limit,
                                   struct timer_linkheap *heap, struct allocif *loc)
{
  if (hash_table_init(&hl->hash, 8192, reasshlhash_fn, NULL) != 0)
  {
    abort();
  }
  linked_list_head_init(&hl->list);
  hl->mem_cur = 0;
  hl->mem_limit = limit;
  hl->heap = heap;
  hl->timer.time64 = gettime64() + REASS_TIMER_SECS*1000ULL*1000ULL;
  hl->timer.fn = reasshlctx_expiry_fn;
  hl->timer.userdata = loc;
  timer_linkheap_add(heap, &hl->timer);
}

#endif
