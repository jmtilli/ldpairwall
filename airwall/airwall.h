#ifndef _SYNPROXY_H_
#define _SYNPROXY_H_

#include "ports.h"
#include "llalloc.h"
#include "packet.h"
#include "iphdr.h"
#include "log.h"
#include "hashtable.h"
#include "linkedlist.h"
#include "containerof.h"
#include "siphash.h"
#include "timerlink.h"
#include <stdio.h>
#include "hashseed.h"
#include "secret.h"
#include "iphash.h"
#if 0
#include "sackhash.h"
#endif
#include "conf.h"
#include "arp.h"
#include "detect.h"
#include "udpporter.h"
#include "threetuple2.h"

const char http_connect_revdatabuf[19];

struct airwall {
  struct conf *conf;
  //struct sack_ip_port_hash autolearn;
  struct threetuple2ctx threetuplectx;
  char ul_mac[6];
  char dl_mac[6];
  struct udp_porter *porter;
  struct udp_porter *udp_porter;
  struct udp_porter *icmp_porter;
};

struct airwall_udp_entry {
  struct hash_list_node local_node;
  struct hash_list_node nat_node;
  struct timer_link timer;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } local_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } nat_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } remote_ip;
  uint32_t ulflowlabel; // after mangling
  uint32_t dlflowlabel;
  uint16_t local_port;
  uint16_t nat_port;
  uint16_t remote_port;
  uint8_t version; // 4 or 6, IPv4 or IPv6
  uint8_t was_incoming;
};

struct airwall_icmp_entry {
  struct hash_list_node local_node;
  struct hash_list_node nat_node;
  struct timer_link timer;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } local_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } nat_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } remote_ip;
  uint32_t ulflowlabel; // after mangling
  uint32_t dlflowlabel;
  uint16_t local_identifier;
  uint16_t nat_identifier;
  uint8_t version; // 4 or 6, IPv4 or IPv6
  uint8_t was_incoming;
};

struct airwall_hash_entry {
  struct hash_list_node local_node;
  struct hash_list_node nat_node;
  struct timer_link timer;
  struct timer_link retx_timer;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } local_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } nat_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } remote_ip;
  uint32_t ulflowlabel; // after mangling
  uint32_t dlflowlabel;
  uint16_t local_port;
  uint16_t nat_port;
  uint16_t remote_port;
  uint16_t flag_state;
  int8_t wscalediff;
  uint8_t lan_wscale;
  uint8_t wan_wscale;
  uint8_t version:4; // 4 or 6, IPv4 or IPv6
  uint8_t was_synproxied:1;
  uint8_t lan_sack_was_supported:1;
  uint8_t revdata:1;
  uint8_t retxtimer_set:1;
  uint8_t port_alloced:1;
  uint32_t seqoffset;
  uint32_t tsoffset;
  uint32_t lan_sent; // what LAN has sent plus 1
  uint32_t wan_sent; // what WAN has sent plus 1
  uint32_t lan_acked; // what WAN has sent and LAN has acked plus 1
  uint32_t wan_acked; // what LAN has sent and WAN has acked plus 1
  uint32_t lan_max; // lan_acked + (tcp_window()<<lan_wscale)
  uint32_t wan_max; // wan_acked + (tcp_window()<<wan_wscale)
#if 0
  uint32_t lan_next;
  uint32_t wan_next;
  uint32_t lan_window; // FIXME make unscaled to save space
  uint32_t wan_window; // FIXME make unscaled to save space
#endif
  uint16_t lan_max_window_unscaled; // max window LAN has advertised
  uint16_t wan_max_window_unscaled; // max window WAN has advertised
  uint32_t local_isn; // ACK number - 1 of ACK packet
  uint32_t remote_isn; // SEQ number - 1 of ACK packet
  union {
    struct {
      uint32_t isn;
    } uplink_syn_rcvd;
    struct {
      uint32_t isn;
    } uplink_syn_sent;
    struct {
      uint16_t mss;
      uint8_t sack_permitted;
      uint8_t timestamp_present;
      uint32_t local_timestamp;
      uint32_t remote_timestamp;
    } downlink_syn_sent; // and also FLAG_STATE_WINDOW_UPDATE_SENT uses this
    struct {
      uint32_t upfin; // valid if FLAG_STATE_UPLINK_FIN
      uint32_t downfin; // valid if FLAG_STATE_DOWNLINK_FIN
      uint32_t retx_seq;
      uint32_t retx_ack;
      uint32_t retx_ts;
      uint32_t retx_tsecho;
      uint16_t retx_win;
      uint8_t retx_ts_present:1;
    } established;
    struct {
      struct linked_list_node listnode;
      uint8_t wscale;
      uint8_t sack_permitted;
      uint16_t mss;
      uint32_t remote_isn;
      uint32_t local_isn;
    } downlink_half_open;
  } state_data;
  struct linked_list_node detect_node;
  struct proto_detect_ctx *detect;
};

enum flag_state {
  FLAG_STATE_UPLINK_SYN_SENT = 1, // may not have other bits
  FLAG_STATE_UPLINK_SYN_RCVD = 2, // may not have other bits
  FLAG_STATE_WINDOW_UPDATE_SENT = 4, // may not have other bits
  FLAG_STATE_DOWNLINK_SYN_SENT = 8, // may not have other bits
  FLAG_STATE_ESTABLISHED = 16, // may have also FIN bits
  FLAG_STATE_UPLINK_FIN = 32, // always with ESTABLISHED
  FLAG_STATE_UPLINK_FIN_ACK = 64, // always with UPLINK_FIN|ESTABLISHED
  FLAG_STATE_DOWNLINK_FIN = 128, // always with ESTABLISHED
  FLAG_STATE_DOWNLINK_FIN_ACK = 256, // always with DOWNLINK_FIN|ESTABLSIHED
  FLAG_STATE_TIME_WAIT = 512, // may not have other bits
  FLAG_STATE_DOWNLINK_HALF_OPEN = 1024, // may not have other bits
  FLAG_STATE_RESETED = 2048, // may not have other bits
};

static inline int airwall_is_connected(struct airwall_hash_entry *e)
{
  return (e->flag_state & FLAG_STATE_ESTABLISHED) == FLAG_STATE_ESTABLISHED;
}

static inline uint32_t airwall_hash_separate4(
  uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_u64(&ctx, (((uint64_t)local_ip) << 32) | remote_ip);
  siphash_feed_u64(&ctx, (((uint64_t)local_port) << 32) | remote_port);
  return siphash_get(&ctx);
}

static inline uint32_t airwall_hash_separate6(
  const void *local_ip, uint16_t local_port, const void *remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_buf(&ctx, local_ip, 16);
  siphash_feed_buf(&ctx, remote_ip, 16);
  siphash_feed_u64(&ctx, (((uint64_t)local_port) << 32) | remote_port);
  return siphash_get(&ctx);
}

static inline uint32_t airwall_hash_icmp_separate4(
  uint32_t local_ip, uint32_t remote_ip, uint16_t identifier)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_u64(&ctx, (((uint64_t)local_ip) << 32) | remote_ip);
  siphash_feed_u64(&ctx, (((uint64_t)identifier) << 32));
  return siphash_get(&ctx);
}

static inline uint32_t airwall_hash_icmp_separate6(
  const void *local_ip, const void *remote_ip, uint16_t identifier)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_buf(&ctx, local_ip, 16);
  siphash_feed_buf(&ctx, remote_ip, 16);
  siphash_feed_u64(&ctx, (((uint64_t)identifier) << 32));
  return siphash_get(&ctx);
}

static inline uint32_t airwall_hash_local(struct airwall_hash_entry *e)
{
  if (e->version == 4)
  {
    return airwall_hash_separate4(ntohl(e->local_ip.ipv4), e->local_port, ntohl(e->remote_ip.ipv4), e->remote_port);
  }
  else
  {
    return airwall_hash_separate6(&e->local_ip, e->local_port, &e->remote_ip, e->remote_port);
  }
}

static inline uint32_t airwall_hash_nat(struct airwall_hash_entry *e)
{
  if (e->version == 4)
  {
    return airwall_hash_separate4(ntohl(e->nat_ip.ipv4), e->nat_port, ntohl(e->remote_ip.ipv4), e->remote_port);
  }
  else
  {
    return airwall_hash_separate6(&e->nat_ip, e->nat_port, &e->remote_ip, e->remote_port);
  }
}

static inline uint32_t airwall_hash_local_udp(struct airwall_udp_entry *e)
{
  if (e->version == 4)
  {
    return airwall_hash_separate4(ntohl(e->local_ip.ipv4), e->local_port, ntohl(e->remote_ip.ipv4), e->remote_port);
  }
  else
  {
    return airwall_hash_separate6(&e->local_ip, e->local_port, &e->remote_ip, e->remote_port);
  }
}

static inline uint32_t airwall_hash_nat_udp(struct airwall_udp_entry *e)
{
  if (e->version == 4)
  {
    return airwall_hash_separate4(ntohl(e->nat_ip.ipv4), e->nat_port, ntohl(e->remote_ip.ipv4), e->remote_port);
  }
  else
  {
    return airwall_hash_separate6(&e->nat_ip, e->nat_port, &e->remote_ip, e->remote_port);
  }
}

static inline uint32_t airwall_hash_local_icmp(struct airwall_icmp_entry *e)
{
  if (e->version == 4)
  {
    return airwall_hash_icmp_separate4(ntohl(e->local_ip.ipv4), ntohl(e->remote_ip.ipv4), e->local_identifier);
  }
  else
  {
    return airwall_hash_icmp_separate6(&e->local_ip, &e->remote_ip, e->local_identifier);
  }
}

static inline uint32_t airwall_hash_nat_icmp(struct airwall_icmp_entry *e)
{
  if (e->version == 4)
  {
    return airwall_hash_icmp_separate4(ntohl(e->nat_ip.ipv4), ntohl(e->remote_ip.ipv4), e->nat_identifier);
  }
  else
  {
    return airwall_hash_icmp_separate6(&e->nat_ip, &e->remote_ip, e->nat_identifier);
  }
}

uint32_t airwall_hash_fn_local(struct hash_list_node *node, void *userdata);

uint32_t airwall_hash_fn_nat(struct hash_list_node *node, void *userdata);

uint32_t airwall_hash_fn_local_udp(struct hash_list_node *node, void *userdata);

uint32_t airwall_hash_fn_nat_udp(struct hash_list_node *node, void *userdata);

uint32_t airwall_hash_fn_local_icmp(struct hash_list_node *node, void *userdata);

uint32_t airwall_hash_fn_nat_icmp(struct hash_list_node *node, void *userdata);

struct worker_local {
  struct hash_table local_hash;
  struct hash_table nat_hash;
  struct hash_table local_udp_hash;
  struct hash_table nat_udp_hash;
  struct hash_table local_icmp_hash;
  struct hash_table nat_icmp_hash;
  int locked;
  pthread_rwlock_t rwlock; // Lock order: first hash bucket lock, then mutex, then global hash lock
  struct timer_linkheap timers;
  struct secretinfo info;
  struct ip_hash ratelimit;
  uint32_t synproxied_connections;
  uint32_t direct_connections;
  uint32_t half_open_connections;
  uint32_t incoming_udp_connections;
  uint32_t direct_udp_connections;
  uint32_t incoming_icmp_connections;
  uint32_t direct_icmp_connections;
  struct linked_list_head half_open_list;
  struct linked_list_head detect_list;
  size_t detect_count;
  struct arp_cache dl_arp_cache;
  struct arp_cache ul_arp_cache;
  struct airwall *airwall;
};

static inline void worker_local_rdlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_rdlock(&local->rwlock);
}

static inline void worker_local_rdunlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_unlock(&local->rwlock);
}

static inline void worker_local_wrlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_wrlock(&local->rwlock);
}

static inline void worker_local_wrunlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_unlock(&local->rwlock);
}

static inline void worker_local_init(
  struct worker_local *local, struct airwall *airwall, int deterministic,
  int locked, struct allocif *intf)
{
  if (locked)
  {
    hash_table_init(
      &local->nat_hash, airwall->conf->conntablesize, airwall_hash_fn_nat, NULL);
    hash_table_init(
      &local->local_hash, airwall->conf->conntablesize, airwall_hash_fn_local, NULL);
    hash_table_init(
      &local->nat_udp_hash, airwall->conf->conntablesize, airwall_hash_fn_nat_udp, NULL);
    hash_table_init(
      &local->local_udp_hash, airwall->conf->conntablesize, airwall_hash_fn_local_udp, NULL);
    hash_table_init(
      &local->nat_icmp_hash, airwall->conf->conntablesize, airwall_hash_fn_nat_icmp, NULL);
    hash_table_init(
      &local->local_icmp_hash, airwall->conf->conntablesize, airwall_hash_fn_local_icmp, NULL);
    local->locked = 1;
    if (pthread_rwlock_init(&local->rwlock, NULL) != 0)
    {
      abort();
    }
  }
  else
  {
    hash_table_init(
      &local->nat_hash, airwall->conf->conntablesize, airwall_hash_fn_nat, NULL);
    hash_table_init(
      &local->local_hash, airwall->conf->conntablesize, airwall_hash_fn_local, NULL);
    hash_table_init(
      &local->nat_udp_hash, airwall->conf->conntablesize, airwall_hash_fn_nat_udp, NULL);
    hash_table_init(
      &local->local_udp_hash, airwall->conf->conntablesize, airwall_hash_fn_local_udp, NULL);
    hash_table_init(
      &local->nat_icmp_hash, airwall->conf->conntablesize, airwall_hash_fn_nat_icmp, NULL);
    hash_table_init(
      &local->local_icmp_hash, airwall->conf->conntablesize, airwall_hash_fn_local_icmp, NULL);
    local->locked = 0;
  }
  timer_linkheap_init(&local->timers);
  if (deterministic)
  {
    secret_init_deterministic(&local->info);
  }
  else
  {
    secret_init_random(&local->info);
  }
  local->ratelimit.hash_size = airwall->conf->ratehash.size;
  local->ratelimit.batch_size = 16384;
  if (local->ratelimit.batch_size > local->ratelimit.hash_size)
  {
    local->ratelimit.batch_size = local->ratelimit.hash_size;
  }
  local->ratelimit.initial_tokens = airwall->conf->ratehash.initial_tokens;
  local->ratelimit.timer_add = airwall->conf->ratehash.timer_add;
  local->ratelimit.timer_period = airwall->conf->ratehash.timer_period_usec;
  local->synproxied_connections = 0;
  local->direct_connections = 0;
  local->half_open_connections = 0;
  local->detect_count = 0;
  local->airwall = airwall;
  arp_cache_init(&local->dl_arp_cache, intf);
  arp_cache_init(&local->ul_arp_cache, intf);
  ip_hash_init(&local->ratelimit, &local->timers, locked ? &local->rwlock : NULL);
  linked_list_head_init(&local->half_open_list);
  linked_list_head_init(&local->detect_list);
}

static inline void worker_local_free(struct worker_local *local)
{
  struct hash_list_node *x, *n;
  size_t bucket;
  ip_hash_free(&local->ratelimit, &local->timers);
  HASH_TABLE_FOR_EACH_SAFE(&local->nat_hash, bucket, n, x)
  {
    struct airwall_hash_entry *e;
    e = CONTAINER_OF(n, struct airwall_hash_entry, nat_node);
    if (e->local_port != 0)
    {
      hash_table_delete(&local->local_hash, &e->local_node, airwall_hash_local(e));
    }
    hash_table_delete(&local->nat_hash, &e->nat_node, airwall_hash_nat(e));
    timer_linkheap_remove(&local->timers, &e->timer);
    if (e->retxtimer_set)
    {
      timer_linkheap_remove(&local->timers, &e->retx_timer);
      e->retxtimer_set = 0;
    }
    if (e->port_alloced)
    {
      deallocate_udp_port(local->airwall->porter, e->nat_port, !e->was_synproxied);
    }
    free(e->detect);
    e->detect = NULL;
    free(e);
  }
  HASH_TABLE_FOR_EACH_SAFE(&local->nat_udp_hash, bucket, n, x)
  {
    struct airwall_udp_entry *e;
    e = CONTAINER_OF(n, struct airwall_udp_entry, nat_node);
    hash_table_delete(&local->local_udp_hash, &e->local_node, airwall_hash_local_udp(e));
    hash_table_delete(&local->nat_udp_hash, &e->nat_node, airwall_hash_nat_udp(e));
    timer_linkheap_remove(&local->timers, &e->timer);
    deallocate_udp_port(local->airwall->udp_porter, e->nat_port, !e->was_incoming);
    free(e);
  }
  HASH_TABLE_FOR_EACH_SAFE(&local->nat_icmp_hash, bucket, n, x)
  {
    struct airwall_icmp_entry *e;
    e = CONTAINER_OF(n, struct airwall_icmp_entry, nat_node);
    hash_table_delete(&local->local_icmp_hash, &e->local_node, airwall_hash_local_icmp(e));
    hash_table_delete(&local->nat_icmp_hash, &e->nat_node, airwall_hash_nat_icmp(e));
    timer_linkheap_remove(&local->timers, &e->timer);
    deallocate_udp_port(local->airwall->icmp_porter, e->nat_identifier, !e->was_incoming);
    free(e);
  }
  hash_table_free(&local->local_icmp_hash);
  hash_table_free(&local->nat_icmp_hash);
  hash_table_free(&local->local_udp_hash);
  hash_table_free(&local->nat_udp_hash);
  hash_table_free(&local->local_hash);
  hash_table_free(&local->nat_hash);
  timer_linkheap_free(&local->timers);
}

struct airwall_hash_ctx {
  uint32_t hashval;
  //struct airwall_hash_entry *entry;
};

static inline int ipmemequal(const void *a, const void *b, size_t sz)
{
  if (sz == 4)
  {
    return hdr_get32h(a) == hdr_get32h(b);
  }
  else if (sz == 16)
  {
    const char *ap = a, *bp = b;
    if (hdr_get32h(ap) != hdr_get32h(bp))
    {
      return 0;
    }
    if (hdr_get32h(ap+4) != hdr_get32h(bp+4))
    {
      return 0;
    }
    if (hdr_get32h(ap+8) != hdr_get32h(bp+8))
    {
      return 0;
    }
    if (hdr_get32h(ap+12) != hdr_get32h(bp+12))
    {
      return 0;
    }
    return 1;
  }
  else
  {
    abort();
  }
}

static inline struct airwall_hash_entry *airwall_hash_get_local(
  struct worker_local *local, int version,
  const void *local_ip, uint16_t local_port, const void *remote_ip, uint16_t remote_port, struct airwall_hash_ctx *ctx)
{
  struct hash_list_node *node;
  int len;
  if (version == 4)
  {
    ctx->hashval = airwall_hash_separate4(hdr_get32n(local_ip), local_port, hdr_get32n(remote_ip), remote_port);
    len = 4;
  }
  else
  {
    ctx->hashval = airwall_hash_separate6(local_ip, local_port, remote_ip, remote_port);
    len = 16;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->local_hash, node, ctx->hashval)
  {
    struct airwall_hash_entry *entry;
    entry = CONTAINER_OF(node, struct airwall_hash_entry, local_node);
    if (   entry->version == version
        && ipmemequal(&entry->local_ip, local_ip, len)
        && entry->local_port == local_port
        && ipmemequal(&entry->remote_ip, remote_ip, len)
        && entry->remote_port == remote_port)
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct airwall_udp_entry *airwall_hash_get_local_udp(
  struct worker_local *local, int version,
  const void *local_ip, uint16_t local_port, const void *remote_ip, uint16_t remote_port, struct airwall_hash_ctx *ctx)
{
  struct hash_list_node *node;
  int len;
  if (version == 4)
  {
    ctx->hashval = airwall_hash_separate4(hdr_get32n(local_ip), local_port, hdr_get32n(remote_ip), remote_port);
    len = 4;
  }
  else
  {
    ctx->hashval = airwall_hash_separate6(local_ip, local_port, remote_ip, remote_port);
    len = 16;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->local_udp_hash, node, ctx->hashval)
  {
    struct airwall_udp_entry *entry;
    entry = CONTAINER_OF(node, struct airwall_udp_entry, local_node);
    if (   entry->version == version
        && ipmemequal(&entry->local_ip, local_ip, len)
        && entry->local_port == local_port
        && ipmemequal(&entry->remote_ip, remote_ip, len)
        && entry->remote_port == remote_port)
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct airwall_icmp_entry *airwall_hash_get_local_icmp(
  struct worker_local *local, int version,
  const void *local_ip, const void *remote_ip, uint16_t identifier, struct airwall_hash_ctx *ctx)
{
  struct hash_list_node *node;
  int len;
  if (version == 4)
  {
    ctx->hashval = airwall_hash_icmp_separate4(hdr_get32n(local_ip), hdr_get32n(remote_ip), identifier);
    len = 4;
  }
  else
  {
    ctx->hashval = airwall_hash_icmp_separate6(local_ip, remote_ip, identifier);
    len = 16;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->local_icmp_hash, node, ctx->hashval)
  {
    struct airwall_icmp_entry *entry;
    entry = CONTAINER_OF(node, struct airwall_icmp_entry, local_node);
    if (   entry->version == version
        && ipmemequal(&entry->local_ip, local_ip, len)
        && entry->local_identifier == identifier
        && ipmemequal(&entry->remote_ip, remote_ip, len))
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct airwall_hash_entry *airwall_hash_get_nat(
  struct worker_local *local, int version,
  const void *nat_ip, uint16_t nat_port, const void *remote_ip, uint16_t remote_port, struct airwall_hash_ctx *ctx)
{
  struct hash_list_node *node;
  int len;
  if (version == 4)
  {
    ctx->hashval = airwall_hash_separate4(hdr_get32n(nat_ip), nat_port, hdr_get32n(remote_ip), remote_port);
    len = 4;
  }
  else
  {
    ctx->hashval = airwall_hash_separate6(nat_ip, nat_port, remote_ip, remote_port);
    len = 16;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->nat_hash, node, ctx->hashval)
  {
    struct airwall_hash_entry *entry;
    entry = CONTAINER_OF(node, struct airwall_hash_entry, nat_node);
    if (   entry->version == version
        && ipmemequal(&entry->nat_ip, nat_ip, len)
        && entry->nat_port == nat_port
        && ipmemequal(&entry->remote_ip, remote_ip, len)
        && entry->remote_port == remote_port)
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct airwall_udp_entry *airwall_hash_get_nat_udp(
  struct worker_local *local, int version,
  const void *nat_ip, uint16_t nat_port, const void *remote_ip, uint16_t remote_port, struct airwall_hash_ctx *ctx)
{
  struct hash_list_node *node;
  int len;
  if (version == 4)
  {
    ctx->hashval = airwall_hash_separate4(hdr_get32n(nat_ip), nat_port, hdr_get32n(remote_ip), remote_port);
    len = 4;
  }
  else
  {
    ctx->hashval = airwall_hash_separate6(nat_ip, nat_port, remote_ip, remote_port);
    len = 16;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->nat_udp_hash, node, ctx->hashval)
  {
    struct airwall_udp_entry *entry;
    entry = CONTAINER_OF(node, struct airwall_udp_entry, nat_node);
    if (   entry->version == version
        && ipmemequal(&entry->nat_ip, nat_ip, len)
        && entry->nat_port == nat_port
        && ipmemequal(&entry->remote_ip, remote_ip, len)
        && entry->remote_port == remote_port)
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct airwall_icmp_entry *airwall_hash_get_nat_icmp(
  struct worker_local *local, int version,
  const void *nat_ip, const void *remote_ip, uint16_t identifier, struct airwall_hash_ctx *ctx)
{
  struct hash_list_node *node;
  int len;
  if (version == 4)
  {
    ctx->hashval = airwall_hash_icmp_separate4(hdr_get32n(nat_ip), hdr_get32n(remote_ip), identifier);
    len = 4;
  }
  else
  {
    ctx->hashval = airwall_hash_icmp_separate6(nat_ip, remote_ip, identifier);
    len = 16;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->nat_icmp_hash, node, ctx->hashval)
  {
    struct airwall_icmp_entry *entry;
    entry = CONTAINER_OF(node, struct airwall_icmp_entry, nat_node);
    if (   entry->version == version
        && ipmemequal(&entry->nat_ip, nat_ip, len)
        && entry->nat_identifier == identifier
        && ipmemequal(&entry->remote_ip, remote_ip, len))
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct airwall_hash_entry *airwall_hash_get4_local(
  struct worker_local *local,
  uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port, struct airwall_hash_ctx *ctx)
{
  local_ip = htonl(local_ip);
  remote_ip = htonl(remote_ip);
  return airwall_hash_get_local(local, 4, &local_ip, local_port, &remote_ip, remote_port, ctx);
}

static inline struct airwall_hash_entry *airwall_hash_get4_nat(
  struct worker_local *local,
  uint32_t nat_ip, uint16_t nat_port, uint32_t remote_ip, uint16_t remote_port, struct airwall_hash_ctx *ctx)
{
  nat_ip = htonl(nat_ip);
  remote_ip = htonl(remote_ip);
  return airwall_hash_get_nat(local, 4, &nat_ip, nat_port, &remote_ip, remote_port, ctx);
}

struct airwall_hash_entry *airwall_hash_put(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *nat_ip,
  uint16_t nat_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint8_t was_synproxied,
  uint64_t time64,
  int port_alloced);

struct airwall_udp_entry *airwall_hash_put_udp(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *nat_ip,
  uint16_t nat_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint8_t was_incoming,
  uint64_t time64);

struct airwall_icmp_entry *airwall_hash_put_icmp(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_identifier,
  const void *nat_ip,
  uint16_t nat_identifier,
  const void *remote_ip,
  uint8_t was_incoming,
  uint64_t time64);

static inline void airwall_hash_put_connected(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *nat_ip,
  uint16_t nat_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint64_t time64)
{
  struct airwall_hash_entry *e;
  uint32_t local_ipv4;
  if (version == 6)
  {
    abort();
  }
  local_ipv4 = hdr_get32n(local_ip);
  allocate_udp_port(local->airwall->porter, nat_port, local_ipv4, local_port, 1);
  e = airwall_hash_put(
    local, version, local_ip, local_port, nat_ip, nat_port, remote_ip, remote_port, 0, time64, 1);
  e->flag_state = FLAG_STATE_ESTABLISHED;
  e->lan_max = 32768;
  e->lan_sent = 0;
  e->lan_acked = 0;
  e->wan_wscale = 0;
  e->wan_max_window_unscaled = 65535;
}

static inline void airwall_init(
  struct airwall *airwall,
  struct conf *conf,
  struct udp_porter *porter,
  struct udp_porter *udp_porter,
  struct udp_porter *icmp_porter)
{
  airwall->conf = conf;
  airwall->porter = porter;
  airwall->udp_porter = udp_porter;
  airwall->icmp_porter = icmp_porter;
  //sack_ip_port_hash_init(&airwall->autolearn, conf->learnhashsize);
  threetuple2ctx_init(&airwall->threetuplectx, porter, udp_porter);
}

static inline void airwall_free(
  struct airwall *airwall, struct worker_local *local)
{
  airwall->conf = NULL;
  //sack_ip_port_hash_free(&airwall->autolearn);
  threetuple2ctx_free(&airwall->threetuplectx, &local->timers);
}

static inline void airwall_hash_del(
  struct worker_local *local,
  struct airwall_hash_entry *e)
{
  hash_table_delete(&local->local_hash, &e->local_node, airwall_hash_local(e));
  hash_table_delete(&local->nat_hash, &e->nat_node, airwall_hash_nat(e));
  timer_linkheap_remove(&local->timers, &e->timer);
  if (e->retxtimer_set)
  {
    timer_linkheap_remove(&local->timers, &e->retx_timer);
    e->retxtimer_set = 0;
  }
  if (e->was_synproxied)
  {
    local->synproxied_connections--;
  }
  else
  {
    local->direct_connections--;
  }
  if (e->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    linked_list_delete(&e->state_data.downlink_half_open.listnode);
    local->half_open_connections--;
  }
  if (e->port_alloced)
  {
    deallocate_udp_port(local->airwall->porter, e->nat_port, !e->was_synproxied);
  }
  free(e->detect);
  e->detect = NULL;
  free(e);
}

struct timer_thread_data {
  struct port *port;
  struct ll_alloc_st *st;
};

int downlink(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st);

int uplink(
  struct airwall *airwall, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st);

#endif
