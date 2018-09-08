#ifndef _CONF_H_
#define _CONF_H_

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include "dynarr.h"
#include "log.h"
#include "hosthash.h"

enum sackconflict {
  SACKCONFLICT_REMOVE,
  SACKCONFLICT_RETAIN,
};

struct ratehashconf {
  size_t size;
  uint32_t timer_period_usec;
  uint32_t timer_add;
  uint32_t initial_tokens;
  uint8_t network_prefix;
  uint8_t network_prefix6;
};

struct ul_addr {
  struct hash_list_node node;
  uint32_t addr;
};

struct portrange {
  uint32_t first;
  uint32_t one_past_last;
};

struct portranges {
  struct portrange tcp;
  struct portrange udp;
};

struct static_mapping {
  uint32_t ext_addr;
  uint16_t ext_port;
  uint32_t int_addr;
  uint8_t protocol;
  uint16_t int_port;
};

struct timeouts {
  uint32_t connected;
  uint32_t one_fin;
  uint32_t both_fin;
  uint32_t ul_syn_sent;
  uint32_t ul_syn_rcvd;
  uint32_t dl_half_open;
  uint32_t dl_syn_sent;
  uint32_t time_wait;
  uint32_t reseted;
  uint32_t window_update_sent;
  uint32_t retx;
  uint32_t udp;
  uint32_t icmp;
  uint32_t reass_timeout;
  uint32_t reass_timer;
};

static inline uint32_t ul_addr_hash_separate(uint32_t addr)
{
  return siphash64(hash_seed_get(), addr);
}
static inline uint32_t ul_addr_hash(struct ul_addr *addr)
{
  return ul_addr_hash_separate(addr->addr);
}
uint32_t ul_addr_hash_fn(struct hash_list_node *node, void *ud);

struct conf {
  enum sackconflict sackconflict;
  size_t conntablesize;
  unsigned threadcount;
  struct ratehashconf ratehash;
  DYNARR(uint16_t) msslist;
  DYNARR(uint8_t) wscalelist;
  DYNARR(uint16_t) tsmsslist;
  DYNARR(uint8_t) tswscalelist;
  DYNARR(struct static_mapping) static_mappings;
  uint32_t halfopen_cache_max;
  uint32_t detect_cache_max;
  int msslist_present;
  int wscalelist_present;
  int tsmsslist_present;
  int tswscalelist_present;
  uint8_t msslist_bits;
  uint8_t wscalelist_bits;
  uint8_t tsmsslist_bits;
  uint8_t tswscalelist_bits;
  uint8_t ts_bits;
  uint16_t own_mss;
  uint8_t own_wscale;
  uint8_t mss_clamp_enabled;
  uint16_t mss_clamp;
  uint8_t own_sack;
  uid_t uid;
  gid_t gid;
  int test_connections;
  uint16_t port;
  struct host_hash hosts;
  struct hash_table ul_alternatives;
  int enable_ack;
  uint32_t dl_addr;
  uint32_t ul_addr;
  uint32_t dl_mask;
  uint32_t ul_mask;
  uint32_t ul_defaultgw;
  int allow_anyport_primary;
  uint32_t port_binding_limit;
  uint32_t max_tcp_connections;
  uint32_t max_udp_connections;
  uint32_t max_icmp_connections;
  uint32_t reass_memory_max;
  struct timeouts timeouts;
  struct portranges portranges;
};

static inline int ul_addr_is_mine(struct conf *conf, uint32_t addr)
{
  struct hash_list_node *node;
  uint32_t hashval;
  if (addr == conf->ul_addr)
  {
    return 1;
  }
  hashval = ul_addr_hash_separate(addr);
  HASH_TABLE_FOR_EACH_POSSIBLE(&conf->ul_alternatives, node, hashval)
  {
    struct ul_addr *e = CONTAINER_OF(node, struct ul_addr, node);
    if (e->addr == addr)
    {
      return 1;
    }
  }
  return 0;
}

static inline void conf_init(struct conf *conf)
{
  conf->sackconflict = SACKCONFLICT_RETAIN;
  conf->conntablesize = 131072;
  conf->ratehash.size = 131072;
  conf->ratehash.timer_period_usec = (1000*1000);
  conf->ratehash.timer_add = 400;
  conf->ratehash.initial_tokens = 2000;
  conf->ratehash.network_prefix = 24;
  conf->ratehash.network_prefix6 = 64;
  DYNARR_INIT(&conf->msslist);
  DYNARR_INIT(&conf->wscalelist);
  DYNARR_INIT(&conf->tsmsslist);
  DYNARR_INIT(&conf->tswscalelist);
  DYNARR_INIT(&conf->static_mappings);
  conf->timeouts.connected = 86400;
  conf->timeouts.one_fin = 7440;
  conf->timeouts.both_fin = 240;
  conf->timeouts.ul_syn_sent = 240;
  conf->timeouts.ul_syn_rcvd = 240;
  conf->timeouts.dl_half_open = 240;
  conf->timeouts.dl_syn_sent = 240;
  conf->timeouts.window_update_sent = 240;
  conf->timeouts.time_wait = 120;
  conf->timeouts.reseted = 45;
  conf->timeouts.retx = 1;
  conf->timeouts.udp = 300;
  conf->timeouts.icmp = 60;
  conf->timeouts.reass_timeout = 60;
  conf->timeouts.reass_timer = 1;
  conf->msslist_present = 0;
  conf->wscalelist_present = 0;
  conf->own_mss = 1460;
  conf->own_wscale = 7;
  conf->mss_clamp_enabled = 0;
  conf->mss_clamp = 1460;
  conf->ts_bits = 5;
  conf->halfopen_cache_max = 0;
  conf->detect_cache_max = 8192;
  conf->threadcount = 1;
  conf->uid = 0;
  conf->gid = 0;
  conf->test_connections = 0;
  conf->port = 12345;
  host_hash_init(&conf->hosts);
  if (hash_table_init(&conf->ul_alternatives, 256, ul_addr_hash_fn, NULL) != 0)
  {
    abort();
  }
  conf->enable_ack = 0;
  conf->dl_addr = 0;
  conf->ul_addr = 0;
  conf->dl_mask = 0;
  conf->ul_mask = 0;
  conf->ul_defaultgw = 0;
  conf->allow_anyport_primary = 0;
  conf->port_binding_limit = 0;
  conf->max_tcp_connections = 131072;
  conf->max_udp_connections = 131072;
  conf->max_icmp_connections = 131072;
  conf->reass_memory_max = 33554432;
  conf->portranges.tcp.first = 32768;
  conf->portranges.tcp.one_past_last = 65536;
  conf->portranges.udp.first = 32768;
  conf->portranges.udp.one_past_last = 65536;
}

static inline void conf_free(struct conf *conf)
{
  struct hash_list_node *n, *x;
  unsigned bucket;

  DYNARR_FREE(&conf->msslist);
  DYNARR_FREE(&conf->wscalelist);
  DYNARR_FREE(&conf->tsmsslist);
  DYNARR_FREE(&conf->tswscalelist);
  DYNARR_FREE(&conf->static_mappings);
  host_hash_free(&conf->hosts);
  HASH_TABLE_FOR_EACH_SAFE(&conf->ul_alternatives, bucket, n, x)
  {
    struct ul_addr *addr = CONTAINER_OF(n, struct ul_addr, node);
    hash_table_delete_already_bucket_locked(&conf->ul_alternatives, &addr->node);
    free(addr);
  }
  hash_table_free(&conf->ul_alternatives);
}

static inline int conf_postprocess(struct conf *conf)
{
  uint8_t bits = 0;
  unsigned bucket;
  size_t i;
  struct hash_list_node *node;
  if (!conf->wscalelist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 0))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 2))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 4))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 7))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->wscalelist_present = 1;
  }
  if (!conf->tswscalelist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 0))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 1))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 3))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 5))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 6))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 8))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 9))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 10))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->tswscalelist_present = 1;
  }
  if (!conf->msslist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->msslist, 216))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1200))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1400))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1460))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->msslist_present = 1;
  }
  if (!conf->tsmsslist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 216))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 344))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 536))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 712))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 940))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 1360))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 1440))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 1452))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->tsmsslist_present = 1;
  }
  conf->msslist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->msslist))
    {
      conf->msslist_bits = bits;
      break;
    }
  }
  conf->wscalelist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->wscalelist))
    {
      conf->wscalelist_bits = bits;
      break;
    }
  }
  conf->tsmsslist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->tsmsslist))
    {
      conf->tsmsslist_bits = bits;
      break;
    }
  }
  conf->tswscalelist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->tswscalelist))
    {
      conf->tswscalelist_bits = bits;
      break;
    }
  }
  if (conf->msslist_bits + conf->wscalelist_bits + 1 > 12)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "too long lists, too little cryptographic security");
    return -EINVAL;
  }
  if (conf->tsmsslist_bits + conf->tswscalelist_bits + conf->ts_bits > 12)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "too long lists, too little TS cryptographic security");
    return -EINVAL;
  }
  if (DYNARR_GET(&conf->wscalelist, 0) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "first element of wscale list must be 0");
    return -EINVAL;
  }
  if (DYNARR_GET(&conf->tswscalelist, 0) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "first element of ts wscale list must be 0");
    return -EINVAL;
  }
  if (conf->dl_addr == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "downlink address not set");
    return -EINVAL;
  }
  if (conf->ul_addr == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "uplink address not set");
    return -EINVAL;
  }
  if (conf->dl_mask == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "downlink mask not set");
    return -EINVAL;
  }
  if (conf->ul_mask == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "uplink mask not set");
    return -EINVAL;
  }
  if (conf->ul_defaultgw == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "uplink default GW not set");
    return -EINVAL;
  }
  if (conf->ul_defaultgw == conf->ul_addr)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "uplink primary addr same as default GW");
    return -EINVAL;
  }
  HASH_TABLE_FOR_EACH(&conf->ul_alternatives, bucket, node)
  {
    struct ul_addr *e = CONTAINER_OF(node, struct ul_addr, node);
    if ((e->addr & conf->ul_mask) != (conf->ul_addr & conf->ul_mask))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "uplink addresses not in same subnet");
      return -EINVAL;
    }
    if (e->addr == conf->ul_defaultgw)
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "uplink alt addresses same as default GW");
      return -EINVAL;
    }
  }
  for (i = 0; i < DYNARR_SIZE(&conf->static_mappings); i++)
  {
    struct static_mapping *map = &DYNARR_GET(&conf->static_mappings, i);
    if (!ul_addr_is_mine(conf, map->ext_addr))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "can't add mapping: addr not mine");
      return -EINVAL;
    }
  }
  return 0;
}

#endif
