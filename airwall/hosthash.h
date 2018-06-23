#ifndef _HOSTHASH_H_
#define _HOSTHASH_H_

#include "hashtable.h"
#include "containerof.h"
#include "siphash.h"
#include "hashseed.h"

struct host_hash {
  struct hash_table tbl;
};

struct host_hash_entry {
  struct hash_list_node node;
  char *hostname;
  uint32_t local_ip;
};

static inline uint32_t str_hash(const char *name)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_buf(&ctx, name, strlen(name));
  return siphash_get(&ctx);
}

static inline uint32_t host_hash(struct host_hash_entry *e)
{
  return str_hash(e->hostname);
}

uint32_t host_hash_fn(struct hash_list_node *node, void *ud);

static inline void host_hash_init(struct host_hash *hash)
{
  if (hash_table_init(&hash->tbl, 256, host_hash_fn, NULL) != 0)
  {
    abort();
  }
}

static inline void
host_hash_add(struct host_hash *hash, const char *name, uint32_t ip)
{
  struct host_hash_entry *e;
  e = malloc(sizeof(*e));
  e->local_ip = ip;
  e->hostname = strdup(name);
  hash_table_add_nogrow_already_bucket_locked(&hash->tbl, &e->node, host_hash(e));
}

static inline void host_hash_free(struct host_hash *hash)
{
  struct hash_list_node *n, *x;
  unsigned bucket;
  HASH_TABLE_FOR_EACH_SAFE(&hash->tbl, bucket, n, x)
  {
    struct host_hash_entry *e;
    e = CONTAINER_OF(n, struct host_hash_entry, node);
    hash_table_delete_already_bucket_locked(&hash->tbl, &e->node);
    free(e->hostname);
    e->hostname = NULL;
    free(e);
  }
  hash_table_free(&hash->tbl);
}

#endif
