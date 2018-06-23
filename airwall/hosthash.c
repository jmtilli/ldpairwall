#include "hosthash.h"

uint32_t host_hash_fn(struct hash_list_node *node, void *ud)
{
  return host_hash(CONTAINER_OF(node, struct host_hash_entry, node));
}
