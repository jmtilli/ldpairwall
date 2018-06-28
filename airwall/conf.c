#include "conf.h"

uint32_t ul_addr_hash_fn(struct hash_list_node *node, void *ud)
{
  return ul_addr_hash(CONTAINER_OF(node, struct ul_addr, node));
}
