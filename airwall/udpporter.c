#include "udpporter.h"
#include "containerof.h"
#include "siphash.h"
#include "hashseed.h"
#include <stdlib.h>

static inline uint32_t free_udp_port_hash_separate(uint32_t ip, uint16_t port)
{
  return siphash64(hash_seed_get(), (((uint64_t)ip)<<32)|port);
}

static inline uint32_t free_udp_port_hash(struct free_udp_port *freeport)
{
  return free_udp_port_hash_separate(freeport->lan_ip, freeport->lan_port);
}

static uint32_t free_udp_port_hash_fn(struct hash_list_node *node, void *ud)
{
  struct free_udp_port *freeport =
    CONTAINER_OF(node, struct free_udp_port, hashnode);
  return free_udp_port_hash(freeport);
}

void init_udp_porter(struct udp_porter *porter)
{
  size_t i;
  if (hash_table_init(&porter->hash, 65536, free_udp_port_hash_fn, NULL) != 0)
  {
    abort();
  }
  for (i = 0; i < 65536; i++)
  {
    linked_list_head_init(&porter->udpportcnts[i]);
  }
  for (i = 0; i < 65536; i++)
  {
    porter->udpports[i].port = i;
    porter->udpports[i].count = 0;
    porter->udpports[i].outcount = 0;
    porter->udpports[i].available = 0;
    porter->udpports[i].lan_ip = 0;
    porter->udpports[i].lan_port = 0;
  }
  for (i = 32768; i < 65536; i++)
  {
    porter->udpports[i].available = 1;
    linked_list_add_tail(&porter->udpports[i].node, &porter->udpportcnts[0]);
  }
}

void free_udp_porter(struct udp_porter *porter)
{
  hash_table_free(&porter->hash);
}

void allocate_udp_port(struct udp_porter *porter,
                       uint16_t port, uint32_t local_ip, uint16_t local_port,
                       int outgoing)
{
  if (porter->udpports[port].count == 0)
  {
    int add_hash = 0;
    if (porter->udpports[port].lan_ip == 0 && porter->udpports[port].lan_port == 0)
    {
      add_hash = 1;
    }
    porter->udpports[port].lan_ip = local_ip;
    porter->udpports[port].lan_port = local_port;
    if (add_hash && (local_ip != 0 || local_port != 0))
    {
      uint32_t hashval = free_udp_port_hash(&porter->udpports[port]);
      hash_table_add_nogrow(&porter->hash, &porter->udpports[port].hashnode, hashval);
    }
  }
  else if (porter->udpports[port].lan_ip != local_ip || porter->udpports[port].lan_port != local_port)
  {
    if (porter->udpports[port].lan_ip != 0 || porter->udpports[port].lan_port != 0)
    {
      hash_table_delete_already_bucket_locked(&porter->hash, &porter->udpports[port].hashnode);
    }
    porter->udpports[port].lan_ip = 0;
    porter->udpports[port].lan_port = 0;
  }
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_delete(&porter->udpports[port].node);
  }
  porter->udpports[port].count++;
  if (outgoing)
  {
    porter->udpports[port].outcount++;
  }
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_add_tail(&porter->udpports[port].node, &porter->udpportcnts[porter->udpports[port].count]);
  }
}

void deallocate_udp_port(struct udp_porter *porter, uint16_t port, int outgoing)
{
  if (porter->udpports[port].count == 0)
  {
    abort();
  }
  if (outgoing)
  {
    if (porter->udpports[port].outcount == 0)
    {
      abort();
    }
  }

  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_delete(&porter->udpports[port].node);
  }
  porter->udpports[port].count--;
  if (outgoing)
  {
    porter->udpports[port].outcount--;
  }
  if (porter->udpports[port].count == 0 && (porter->udpports[port].lan_ip != 0 || porter->udpports[port].lan_port != 0))
  {
    hash_table_delete_already_bucket_locked(&porter->hash, &porter->udpports[port].hashnode);
  }
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_add_tail(&porter->udpports[port].node, &porter->udpportcnts[porter->udpports[port].count]);
  }
}

uint16_t get_udp_port_different(struct udp_porter *porter, uint32_t local_ip, uint16_t preferred, uint16_t local_port)
{
  uint16_t port = 0;
  size_t i;
  uint32_t hashval = free_udp_port_hash_separate(local_ip, local_port);
  struct hash_list_node *node;

  HASH_TABLE_FOR_EACH_POSSIBLE(&porter->hash, node, hashval)
  {
    struct free_udp_port *freeport =
      CONTAINER_OF(node, struct free_udp_port, hashnode);
    if (freeport->lan_ip == local_ip && freeport->lan_port == local_port &&
        freeport->available)
    {
      allocate_udp_port(porter, freeport->port, local_ip, local_port, 1);
      return freeport->port;
    }
  }

  if ((porter->udpports[preferred].count == 0 || (porter->udpports[preferred].lan_ip == local_ip && porter->udpports[preferred].lan_port == local_port)) && porter->udpports[preferred].available)
  {
    allocate_udp_port(porter, preferred, local_ip, local_port, 1);
    return preferred;
  }
  for (i = 0; i < 65536; i++)
  {
    if (linked_list_is_empty(&porter->udpportcnts[i]))
    {
      continue;
    }
    port = CONTAINER_OF(porter->udpportcnts[i].node.next, struct free_udp_port, node)->port;
    break;
  }
  allocate_udp_port(porter, port, local_ip, local_port, 1);
  return port;
}

uint16_t get_udp_port(struct udp_porter *porter, uint32_t local_ip, uint16_t preferred)
{
  return get_udp_port_different(porter, local_ip, preferred, preferred);
}
