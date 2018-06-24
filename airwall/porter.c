#include "porter.h"
#include "containerof.h"
#include <stdlib.h>

void init_porter(struct porter *porter)
{
  size_t i;
  for (i = 0; i < 65536; i++)
  {
    linked_list_head_init(&porter->portcnts[i]);
  }
  for (i = 0; i < 65536; i++)
  {
    porter->ports[i].port = i;
    porter->ports[i].count = 0;
    porter->ports[i].available = 0;
  }
  for (i = 32768; i < 65536; i++)
  {
    porter->ports[i].available = 1;
    linked_list_add_tail(&porter->ports[i].node, &porter->portcnts[0]);
  }
}

void allocate_port(struct porter *porter, uint16_t port)
{
  if (porter->ports[port].count <= UINT16_MAX && porter->ports[port].available)
  {
    linked_list_delete(&porter->ports[port].node);
  }
  porter->ports[port].count++;
  if (porter->ports[port].count <= UINT16_MAX && porter->ports[port].available)
  {
    linked_list_add_tail(&porter->ports[port].node, &porter->portcnts[porter->ports[port].count]);
  }
}

void deallocate_port(struct porter *porter, uint16_t port)
{
  if (porter->ports[port].count == 0)
  {
    abort();
  }
  if (porter->ports[port].count <= UINT16_MAX && porter->ports[port].available)
  {
    linked_list_delete(&porter->ports[port].node);
  }
  porter->ports[port].count--;
  if (porter->ports[port].count <= UINT16_MAX && porter->ports[port].available)
  {
    linked_list_add_tail(&porter->ports[port].node, &porter->portcnts[porter->ports[port].count]);
  }
}

uint16_t get_port(struct porter *porter, uint16_t preferred)
{
  uint16_t port = 0;
  size_t i;
  if (porter->ports[preferred].count == 0 && porter->ports[preferred].available)
  {
    allocate_port(porter, preferred);
    return preferred;
  }
  for (i = 0; i < 65536; i++)
  {
    if (linked_list_is_empty(&porter->portcnts[i]))
    {
      continue;
    }
    port = CONTAINER_OF(porter->portcnts[i].node.next, struct free_port, node)->port;
    break;
  }
  allocate_port(porter, port);
  return port;
}
