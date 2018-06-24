#include "porter.h"
#include "containerof.h"
#include <stdlib.h>

void init_porter(void)
{
  size_t i;
  for (i = 0; i < 65536; i++)
  {
    linked_list_head_init(&portcnts[i]);
  }
  for (i = 0; i < 65536; i++)
  {
    ports[i].port = i;
    ports[i].count = 0;
    ports[i].available = 0;
  }
  for (i = 1024; i < 65536; i++)
  {
    ports[i].available = 1;
    linked_list_add_tail(&ports[i].node, &portcnts[0]);
  }
}

void allocate_port(uint16_t port)
{
  ports[port].count++;
  linked_list_delete(&ports[port].node);
  linked_list_add_tail(&ports[port].node, &portcnts[ports[port].count]);
}

void deallocate_port(uint16_t port)
{
  if (ports[port].count == 0)
  {
    abort();
  }
  ports[port].count--;
  linked_list_delete(&ports[port].node);
  linked_list_add_tail(&ports[port].node, &portcnts[ports[port].count]);
}

uint16_t get_port(uint16_t preferred)
{
  uint16_t port = 0;
  size_t i;
  if (ports[preferred].count == 0 && ports[preferred].available)
  {
    allocate_port(preferred);
    return preferred;
  }
  for (i = 0; i < 65536; i++)
  {
    if (linked_list_is_empty(&portcnts[i]))
    {
      continue;
    }
    port = CONTAINER_OF(portcnts[i].node.next, struct free_port, node)->port;
  }
  allocate_port(port);
  return port;
}
