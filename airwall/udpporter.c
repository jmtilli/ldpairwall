#include "udpporter.h"
#include "containerof.h"
#include <stdlib.h>

struct linked_list_head udpportcnts[65536] = {};
struct free_udp_port udpports[65536] = {};

void init_udp_porter(void)
{
  size_t i;
  for (i = 0; i < 65536; i++)
  {
    linked_list_head_init(&udpportcnts[i]);
  }
  for (i = 0; i < 65536; i++)
  {
    udpports[i].port = i;
    udpports[i].count = 0;
    udpports[i].available = 0;
  }
  for (i = 1024; i < 65536; i++)
  {
    udpports[i].available = 1;
    linked_list_add_tail(&udpports[i].node, &udpportcnts[0]);
  }
}

void allocate_udp_port(uint16_t port, uint32_t local_ip, uint16_t local_port)
{
  if (udpports[port].count == 0)
  {
    udpports[port].lan_ip = local_ip;
    udpports[port].lan_port = local_port;
  }
  else
  {
    udpports[port].lan_ip = 0;
    udpports[port].lan_port = 0;
  }
  if (udpports[port].count <= UINT16_MAX)
  {
    linked_list_delete(&udpports[port].node);
  }
  udpports[port].count++;
  if (udpports[port].count <= UINT16_MAX)
  {
    linked_list_add_tail(&udpports[port].node, &udpportcnts[udpports[port].count]);
  }
}

void deallocate_udp_port(uint16_t port)
{
  if (udpports[port].count == 0)
  {
    abort();
  }
  if (udpports[port].count <= UINT16_MAX)
  {
    linked_list_delete(&udpports[port].node);
  }
  udpports[port].lan_ip = 0;
  udpports[port].lan_port = 0;
  udpports[port].count--;
  if (udpports[port].count <= UINT16_MAX)
  {
    linked_list_add_tail(&udpports[port].node, &udpportcnts[udpports[port].count]);
  }
}

uint16_t get_udp_port(uint32_t local_ip, uint16_t preferred)
{
  uint16_t port = 0;
  size_t i;
  if (udpports[preferred].count == 0 && udpports[preferred].available)
  {
    allocate_udp_port(preferred, local_ip, preferred);
    return preferred;
  }
  for (i = 0; i < 65536; i++)
  {
    if (linked_list_is_empty(&udpportcnts[i]))
    {
      continue;
    }
    port = CONTAINER_OF(udpportcnts[i].node.next, struct free_udp_port, node)->port;
    break;
  }
  allocate_udp_port(port, local_ip, preferred);
  return port;
}
