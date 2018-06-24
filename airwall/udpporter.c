#include "udpporter.h"
#include "containerof.h"
#include <stdlib.h>

void init_udp_porter(struct udp_porter *porter)
{
  size_t i;
  for (i = 0; i < 65536; i++)
  {
    linked_list_head_init(&porter->udpportcnts[i]);
  }
  for (i = 0; i < 65536; i++)
  {
    porter->udpports[i].port = i;
    porter->udpports[i].count = 0;
    porter->udpports[i].available = 0;
  }
  for (i = 32768; i < 65536; i++)
  {
    porter->udpports[i].available = 1;
    linked_list_add_tail(&porter->udpports[i].node, &porter->udpportcnts[0]);
  }
}

void allocate_udp_port(struct udp_porter *porter,
                       uint16_t port, uint32_t local_ip, uint16_t local_port)
{
  if (porter->udpports[port].count == 0)
  {
    porter->udpports[port].lan_ip = local_ip;
    porter->udpports[port].lan_port = local_port;
  }
  else if (porter->udpports[port].lan_ip != local_ip || porter->udpports[port].lan_port != local_port)
  {
    porter->udpports[port].lan_ip = 0;
    porter->udpports[port].lan_port = 0;
  }
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_delete(&porter->udpports[port].node);
  }
  porter->udpports[port].count++;
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_add_tail(&porter->udpports[port].node, &porter->udpportcnts[porter->udpports[port].count]);
  }
}

void deallocate_udp_port(struct udp_porter *porter, uint16_t port)
{
  if (porter->udpports[port].count == 0)
  {
    abort();
  }
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_delete(&porter->udpports[port].node);
  }
  porter->udpports[port].count--;
  if (porter->udpports[port].count <= UINT16_MAX && porter->udpports[port].available)
  {
    linked_list_add_tail(&porter->udpports[port].node, &porter->udpportcnts[porter->udpports[port].count]);
  }
}

uint16_t get_udp_port(struct udp_porter *porter, uint32_t local_ip, uint16_t preferred)
{
  uint16_t port = 0;
  size_t i;
  if ((porter->udpports[preferred].count == 0 || (porter->udpports[preferred].lan_ip == local_ip && porter->udpports[preferred].lan_port == preferred)) && porter->udpports[preferred].available)
  {
    allocate_udp_port(porter, preferred, local_ip, preferred);
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
  allocate_udp_port(porter, port, local_ip, preferred);
  return port;
}
