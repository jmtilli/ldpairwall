#ifndef _PORTER_H_
#define _PORTER_H_

#include "linkedlist.h"
#include <stdint.h>

struct free_udp_port {
  struct linked_list_node node;
  uint32_t count;
  uint32_t lan_ip;
  uint16_t port;
  uint16_t lan_port;
  uint8_t available:1;
};

struct linked_list_head udpportcnts[65536];
struct free_udp_port udpports[65536];

void init_udp_porter(void);

void allocate_udp_port(uint16_t port, uint32_t local_ip, uint16_t local_port);

void deallocate_udp_port(uint16_t port);

uint16_t get_udp_port(uint32_t local_ip, uint16_t preferred);

#endif
