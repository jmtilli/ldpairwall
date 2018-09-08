#ifndef _UDPPORTER_H_
#define _UDPPORTER_H_

#include "linkedlist.h"
#include "hashtable.h"
#include <stdint.h>

struct free_udp_port {
  struct linked_list_node node;
  struct hash_list_node hashnode;
  uint32_t count;
  uint32_t lan_ip;
  uint16_t port;
  uint16_t lan_port;
  uint32_t available:1;
  uint32_t outcount:31;
};

struct udp_porter {
  struct linked_list_head udpportcnts[65536];
  struct free_udp_port udpports[65536];
  struct hash_table hash;
};

void init_udp_porter(struct udp_porter *porter, uint32_t portrange_first,
                     uint32_t portrange_last);

void free_udp_porter(struct udp_porter *porter);

void allocate_udp_port(struct udp_porter *porter,
                       uint16_t port, uint32_t local_ip, uint16_t local_port,
                       int outgoing);

void deallocate_udp_port(struct udp_porter *porter, uint16_t port,
                         int outgoing);

uint16_t get_udp_port_different(struct udp_porter *porter,
                                uint32_t local_ip,
                                uint16_t preferred, uint16_t local_port,
                                int outgoing);

uint16_t get_udp_port(struct udp_porter *porter,
                      uint32_t local_ip, uint16_t preferred, int outoging);

int get_exact_port_in(struct udp_porter *porter, uint32_t local_ip, uint16_t port);

#endif
