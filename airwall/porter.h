#ifndef _PORTER_H_
#define _PORTER_H_

#include "linkedlist.h"
#include <stdint.h>

struct free_port {
  struct linked_list_node node;
  uint32_t count;
  uint16_t port;
  uint8_t available:1;
};

struct porter {
  struct linked_list_head portcnts[65536];
  struct free_port ports[65536];
};

void init_porter(struct porter *porter);

void allocate_port(struct porter *porter, uint16_t port);

void deallocate_port(struct porter *porter, uint16_t port);

uint16_t get_port(struct porter *porter, uint16_t preferred);

#endif
