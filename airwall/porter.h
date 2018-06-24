#ifndef _PORTER_H_
#define _PORTER_H_

#include "linkedlist.h"
#include <stdint.h>

struct free_port {
  struct linked_list_node node;
  uint16_t port;
  uint16_t count;
  uint8_t available:1;
};

struct linked_list_head portcnts[65536];
struct free_port ports[65536];

void init_porter(void);

void allocate_port(uint16_t port);

void deallocate_port(uint16_t port);

uint16_t get_port(uint16_t preferred);

#endif
