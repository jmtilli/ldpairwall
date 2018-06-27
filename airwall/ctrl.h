#ifndef _CTRL_H_
#define _CTRL_H_

#include "airwall.h"

struct ctrl_args {
  struct airwall *airwall;
  struct worker_local *local;
  int piperd;
};

void *ctrl_func(void *userdata);

#endif
