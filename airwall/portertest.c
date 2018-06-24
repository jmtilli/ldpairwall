#include "porter.h"
#include <stdio.h>

struct porter porter;

int main(int argc, char **argv)
{
  uint16_t port;
  size_t i;

  init_porter(&porter);

  for (i = 0; i < 100; i++)
  {
    port = get_port(&porter, 0);
    printf("%d\n", port);
    deallocate_port(&porter, port);
  }
  return 0;
}
