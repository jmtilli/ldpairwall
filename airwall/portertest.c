#include "porter.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  uint16_t port;
  size_t i;

  init_porter();

  for (i = 0; i < 100; i++)
  {
    port = get_port(0);
    printf("%d\n", port);
    deallocate_port(port);
  }
  return 0;
}
