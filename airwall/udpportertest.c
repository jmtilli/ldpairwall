#include "udpporter.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  uint16_t port;
  size_t i;

  init_udp_porter();

  for (i = 0; i < 100; i++)
  {
    port = get_udp_port((10<<24)|100, 1024);
    printf("%d\n", port);
    deallocate_udp_port(port);
  }
  return 0;
}
