#include "udpporter.h"
#include "hashseed.h"
#include <stdio.h>

struct udp_porter porter;

int main(int argc, char **argv)
{
  uint16_t port;
  size_t i;
  uint32_t local_ip = 0x12345678;

  hash_seed_init();

  init_udp_porter(&porter, 32768, 65536);
  allocate_udp_port(&porter, 8080, local_ip, 22, 0);
  allocate_udp_port(&porter, 8080, local_ip, 22, 0);
  allocate_udp_port(&porter, 8080, local_ip, 22, 0);
  deallocate_udp_port(&porter, 8080, !1);
  deallocate_udp_port(&porter, 8080, !1);
  deallocate_udp_port(&porter, 8080, !1);
  allocate_udp_port(&porter, 8080, local_ip, 22, 0);
  allocate_udp_port(&porter, 8080, local_ip, 23, 0);
  deallocate_udp_port(&porter, 8080, !1);
  deallocate_udp_port(&porter, 8080, !1);
  free_udp_porter(&porter);

  init_udp_porter(&porter, 32768, 65536);

  for (i = 0; i < 100; i++)
  {
    port = get_udp_port(&porter, (10<<24)|100, 1024, 1);
    printf("%d\n", port);
    deallocate_udp_port(&porter, port, 1);
  }

  free_udp_porter(&porter);

  return 0;
}
