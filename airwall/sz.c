#include "detect.h"
#include "airwall.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  printf("%zu\n", sizeof(struct airwall_hash_entry));
  printf("%zu\n", sizeof(struct proto_detect_ctx));
  return 0;
}
