#include <stdint.h>
#include <errno.h>
#include "siphash.h"
#include "hashseed.h"
#include "hashtable.h"
#include "containerof.h"
#include "threetuple2.h"
#include "time64.h"

int main(int argc, char **argv)
{
  struct threetuple2ctx ctx = {};
  struct timer_linkheap heap = {};
  timer_linkheap_init(&heap);
  hash_seed_init();
  threetuple2ctx_init(&ctx, NULL, NULL);
  if (threetuple2ctx_consume(&ctx, &heap, (10<<24) | 1, 12345, 17, NULL, NULL) != -ENOENT)
  {
    abort();
  }
  if (threetuple2ctx_add(&ctx, &heap, 0, 0, (10<<24) | 1, 12345, 17, (10<<24)|100, 54321, gettime64() + 2ULL*1000ULL*1000ULL) != 0)
  {
    abort();
  }
  if (threetuple2ctx_consume(&ctx, &heap, (10<<24) | 1, 12345, 17, NULL, NULL) != 0)
  {
    abort();
  }
  if (threetuple2ctx_add(&ctx, &heap, 0, 0, (10<<24) | 1, 12345, 17, (10<<24)|100, 54321, gettime64() + 2ULL*1000ULL*1000ULL)
      != -EEXIST)
  {
    abort();
  }
  threetuple2ctx_free(&ctx, &heap);
  return 0;
}
