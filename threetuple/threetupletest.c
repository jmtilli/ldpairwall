#include <stdint.h>
#include <errno.h>
#include "siphash.h"
#include "hashseed.h"
#include "hashtable.h"
#include "containerof.h"
#include "threetuple.h"
#include "time64.h"

int main(int argc, char **argv)
{
  struct threetuplectx ctx = {};
  struct threetuplepayload payload = {};
  struct timer_linkheap heap = {};
  timer_linkheap_init(&heap);
  hash_seed_init();
  threetuplectx_init(&ctx);
  if (threetuplectx_find(&ctx, (10<<24) | 1, 12345, 17, NULL) != -ENOENT)
  {
    abort();
  }
  if (threetuplectx_delete(&ctx, &heap, (10<<24) | 1, 12345, 17, 1, 1) != -ENOENT)
  {
    abort();
  }
  if (threetuplectx_add(&ctx, &heap, (10<<24) | 1, 12345, 17, 1, 1, &payload, gettime64()) != 0)
  {
    abort();
  }
  if (threetuplectx_find(&ctx, (10<<24) | 1, 12345, 17, NULL) != 0)
  {
    abort();
  }
  if (threetuplectx_add(&ctx, &heap, (10<<24) | 1, 12345, 17, 1, 1, &payload, gettime64())
      != -EEXIST)
  {
    abort();
  }
  if (threetuplectx_delete(&ctx, &heap, (10<<24) | 1, 12345, 17, 1, 1) != 0)
  {
    abort();
  }
  if (threetuplectx_find(&ctx, (10<<24) | 1, 12345, 17, NULL) != -ENOENT)
  {
    abort();
  }
  if (threetuplectx_modify(&ctx, &heap, (10<<24) | 1, 12345, 17, 1, 1, &payload, gettime64()) != 0)
  {
    abort();
  }
  if (threetuplectx_modify(&ctx, &heap, (10<<24) | 1, 12345, 17, 1, 1, &payload, gettime64()) != 0)
  {
    abort();
  }
  threetuplectx_free(&ctx, &heap);
  return 0;
}
