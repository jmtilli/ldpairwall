#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "detect.h"

uint64_t uribitmaskloc[2] = {0,0};
uint64_t tokenbitmaskloc[2] = {0,0};

static inline int istoken(char ch)
{
  return ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' ||
         ch == '\'' || ch == '*' || ch == '+' || ch == '-' || ch == '.' ||
         ch == '^' || ch == '_' || ch == '`' || ch == '|' || ch == '~' ||
         isdigit(ch) || isalpha(ch);
}

static inline int isurichar(char ch)
{
  return ch == ':' || ch == '/' || ch == '?' || ch == '#' || ch == '[' ||
         ch == ']' || ch == '@' || ch == '!' || ch == '$' || ch == '&' ||
         ch == '\'' || ch == '(' || ch == ')' || ch == '*' || ch == '+' ||
         ch == ',' || ch == ';' || ch == '=' || isdigit(ch) || isalpha(ch) ||
         ch == '-' || ch == '.' || ch == '_' || ch == '~' || ch == '%';
}

static inline int isuricharfast(char ch)
{
  uint8_t i = (uint8_t)ch;
  if (i >= 128)
  {
    return 0;
  }
  return !!(uribitmaskloc[i/64] & (1ULL<<(i%64)));
}
static inline int istokenfast(char ch)
{
  uint8_t i = (uint8_t)ch;
  if (i >= 128)
  {
    return 0;
  }
  return !!(tokenbitmaskloc[i/64] & (1ULL<<(i%64)));
}

static void gentbls(void)
{
  uint8_t i;
  for (i = 0; i < 128; i++)
  {
    if (isurichar((char)i))
    {
      uribitmaskloc[i/64] |= 1ULL<<(i%64);
    }
    if (istoken((char)i))
    {
      tokenbitmaskloc[i/64] |= 1ULL<<(i%64);
    }
  }
  for (i = 0; i < 128; i++)
  {
    if ((!!isurichar((char)i)) != isuricharfast((char)i))
    {
      printf("err uri %d\n", i);
      abort();
    }
    if ((!!istoken((char)i)) != istokenfast((char)i))
    {
      printf("err tok %d\n", i);
      abort();
    }
  }
  printf("const uint64_t uribitmask[4] = {\n");
  printf("  0x%llxULL,\n", (unsigned long long)uribitmaskloc[0]);
  printf("  0x%llxULL,\n", (unsigned long long)uribitmaskloc[1]);
  printf("  0x%llxULL,\n", (unsigned long long)0);
  printf("  0x%llxULL,\n", (unsigned long long)0);
  printf("};\n");
  printf("const uint64_t tokenbitmask[4] = {\n");
  printf("  0x%llxULL,\n", (unsigned long long)tokenbitmaskloc[0]);
  printf("  0x%llxULL,\n", (unsigned long long)tokenbitmaskloc[1]);
  printf("  0x%llxULL,\n", (unsigned long long)0);
  printf("  0x%llxULL,\n", (unsigned long long)0);
  printf("};\n");
}


int main(int argc, char **argv)
{
  gentbls();
  return 0;
}
