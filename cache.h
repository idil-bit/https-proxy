#include <time.h>
#include <stdint.h>
#include "cached_item.h"

#ifndef CACHE_INCLUDED
#define CACHE_INCLUDED

#define T Cache
typedef struct T *T;

T Cache_new(int size);
void Cache_free(T *cache);
void Cache_put(T cache, char *key, char *value, int value_size, int max_age);
Cached_item Cache_get(T cache, char *key);

#undef T
#endif