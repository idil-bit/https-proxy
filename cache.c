
#include "cache.h"
#include "cached_item.h"
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>

#define T Cache

struct T {
    int size;
    Cached_item *cached_items;
    int curr_time;
};

int Cache_evict(T cache);

// size must be >= 0
T Cache_new(int size) {
    T cache = malloc(sizeof(*cache));
    cache->cached_items = calloc(size, sizeof(cache->cached_items[0]));
    assert(cache->cached_items != NULL);
    cache->size = size;
    cache->curr_time = 1;
    return cache;
}

void Cache_free(T *cache) {
    for (int i = 0; i < (*cache)->size; i++) {
        if (!(*cache)->cached_items[i]) {
            continue;
        }
        Cached_item_free(&((*cache)->cached_items[i]));
    }
    free((*cache)->cached_items);
    free(*cache);
}

void Cache_put(T cache, char *key, char *value, int value_size, int max_age) {
    int retrieval_time = cache->curr_time; // is technically retrieved at the time it is put into the cache
    int i = 0;
    while(i < cache->size) {
        if (cache->cached_items[i] == NULL) {
            break; // i is end of cache
        }
        if (strcmp(Cached_item_key(cache->cached_items[i]), key) == 0) {
            Cached_item_free(&cache->cached_items[i]); // replace cached item w/ same name
            break;
        }
        i++;
    }
    if (i >= cache->size) {
        i = Cache_evict(cache);
    } 
    Cached_item cached_item = Cached_item_new(key, value, value_size, cache->curr_time, max_age, retrieval_time);
    cache->cached_items[i] = cached_item;
    assert(cache->cached_items[i] != NULL);
    cache->curr_time++;
}

// evicts item and returns slot of eviction
int Cache_evict(T cache) {
    // first, check for stale items
    int oldest_stale_index = -1;

    // also check for least recently retrieved item
    int least_recently_retrieved_index = -1;
    int least_recently_retrieved_time = -1;

    intmax_t current_time = (intmax_t)time(NULL);
    for (int i = 0; i < cache->size; i++) {
        if (cache->cached_items[i] == NULL) {
            return i;
        }
        intmax_t expiration = Cached_item_expiration(cache->cached_items[i]);
        if (expiration <= current_time) {
            if (oldest_stale_index == -1) {
                oldest_stale_index = i;
                break;
            }
        }
       // find least recently retrieved item
        if (least_recently_retrieved_index == -1 ||
            Cached_item_retrieval_time(cache->cached_items[i]) < least_recently_retrieved_time) {
                least_recently_retrieved_index = i;
                least_recently_retrieved_time = Cached_item_retrieval_time(cache->cached_items[i]);
        }
    }
    int deleted_index = -1;
    // delete stale item if there is one, otherwise delete least recently retrieved item 
    // or oldest never-retrieved item
    if (oldest_stale_index != -1) {
        deleted_index = oldest_stale_index;
    } else {
        deleted_index = least_recently_retrieved_index;
    }

    Cached_item_free(&(cache->cached_items[deleted_index]));

    return deleted_index;
}

// returns cached item with specified key
Cached_item Cache_get(T cache, char *key) {
    Cached_item curr = NULL;
    int i = 0;
    while (i < cache->size) {
        curr = cache->cached_items[i];
        if (curr != NULL && strcmp(curr->key, key) == 0) {
            /* check if item is expired */
            if (Cached_item_expiration(curr) <= (intmax_t) time(NULL)) {
                printf("item expired");
                Cached_item_free(&curr);
                cache->cached_items[i] = NULL;
                return NULL;
            } else {
                curr->retrieval_time = cache->curr_time;
                cache->curr_time++;
                return curr;
            }
        }
        i++;
    }
    return NULL;
}

#undef T