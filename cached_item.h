#include <time.h>
#include <stdint.h>

#ifndef CACHED_ITEM_INCLUDED
#define CACHED_ITEM_INCLUDED

#define T Cached_item
typedef struct T *T;

struct T {
    char *key;
    char *value;
    int value_size;
    intmax_t initial_storage_time;
    int relative_storage_time; // relative to other files in cache
    int max_age; // in seconds
    int retrieval_time; // relative to other files in cache
};

T Cached_item_new(char *key, char *value, int value_size, int relative_storage_time, int max_age, 
                  int retrieval_time);
intmax_t Cached_item_expiration(T cached_item);
void Cached_item_free(T *cached_item);
void Cached_item_update(T cached_item, int relative_storage_time, int max_age);
int Cached_item_retrieve(T cached_item, int curr_time, char **value, int *value_size);
char *Cached_item_output_key(T cached_item);

// retrieval of member variables
char *Cached_item_key(T cached_item);
int Cached_item_retrieval_time(T cached_item);
int Cached_item_relative_storage_time(T cached_item);
intmax_t Cached_item_age(T cached_item);

#undef T
#endif