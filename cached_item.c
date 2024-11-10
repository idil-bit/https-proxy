#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "cached_item.h"

#define T Cached_item

T Cached_item_new(char *key, char *value, int value_size, int relative_storage_time, int max_age, 
                  int retrieval_time) {
    T cached_item = malloc(sizeof(*cached_item));
    assert(cached_item != NULL);
    cached_item->key = key;
    cached_item->value = malloc(value_size);
    memcpy(cached_item->value, value, value_size);
    cached_item->initial_storage_time = (intmax_t) time(NULL);
    cached_item->relative_storage_time = relative_storage_time;
    cached_item->max_age = max_age;
    cached_item->retrieval_time = retrieval_time; 
    cached_item->value_size = value_size;
    return cached_item;
}

void Cached_item_free(T *cached_file) {
    assert(cached_file != NULL);
    assert(*cached_file != NULL);
    free((*cached_file)->key);
    free((*cached_file)->value);
    free(*cached_file);
}

intmax_t Cached_item_age(T cached_item) {
    return (intmax_t)time(NULL) - cached_item->initial_storage_time;
}

intmax_t Cached_item_expiration(T cached_item) {
    return cached_item->initial_storage_time + cached_item->max_age;
}


// returns age of file, or -1 if expired. sets *contents to NULL if expired
int Cached_file_retrieve(T cached_file, int curr_time, char **value, int *value_size) {
    intmax_t real_time = (intmax_t)time(NULL);
    int age = real_time - cached_file->initial_storage_time;
    if (age >= cached_file->max_age) {
        *value = NULL;
        return -1;
    }
    *value = cached_file->value;
    *value_size = cached_file->value_size;
    cached_file->retrieval_time = curr_time;
    return age;
}

char *Cached_item_key(T cached_file) {
    return cached_file->key;
}

int Cached_item_retrieval_time(T cached_file) {
    return cached_file->retrieval_time;
}

int Cached_item_relative_storage_time(T cached_file) {
    return cached_file->relative_storage_time;
}

#undef T