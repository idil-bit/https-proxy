#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#include <bool.h>

struct Message {
    char *buffer;
    int buffer_size;
    bool bytes_read;
    bool header_read;
    int total_length;
}

void create_Message(Message *msg);
void add_to_Message(Message *message, int sd);

#endif