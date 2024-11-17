#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#include <stdbool.h>
#include <openssl/ssl.h>

struct Message {
    char *buffer;
    int buffer_size;
    int bytes_read;
    bool header_read;
    int total_length;
};
typedef struct Message Message;

struct ConnectionType {
    bool isHTTPs;
    bool isTunnel;
    SSL *ssl;
};
typedef struct ConnectionType ConnectionType;

void create_Message(Message *msg);
int add_to_Message(Message *message, int sd, ConnectionType *ct);
void expand_buffer(Message *message);
int check_message(Message *message, int sd);
int update_Message(Message *message);

#endif