#include "message.h"

#define INITIAL_BUFFER_SIZE 1024

void create_Message(Message *message) {
    message->buffer = (char *) malloc(INITIAL_BUFFER_SIZE);
    message->buffer_size = INITIAL_BUFFER_SIZE;
    message->bytes_read = 0;
    message->header_read = false;
    message->total_length = 0;
}

// -1: errors in reading
//  0: success in reading
//  1: more to reading
int add_to_Message(Message *message, int sd) {
    if (message->bytes_read == buffer_size) {
        expand_buffer(message);
    }

    char *currIndex = message->buffer + message->bytes_read;
    if (message->header_read) {
        int bytes_to_read = message->total_length - message->bytes_read;
        ssize_t read_bytes = read(sd, currIndex, bytes_to_read);
        if (read_bytes < 0) {
            return -1;
        }

        message->bytes_read += read_bytes;
        return (message->bytes_read == message->total_length) ? 0 : 1;
    } else {
        // read in until end of buffer
        ssize_t read_bytes = read(sd, currIndex, message->buffer_size - message->bytes_read);
        if (read_bytes < 0) {
            return -1;
        }
        // check if header is fully read
        char *endOfResponse = strstr(message->buffer, "\r\n\r\n");
        if (endOfResponse != NULL) {
            message->header_read = true;
            int headerSize = endOfResponse + 4 - message->buffer;
            message->total_length = headerSize;
            if (strstr(message->buffer, "GET") != NULL) {
                return 0;
            } 
            // find the content-length field
            char *contentLenIndex = strstr(message->buffer, "Content-Length: ");
            if (contentLenIndex == NULL) {
                return 0;
            } else {
                contentLenIndex += strlen("Content-Length: ");
                int contentLength = atoi(contentLenIndex);
                message->total_length = contentLength + headerSize;
                if (message->buffer_size < message->total_length) {
                    char *new_buffer = (char *) malloc(message->total_length);
                    memcpy(new_buffer, message->buffer, message->buffer_size);
                    free(message->buffer);
                    message->buffer_size = message->total_length;
                    message->buffer = new_buffer;
                }
                return (message->bytes_read == message->total_length) ? 0 : 1;
            }
        }
    }
}

void expand_buffer(Message *message) {
    char *new_buffer = (char *) malloc(2 * message->buffer_size);
    memcpy(new_buffer, message->buffer, message->buffer_size);
    free(message->buffer);
    message->buffer_size *= 2;
    message->buffer = new_buffer;
}