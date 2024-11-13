#include "message.h"
#include <stdlib.h>
#include <unistd.h> 
#include <string.h>
#include <stdio.h>

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
/* TODO: may want to add support for sending partial messages immediately after reading */
int add_to_Message(Message *message, int sd) {
    if (message->bytes_read == message->buffer_size) {
        expand_buffer(message);
    }

    char *currIndex = message->buffer + message->bytes_read;
    if (message->header_read) {
        int bytes_to_read = message->total_length - message->bytes_read;
        ssize_t read_bytes = read(sd, currIndex, bytes_to_read);
        if (read_bytes <= 0) {
            return -1;
        }


        message->bytes_read += read_bytes;
        message->buffer[message->bytes_read] = '\0';
        if (message->bytes_read == message->total_length) {
            printf("message from socket %d is as follows:\n", sd);
            fwrite(message->buffer, 1, 20, stdout);
            printf("\n");
        }
        return (message->bytes_read == message->total_length) ? 0 : 1;
    } else {
        // read in until end of buffer
        ssize_t read_bytes = read(sd, currIndex, message->buffer_size - message->bytes_read - 1);

        message->bytes_read += read_bytes;
        message->buffer[message->bytes_read] = '\0';
        // check if header is fully read
        return check_message(message, sd);
    }
}

int check_message(Message *message, int sd) {
    char *endOfResponse = strstr(message->buffer, "\r\n\r\n");
    if (endOfResponse != NULL) {
        message->header_read = true;
        int headerSize = endOfResponse + 4 - message->buffer;
        message->total_length = headerSize;
        if (strstr(message->buffer, "GET") != NULL) {
            if (message->bytes_read >= message->total_length) {
                printf("message from socket %d is as follows:\n", sd);
                fwrite(message->buffer, 1, 20, stdout);
                printf("\n");
            }
            return 0;
        } 
        // find the content-length field
        char *contentLenIndex = strstr(message->buffer, "Content-Length: ");
        if (contentLenIndex == NULL) {
            if (message->bytes_read >= message->total_length) {
                printf("message from socket %d is as follows:\n", sd);
                fwrite(message->buffer, 1, 20, stdout);
                printf("\n");
            }
            return 0; // assume no content length field means no message body
        } else {
            contentLenIndex += strlen("Content-Length: ");
            int contentLength = atoi(contentLenIndex);
            message->total_length = contentLength + headerSize;
            if (message->buffer_size < message->total_length + 1) {
                char *new_buffer = (char *) malloc(message->total_length + 1);
                memcpy(new_buffer, message->buffer, message->buffer_size);
                free(message->buffer);
                message->buffer_size = message->total_length;
                message->buffer = new_buffer;
            }
            if (message->bytes_read >= message->total_length) {
                printf("message from socket %d is as follows:\n", sd);
                fwrite(message->buffer, 1, 20, stdout);
                printf("\n");
            }
            return (message->bytes_read >= message->total_length) ? 0 : 1;
        }
    }
    return 1; // still need to read header
}

void expand_buffer(Message *message) {
    char *new_buffer = (char *) malloc(2 * message->buffer_size);
    memcpy(new_buffer, message->buffer, message->buffer_size);
    free(message->buffer);
    message->buffer_size *= 2;
    message->buffer = new_buffer;
}

// 0 for ready to process next request
// 1 for next request is not ready yet
int update_Message(Message *message) {
    // if there is nothing left to process
    if (message->bytes_read == message->total_length) {
        free(message->buffer);
        message->buffer = NULL;
        create_Message(message);
        return 1;
    } else {
        int curr_length = message->bytes_read - message->total_length;
        int buffer_size = curr_length > INITIAL_BUFFER_SIZE ? curr_length : INITIAL_BUFFER_SIZE;
        char *new_buffer = (char *)malloc(buffer_size);
        printf("message->total_length: %d\n", message->total_length);
        printf("message->bytes read: %d\n", message->bytes_read);
        memcpy(new_buffer, message->buffer + message->total_length, curr_length);
        
        // update message fields
        free(message->buffer);
        message->buffer = new_buffer;
        message->buffer_size = buffer_size;
        message->bytes_read = curr_length;
        message->header_read = false;

        return check_message(message, 0);
    }
}