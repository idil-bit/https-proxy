#define _GNU_SOURCE
#include "message.h"
#include <stdlib.h>
#include <unistd.h> 
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <openssl/err.h>

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
//  2: tunnel mode should be turned on for client and server
/* TODO: may want to add support for sending partial messages immediately after reading */
int add_to_Message(Message *message, int sd, ConnectionType *ct) {
    if (ct->isHTTPs) {
        // printf("ssl read on socket %d\n", sd);
    }
    char *currIndex = message->buffer + message->bytes_read;
    if (message->header_read) {
        int bytes_to_read = message->total_length - message->bytes_read;
        /* if ssl connection, use ssl read*/
        ssize_t read_bytes;
        if (ct->isHTTPs) {
            read_bytes = SSL_read(ct->ssl, currIndex, bytes_to_read);
        } else {
            read_bytes = read(sd, currIndex, bytes_to_read);
        }

        if (read_bytes <= 0) {
            if (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_READ) {
                return 1;
            }
            if (ct->isHTTPs) {
                printf("ssl read failed on socket %d\n", sd);
            }
            printf("read bytes: %d\n", (int) read_bytes);
            printf("SSL error code: %d\n", SSL_get_error(ct->ssl, read_bytes));
            if (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_ZERO_RETURN) {
                printf("TLS connection closed gracefully\n");
            } 
            // printf("errno: %d\n", errno);
            int err;
            while ((err = ERR_get_error()) != 0) {
                fprintf(stderr, "SSL error: %s\n", ERR_error_string(err, NULL));
            }
            return -1;
        }

        message->bytes_read += read_bytes;
        message->buffer[message->bytes_read] = '\0';
        if (message->bytes_read == message->total_length) {
            printf("message from socket %d is as follows:\n", sd);
            fwrite(message->buffer, 1, 20, stdout);
            printf("\n");
        }
        /* if in tunnel mode, will just send it blindly */
        if (ct->isTunnel) { return 2; }

        return (message->bytes_read == message->total_length) ? 0 : 1;
    } else {
        // read in until end of buffer
        ssize_t read_bytes;
        if (ct->isHTTPs) {
            read_bytes = SSL_read(ct->ssl, currIndex, message->buffer_size - message->bytes_read);
        } else {
            read_bytes = read(sd, currIndex, message->buffer_size - message->bytes_read);
        }
        printf("read bytes: %d\n", (int) read_bytes);
        /* return -1 to signify error reading */
        if (read_bytes <= 0) {
            if (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_READ) {
                return 1;
            }
            if (ct->isHTTPs) {
                printf("ssl read failed on socket %d\n", sd);
            }
            printf("SSL error code: %d\n", SSL_get_error(ct->ssl, read_bytes));
            if (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_ZERO_RETURN) {
                printf("TLS connection closed gracefully\n");
            }
            printf("errno: %d\n", errno);
            int err;
            while ((err = ERR_get_error()) != 0) {
                fprintf(stderr, "SSL error: %s\n", ERR_error_string(err, NULL));
            }

            return -1;
        }
        message->bytes_read += read_bytes;
        if (message->bytes_read == message->buffer_size) {
            printf("expanding buffer\n");
            expand_buffer(message);
        }
        message->buffer[message->bytes_read] = '\0';
        /* if in tunnel mode, will just send it blindly */
        if (ct->isTunnel) { return 2; }
        // check if header is fully read
        return check_message(message, sd);
    }
}

int check_message(Message *message, int sd) {
    char *endOfResponse = strstr(message->buffer, "\r\n\r\n");
    if (endOfResponse != NULL) {
        printf("header read\n");
        message->header_read = true;
        int headerSize = endOfResponse + 4 - message->buffer;
        message->total_length = headerSize;
        if (strstr(message->buffer, "GET") != NULL || strstr(message->buffer, "CONNECT") != NULL) {
            if (message->bytes_read >= message->total_length) {
                printf("message from socket %d is as follows:\n", sd);
                fwrite(message->buffer, 1, 20, stdout);
                printf("\n");
            }
            return 0;
        } 
        // find the content-length field
        char *contentLenIndex = strcasestr(message->buffer, "Content-Length: ");
        if (contentLenIndex == NULL) {
            if (strcasestr(message->buffer, "Transfer-Encoding: chunked")) {
                printf("chunked data incoming!\n");
            }
            printf("no content length or chunked transfer encoding ");
            fwrite(message->buffer, 1, 20, stdout);
            /* no content-length and no transfer-encoding means body length is determined 
                by bytes sent until server closes connection*/
            /* turn on tunnel mode */
            return 2;
        } else {            
            contentLenIndex += strlen("Content-Length:");
            while (*contentLenIndex == ' ' || *contentLenIndex == '\t') {
                contentLenIndex++;
            }
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
    char *new_buffer = malloc(2 * message->buffer_size);
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
    } else if (message->bytes_read < message->total_length) {
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