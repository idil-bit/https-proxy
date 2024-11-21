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
//  3: nonfatal error
//  4: blocking waiting for write - proxy should add socket to write set
/* TODO: may want to add support for sending partial messages immediately after reading */
int add_to_Message(Message *message, int sd, ConnectionType *ct) {
    if (message->buffer == NULL) {
        create_Message(message);
    }
    if (!ct->isTunnel && ct->isHTTPs && ct->ssl == NULL) {
        /* proxy is reading from the client before it is setting up connection to server */
        /* solution: temporarily remove client from read set */
        printf("error https socket w/ null ssl on socket %d\n", sd);
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
            if (ct->ssl != NULL && SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_WRITE) {
                printf("read blocked waiting for write\n");
                return 4;
            }
            if (ct->ssl != NULL && (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_READ || 
                SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_WRITE ||
                errno == EINPROGRESS || errno == 0 || errno == 35 )) {
                return 3; /* don't want to treat it as a successful read like return 1 but also don't want to return -1 or 0 */
            }
            if (ct->isHTTPs) {
                if (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_ZERO_RETURN) {
                    // printf("TLS connection closed gracefully\n");
                    return -1;
                } 
                printf("ssl read failed on socket %d\n", sd);
                printf("read bytes: %d\n", (int) read_bytes);
                printf("SSL error code: %d\n", SSL_get_error(ct->ssl, read_bytes));
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
        /* return -1 to signify error reading */
        if (read_bytes <= 0) {
            if (ct->ssl != NULL && SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_WRITE) {
                printf("read blocked waiting for write\n");
                return 4;
            }
            if (ct->ssl != NULL && (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_READ || 
                SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_WANT_WRITE || 
                errno == EINPROGRESS || errno == 0 || errno == 35)) { /* error code of 35 means read would have blocket */
                return 3;
            }
            if (ct->isHTTPs) {
                if (SSL_get_error(ct->ssl, read_bytes) == SSL_ERROR_ZERO_RETURN) {
                    // printf("TLS connection closed gracefully\n");
                    return -1;
                }
                printf("ssl read failed on socket %d\n", sd);
                printf("SSL error code: %d\n", SSL_get_error(ct->ssl, read_bytes));
                printf("errno: %d\n", errno);
                int err;
                while ((err = ERR_get_error()) != 0) {
                    fprintf(stderr, "SSL error: %s\n", ERR_error_string(err, NULL));
                }
            }

            return -1;
        }
        message->bytes_read += read_bytes;
        if (message->bytes_read == message->buffer_size) {
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
        message->header_read = true;
        int headerSize = endOfResponse + 4 - message->buffer;
        message->total_length = headerSize;
        /* use memcmp to make sure GET or CONNECT is at start of message */
        if (memcmp(message->buffer, "GET", 3) == 0 || memcmp(message->buffer, "CONNECT", 7) == 0) {
            return 0;
        } 
        // find the content-length field
        char *contentLenIndex = strcasestr(message->buffer, "Content-Length: ");
        if (contentLenIndex == NULL) {
            if (strcasestr(message->buffer, "Transfer-Encoding: chunked")) {
                printf("chunked data incoming!\n");
            } else {
                printf("no content length or chunked transfer encoding\n");
            }
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
            if (contentLength > 5000000) {
                return 2; /* don't cache anything larger than 5 MB*/
            }
            message->total_length = contentLength + headerSize;
            if (message->buffer_size < message->total_length + 1) {
                char *new_buffer = (char *) malloc(message->total_length + 1);
                memcpy(new_buffer, message->buffer, message->buffer_size);
                free(message->buffer);
                message->buffer_size = message->total_length;
                message->buffer = new_buffer;
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
        int buffer_size = curr_length >= INITIAL_BUFFER_SIZE ? curr_length + 1 : INITIAL_BUFFER_SIZE;
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

        message->buffer[message->bytes_read] = '\0';

        return check_message(message, 0);
    }
}