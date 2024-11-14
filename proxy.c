#include "cache.h"
#include "proxy_helpers.h"
#include "message.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <errno.h>
#include <fcntl.h>

/* TODO: test with different cache sizes for optimization */
#define CACHE_SIZE 10
#define BUFFER_SIZE 1024

struct ConnectionType {
    bool isHTTPs;
    SSL *ssl;
};

typedef struct ConnectionType ConnectionType;

int proxySD;
Cache cache;
Message partialMessages[FD_SETSIZE];
char *identifiers[FD_SETSIZE]; // mapping of serverSD to cache identifiers
EVP_PKEY *publicKey;
EVP_PKEY *privateKey;

void signal_handler(int signal) {
    (void) signal;
    close(proxySD);
    Cache_free(&cache);
    for (int i = 0; i < FD_SETSIZE; i++) {
        if (partialMessages[i].buffer != NULL) {
            free(partialMessages[i].buffer);
            partialMessages[i].buffer = NULL;
        }
        if (identifiers[i] != NULL) {
            free(identifiers[i]);
            identifiers[i] = NULL;
        }
    }
    EVP_PKEY_free(publicKey);
    EVP_PKEY_free(privateKey);
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[])
{
    if (argc != 2) { return -1; }
    int portNumber = atoi(argv[1]);

    proxySD = socket(AF_INET, SOCK_STREAM, 0);
    if (proxySD == -1) { return -1; }

    printf("initializing proxy on socket %d\n", proxySD);

    struct sockaddr_in saddr, caddr;
    memset(&saddr, '\0', sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(portNumber);

    int optval = 1;
    setsockopt(proxySD, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));
    if (bind(proxySD, (struct sockaddr *) &saddr, sizeof(saddr)) == -1) { return -1; }
    if (listen(proxySD, 0) == -1) { return -1; }

    cache = Cache_new(CACHE_SIZE);

    ConnectionType connectionTypes[FD_SETSIZE];
    int clientToServer[FD_SETSIZE]; // for each clientSD, the serverSD they talk to
    int serverToClient[FD_SETSIZE]; // for each serverSD, the clientSD they talk to
    for (int i = 0; i < FD_SETSIZE; i++) {
        connectionTypes[i].isHTTPs = false;
        partialMessages[i].buffer = NULL;
        clientToServer[i] = -1;
        serverToClient[i] = -1;
    }
    
    fd_set clients_set, servers_set; // holds client and server sockets
    FD_ZERO(&clients_set);
    FD_ZERO(&servers_set);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN); // allows writing to a closed socket without crashing program

    fd_set read_fd_set, read_fd_set_copy, write_fd_set, write_fd_set_copy;
    FD_ZERO(&read_fd_set);
    FD_ZERO(&write_fd_set);
    FD_SET(proxySD, &read_fd_set);

    // init_openssl();

    int clientSD;
    int clen = sizeof(caddr);

    FILE *public_fp = fopen("public.pem", "r");
    FILE *private_fp = fopen("private.pem", "r");
    publicKey = PEM_read_PUBKEY(public_fp, NULL, NULL, NULL);
    privateKey = PEM_read_PrivateKey(private_fp, NULL, NULL, NULL);
    fclose(public_fp);
    fclose(private_fp);
    
    while (1) {
        read_fd_set_copy = read_fd_set;
        write_fd_set_copy = write_fd_set;
        /* checking for invalid file descriptors */
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &read_fd_set)) {
                if (fcntl(i, F_GETFD) == -1 && errno == EBADF) {
                    printf("Invalid file descriptor in read set: %d\n", i);
                }
            }
            if (FD_ISSET(i, &write_fd_set)) {
                if (fcntl(i, F_GETFD) == -1 && errno == EBADF) {
                    printf("Invalid file descriptor in write set: %d\n", i);
                }
            }
        }
        if (select (FD_SETSIZE, &read_fd_set_copy, &write_fd_set_copy, NULL, NULL) < 0) {	
                    perror("select");
                    exit (EXIT_FAILURE);
        }

        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &read_fd_set_copy)) {
                if (i == proxySD) {
                    // accept connection 
                    clientSD = accept(proxySD, (struct sockaddr *) &caddr, (unsigned int *) &clen);
                    if (clientSD == -1) {
                        continue;
                    }
                    FD_SET(clientSD, &read_fd_set);
                    FD_SET(clientSD, &clients_set);
                    printf("adding socket %d to client and read set\n", clientSD);
                    /* make sure there is no old client request */
                    if (partialMessages[clientSD].buffer != NULL) {
                        free(partialMessages[clientSD].buffer);
                        partialMessages[clientSD].buffer = NULL;
                    }
                    create_Message(&(partialMessages[clientSD]));
                } else if (FD_ISSET(i, &clients_set)) {
                    int read_result = add_to_Message(&(partialMessages[i]), i);
                    if (read_result == 0) {
                        if (strstr(partialMessages[i].buffer, "CONNECT") != NULL) {
                            /* for debugging http only */
                            close(i);
                            FD_CLR(i, &clients_set);
                            FD_CLR(i, &read_fd_set);
                            continue;

                            printf("connect received!: \n%s\n", partialMessages[i].buffer);
                            int serverSD = get_server_socket(partialMessages[i].buffer);
                            
                            /* add https server to socket we are expecting a write from */
                            FD_SET(serverSD, &write_fd_set);
                            FD_SET(serverSD, &servers_set);
                            clientToServer[i] = serverSD;
                            serverToClient[serverSD] = i;

                            connectionTypes[serverSD].isHTTPs = true;

                            /* add hostname to hostnames */
                            identifiers[serverSD] = get_identifier(partialMessages[i].buffer);
                        } else if (strstr(partialMessages[i].buffer, "GET") != NULL) {
                            // check if response is already cached
                            char *placeholder_host;
                            int placeholder_port;
                            (void) placeholder_host;
                            (void) placeholder_port;
                            char *identifier = get_identifier(partialMessages[i].buffer);
                            Cached_item cached_response = Cache_get(cache, identifier);
                            free(identifier);
                            if (cached_response != NULL) {		
                                printf("hit cache! max age = %d\n", cached_response->max_age);					
                                if (write(i, cached_response->value, cached_response->value_size) == -1) {
                                    // remove client
                                    printf("writing to client failed - removing socket %d from client and read set\n", i);
                                    close(i);
                                    printf("closing socket %d line 165\n", i);
                                    FD_CLR(i, &clients_set);
                                    FD_CLR(i, &read_fd_set);	
                                    free(partialMessages[i].buffer);
                                    partialMessages[i].buffer = NULL;
                                    clientToServer[i] = -1;
                                }
                            } else { /* invariant: partialMessages[i].buffer != NULL */
                                /* check if -1 and handle accordingly */
                                int serverSD = get_server_socket(partialMessages[i].buffer);
                                if (serverSD == -1) {
                                    close(i);
                                    free(partialMessages[i].buffer);
                                    partialMessages[i].buffer = NULL;
                                    FD_CLR(i, &clients_set);
                                    FD_CLR(i, &read_fd_set);
                                    continue;
                                }

                                identifiers[serverSD] = get_identifier(partialMessages[i].buffer);

                                // add to clientToServer and serverToClient
                                printf("adding server socket %d to server and write set\n", serverSD);
                                FD_SET(serverSD, &servers_set);
                                FD_SET(serverSD, &write_fd_set);
                                clientToServer[i] = serverSD;
                                serverToClient[serverSD] = i;
                            }
                        } else {
                            printf("unsupported request type\n");
                            close(i);
                            FD_CLR(i, &read_fd_set);
                            FD_CLR(i, &clients_set);
                        }
                        
                    } else if (read_result == -1) {
                        // remove client
                        close(i);
                        printf("closing socket %d line 189\n", i);
                        FD_CLR(i, &clients_set);
                        FD_CLR(i, &read_fd_set);
                        free(partialMessages[i].buffer);
                        partialMessages[i].buffer = NULL;
                        clientToServer[i] = -1;
                    }
                } else if (FD_ISSET(i, &servers_set)) {
                    clientSD = serverToClient[i];

                    // if corresponding client has closed the connection
                    if (clientToServer[clientSD] == -1) {
                        // close this connection and remove from sets
                        printf("corresponding client connection was closed - removing server socket %d from server, write, and read set\n", i);
                        close(i);
                        printf("closing socket %d line 204\n", i);
                        FD_CLR(i, &servers_set);
                        FD_CLR(i, &write_fd_set);
                        FD_CLR(i, &read_fd_set);
                        serverToClient[i] = -1;
                        free(partialMessages[i].buffer);
                        partialMessages[i].buffer = NULL;
                        continue;
                    }
                    
                    // read in response and immediately forward data to client
                    if (partialMessages[i].buffer == NULL) {
                        create_Message(&(partialMessages[i]));
                    }
                    int old_bytes_read = partialMessages[i].bytes_read;
                    int read_result = add_to_Message(&(partialMessages[i]), i);
                    // if response is fully read, then cache it and move up any extra data
                    if (read_result == -1) {
                        // close connection
                        close(i);
                        printf("closing socket %d line 223\n", i);
                        FD_CLR(i, &servers_set);
                        FD_CLR(i, &write_fd_set);
                        FD_CLR(i, &read_fd_set);
                        free(identifiers[i]); /* free server hostname */
                        identifiers[i] = NULL;
                        printf("read failed - cleared %d from server", i);
                        serverToClient[i] = -1;
                        free(partialMessages[i].buffer);
                        partialMessages[i].buffer = NULL;
                    } else {
                        // send chunk we just read in (from old bytes read to current bytes read)
                        if (write(clientSD, partialMessages[i].buffer + old_bytes_read, 
                                partialMessages[i].bytes_read - old_bytes_read) == -1) {
                            close(i);
                            printf("closing socket %d line 238\n", i);
                            FD_CLR(i, &servers_set);
                            FD_CLR(i, &read_fd_set);
                            FD_CLR(i, &write_fd_set);
                            serverToClient[i] = -1;
                            close(clientSD);
                            printf("closing socket %d line 243\n", clientSD);
                            FD_CLR(clientSD, &clients_set);
                            FD_CLR(clientSD, &read_fd_set);
                            clientToServer[clientSD] = -1;
                        }
                        if (read_result == 0) {
                            // cache only if entire response has been received
                            /* TODO: should we test for best max age value or is there a good default? */
                            /* there should only be one response in the buffer */
                            Cache_put(cache, 
                                      identifiers[i], 
                                      partialMessages[i].buffer, 
                                      partialMessages[i].total_length, 
                                      get_max_age(partialMessages[i].buffer));
                            if (partialMessages[i].bytes_read != partialMessages[i].total_length) {
                                printf("unexpected read of more than one response\n");
                                printf("partialMessages[i].bytes_read: %d, partialMessages[i].total_length: %d\n", partialMessages[i].bytes_read, partialMessages[i].total_length);
                            }

                            close(i);
                            FD_CLR(i, &servers_set);
                            FD_CLR(i, &read_fd_set);
                            FD_CLR(i, &write_fd_set);
                            clientToServer[clientSD] = -1;
                            serverToClient[i] = -1;
                            free(identifiers[i]);
                            identifiers[i] = NULL;
                            
                            if (update_Message(&(partialMessages[clientSD])) == 0) {
                                int serverSD = get_server_socket(partialMessages[clientSD].buffer);

                                // add to clientToServer and serverToClient
                                FD_SET(serverSD, &servers_set);
                                FD_SET(serverSD, &write_fd_set);
                                printf("socket %d added to servers\n", serverSD);
                                clientToServer[clientSD] = serverSD;
                                serverToClient[serverSD] = clientSD;
                            }
                        }
                    }
                } else {
                    // don't expect code to ever reach here
                    printf("TODO: unexpected socket %d open\n", i);
                }
            }
            if (FD_ISSET(i, &write_fd_set_copy)) {
                clientSD = serverToClient[i];

                /* connect was successful - don't need to check if socket is open for writing anymore */
                FD_CLR(i, &write_fd_set);
                FD_SET(i, &read_fd_set);
                printf("connection to socket %d was successful - added to read and cleared from write\n", i);

                /* make sure there is no old server response */
                if (partialMessages[i].buffer != NULL) {
                    free(partialMessages[i].buffer);
                    partialMessages[i].buffer = NULL;
                }

                /* if i is an ssl connection: send back 200 ok to client */
                if (connectionTypes[i].isHTTPs) {

                    /* send back 200 ok */
                    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    if (write(clientSD, response, strlen(response)) == -1) {
                        close(clientSD);
                        /* TODO: remove client from all DSs */
                        connectionTypes[clientSD].isHTTPs = false;
                        connectionTypes[i].isHTTPs = false;
                        /* clear client and server from fd sets */
                        close(clientSD);
                        printf("closing socket %d line 292\n", clientSD);
                        FD_CLR(clientSD, &read_fd_set);
                        FD_CLR(clientSD, &clients_set);
                        close(i);
                        printf("closing socket %d line 296\n", i);
                        FD_CLR(i, &servers_set);
                        FD_CLR(i, &read_fd_set);
                        FD_CLR(i, &write_fd_set);
                        continue;
                    }
                    /* TODO: initiate ssl handshake w/ server and accept ssl handshake from client */

                    /* create ssl object for server */
                    SSL_CTX *ctx_server = create_context();
                    configure_context_server(ctx_server, identifiers[i]); 
                    SSL *ssl_server;
                    ssl_server = SSL_new(ctx_server);
                    connectionTypes[i].ssl = ssl_server;

                    /* create ssl object for client */
                    SSL_CTX *ctx_client = create_context();
                    configure_context_client(ctx_client, publicKey, privateKey, identifiers[i]); 
                    SSL *ssl_client;
                    ssl_client = SSL_new(ctx_client);
                    connectionTypes[clientSD].ssl = ssl_client;

                    X509 *domain_specific_certificate = generate_x509(publicKey, privateKey, identifiers[i]);

                } else {
                    printf("writing message of length %d to server\n", partialMessages[clientSD].total_length);
                    if (write(i, partialMessages[clientSD].buffer, partialMessages[clientSD].total_length) == -1) { 
                        close(i); 
                        printf("closing socket %d line 325\n", i);
                        FD_CLR(i, &read_fd_set);
                        FD_CLR(i, &servers_set);
                    }
                }

            }
        }
    }

    if (close(proxySD) == -1) { return -1; }
    return 0;
}