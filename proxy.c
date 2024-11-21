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
#include <openssl/err.h>
#include <errno.h>
#include <fcntl.h>

/* TODO: test with different cache sizes for optimization */
#define CACHE_SIZE 10
#define BUFFER_SIZE 100000

int proxySD;
Cache cache;
Message partialMessages[FD_SETSIZE];
char *identifiers[FD_SETSIZE]; // mapping of serverSD to cache identifiers
EVP_PKEY *publicKey;
EVP_PKEY *privateKey;
fd_set clients_set, servers_set; // holds client and server sockets
fd_set ssl_handshakes; // holds sockets in the middle of ssl handshakes
fd_set read_fd_set, read_fd_set_copy, write_fd_set, write_fd_set_copy;
int clientToServer[FD_SETSIZE]; // for each clientSD, the serverSD they talk to
int serverToClient[FD_SETSIZE]; // for each serverSD, the clientSD they talk to
ConnectionType connectionTypes[FD_SETSIZE];

void close_client(int clientSD) {
    printf("closing client %d\n", clientSD);
    if (clientSD == -1) {
        return;
    }
    if (connectionTypes[clientSD].ssl != NULL) {
        SSL_shutdown(connectionTypes[clientSD].ssl);
        SSL_free(connectionTypes[clientSD].ssl);
        connectionTypes[clientSD].ssl = NULL;
    }
    connectionTypes[clientSD].isHTTPs = false;
    connectionTypes[clientSD].isTunnel = false;
    close(clientSD);
    FD_CLR(clientSD, &read_fd_set);
    FD_CLR(clientSD, &read_fd_set_copy);
    FD_CLR(clientSD, &clients_set);
    FD_CLR(clientSD, &ssl_handshakes);
    FD_CLR(clientSD, &write_fd_set);
    FD_CLR(clientSD, &write_fd_set_copy);
    clientToServer[clientSD] = -1;
}

void close_server(int serverSD) {
    printf("closing server %d\n", serverSD);
    if (serverSD == -1) {
        return;
    }
    if (connectionTypes[serverSD].ssl != NULL) {
        SSL_shutdown(connectionTypes[serverSD].ssl);
        SSL_free(connectionTypes[serverSD].ssl);
        connectionTypes[serverSD].ssl = NULL;
    }
    connectionTypes[serverSD].isHTTPs = false;
    connectionTypes[serverSD].isTunnel = false;
    close(serverSD);
    FD_CLR(serverSD, &read_fd_set);
    FD_CLR(serverSD, &read_fd_set_copy);
    FD_CLR(serverSD, &clients_set);
    FD_CLR(serverSD, &ssl_handshakes);
    FD_CLR(serverSD, &write_fd_set);
    FD_CLR(serverSD, &write_fd_set_copy);
    serverToClient[serverSD] = -1;
}

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

/* TODO: if read fails due to needing a write, add it to write set. Check write set first - if it needs a read then  just add to write_fd_set_copy */
int main(int argc, char* argv[])
{
    if ((argc != 3) && (argc != 2)) { return -1; }
    int portNumber = atoi(argv[1]);
    int tunnelMode = 0;
    int printMode = 0;
    if (argc == 3) {
        if (strstr(argv[2], "tunnel") != NULL) {
            tunnelMode = 1;
        } else if (strstr(argv[2], "print") != NULL) {
            printMode = 1;
        }
    }
    if (tunnelMode)
        printf("proxy was initiated in tunnel mode\n");
    if (printMode)
        printf("proxy was initiated in print mode\n");
    // tunnelMode will be on for other messages that:
        // are sent in chunked transfer encoding
        // for requests other than GET & CONNECT
        // for GET messages that don't have a content length

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
    for (int i = 0; i < FD_SETSIZE; i++) {
        connectionTypes[i].isHTTPs = false;
        connectionTypes[i].isTunnel = false;
        connectionTypes[i].ssl = NULL;
        partialMessages[i].buffer = NULL;
        clientToServer[i] = -1;
        serverToClient[i] = -1;
    }
    
    
    FD_ZERO(&clients_set);
    FD_ZERO(&servers_set);

    FD_ZERO(&ssl_handshakes);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN); // allows writing to a closed socket without crashing program

    FD_ZERO(&read_fd_set);
    FD_ZERO(&write_fd_set);
    FD_SET(proxySD, &read_fd_set);

    int fdMax = proxySD + 1;

    // init_openssl();

    int clientSD;
    int serverSD;
    int clen = sizeof(caddr);

    FILE *public_fp = fopen("public.pem", "r");
    FILE *private_fp = fopen("key.pem", "r");
    publicKey = PEM_read_PUBKEY(public_fp, NULL, NULL, NULL);
    privateKey = PEM_read_PrivateKey(private_fp, NULL, NULL, NULL);
    fclose(public_fp);
    fclose(private_fp);

    char buffer[BUFFER_SIZE];

    while (1) {
        read_fd_set_copy = read_fd_set;
        write_fd_set_copy = write_fd_set;
        if (select (fdMax, &read_fd_set_copy, &write_fd_set_copy, NULL, NULL) < 0) {	
                    perror("select");
                    exit (EXIT_FAILURE);
        }

        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &write_fd_set_copy)) {
                if (FD_ISSET(i, &ssl_handshakes)) {
                    /* can handle it same as in read set */
                    FD_SET(i, &read_fd_set_copy);
                    FD_CLR(i, &write_fd_set);
                } else if (FD_ISSET(i, &read_fd_set)) { /* waiting for ssl read */
                    FD_SET(i, &read_fd_set_copy);
                    FD_CLR(i, &write_fd_set);
                }
                else {
                    clientSD = serverToClient[i];

                    /* connect was successful - don't need to check if socket is open for writing anymore */
                    FD_CLR(i, &write_fd_set);
                    FD_SET(i, &read_fd_set);
                    FD_SET(clientSD, &read_fd_set);

                    printf("successful connection to server socket %d for client %d\n", i, clientSD);
                    
                    /* make sure there is no old server response */
                    if (partialMessages[i].buffer != NULL) {
                        free(partialMessages[i].buffer);
                        partialMessages[i].buffer = NULL;
                    }

                    /* if i is an ssl connection: send back 200 ok to client */
                    if (connectionTypes[i].isHTTPs) {
                        printf("successful https connection to server socket %d for client %d\n", i, clientSD);
                        /* send back 200 ok */
                        update_Message(&partialMessages[clientSD]);
                        const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
                        if (write(clientSD, response, strlen(response)) <= 0) {
                            printf("writing connection established message to client failed\n");
                            close_client(clientSD);
                            close_server(i);
                            continue;
                        }
                        
                        if (connectionTypes[i].isTunnel) {
                            printf("server %d and client %d are tunnels\n", i, clientSD);
                            continue;
                        }
                        /* create ssl object for server */
                        SSL_CTX *ctx_server = create_context(TLS_method()); // proxy is acting as client
                        if (ctx_server == NULL) {
                            printf("creating server context failed\n");
                        }
                        configure_context_server(ctx_server, privateKey, identifiers[i]); 
                        SSL *ssl_server;
                        ssl_server = SSL_new(ctx_server);
                        if (ssl_server == NULL) {
                            printf("creating server ssl failed\n");
                        }

                        SSL_CTX_free(ctx_server);

                        /* set ssl server name */
                        char *port_ptr = identifiers[i];
                        while(*port_ptr != ':') {
                            port_ptr++;
                        }
                        *port_ptr = '\0'; // null terminate host
                        SSL_set_tlsext_host_name(ssl_server, identifiers[i]);

                        /* restore host w/ port */
                        *port_ptr = ':';
                        SSL_set_fd(ssl_server, i);
                        connectionTypes[i].ssl = ssl_server;
                        SSL_set_connect_state(ssl_server);

                        int ssl_connect_res = SSL_connect(ssl_server);
                        if (ssl_connect_res != 1) {
                            if (SSL_get_error(ssl_server, ssl_connect_res) == SSL_ERROR_WANT_WRITE) {
                                FD_SET(i, &ssl_handshakes);
                                FD_SET(i, &write_fd_set);
                            }
                            if (SSL_get_error(ssl_server, ssl_connect_res) == SSL_ERROR_WANT_READ) {
                                /* ssl handshake needs to wait for server to send more data */
                                FD_SET(i, &ssl_handshakes);
                            } else {
                                printf("ssl connect to server failed on socket %d\n", i);
                                ERR_print_errors_fp(stderr);
                                /* TODO: should we make fd sets global and then we could just make a function to remove a client/server? */
                                close_server(i);
                                close_client(clientSD);
                                continue;
                            } 
                        } else {
                            printf("successful ssl connect to server on socket %d\n", i);
                        }

                        /* create ssl object for client */
                        SSL_CTX *ctx_client = create_context(TLS_method()); // proxy is acting as server
                        configure_context_client(ctx_client, publicKey, privateKey, identifiers[i]); 
                        SSL *ssl_client;
                        ssl_client = SSL_new(ctx_client);
                        if (ssl_client == NULL) {
                            printf("creating ssl client failed\n");
                        }
                        SSL_CTX_free(ctx_client);
                        SSL_set_fd(ssl_client, clientSD);
                        connectionTypes[clientSD].ssl = ssl_client;
                        SSL_set_accept_state(ssl_client);

                        int ssl_accept_res = SSL_accept(ssl_client);
                        if (ssl_accept_res != 1) {
                            if (SSL_get_error(ssl_client, ssl_accept_res) == SSL_ERROR_WANT_WRITE) {
                                FD_SET(clientSD, &ssl_handshakes);
                                FD_SET(clientSD, &write_fd_set);
                            }
                            else if (SSL_get_error(ssl_client, ssl_accept_res) == SSL_ERROR_WANT_READ || errno == EWOULDBLOCK) {
                                /* ssl handshake needs to wait for client to send more data */
                                FD_SET(clientSD, &ssl_handshakes);
                            } else {
                                printf("ssl accept failed\n");
                                printf("SSL error code: %d\n", SSL_get_error(ssl_client, ssl_accept_res));
                                printf("errno: %d\n", errno);
                                if (SSL_get_error(ssl_client, ssl_accept_res) == SSL_ERROR_ZERO_RETURN) {
                                    printf("TLS connection closed gracefully\n");
                                } 
                                int err;
                                while ((err = ERR_get_error()) != 0) {
                                    fprintf(stderr, "SSL error: %s\n", ERR_error_string(err, NULL));
                                }
                                close_server(i);
                                close_client(clientSD);
                                continue;
                            }
                        
                        } else {
                            printf("successful ssl accept from client on socket %d\n", i);
                        }

                    } else {
                        connectionTypes[clientSD].isHTTPs = false;
                        if (write(i, partialMessages[clientSD].buffer, partialMessages[clientSD].total_length) == -1) { 
                            printf("writing message to server failed\n");
                            close_server(i);
                            close_client(clientSD);
                        }
                    }
                }

            }
            if (FD_ISSET(i, &read_fd_set_copy)) {
                if (i == proxySD) {
                    // accept connection 
                    clientSD = accept(proxySD, (struct sockaddr *) &caddr, (unsigned int *) &clen);
                    if (clientSD == -1) {
                        continue;
                    }

                    int flags = fcntl(clientSD, F_GETFL, 0);
                    flags = flags | O_NONBLOCK;
                    if (fcntl(clientSD, F_SETFL, flags) < 0) {
                        perror("fcntl(F_SETFL)");
                    }
                    fdMax = fdMax > clientSD ? fdMax : clientSD + 1;

                    FD_SET(clientSD, &read_fd_set);
                    FD_SET(clientSD, &clients_set);
                    // printf("adding socket %d to client and read set\n", clientSD);
                    /* make sure there is no old client request */
                    if (partialMessages[clientSD].buffer != NULL) {
                        free(partialMessages[clientSD].buffer);
                        partialMessages[clientSD].buffer = NULL;
                    }
                    create_Message(&(partialMessages[clientSD]));

                    /* not yet an https connection as we have not received a CONNECT message */
                    connectionTypes[clientSD].isHTTPs = false;
                    connectionTypes[clientSD].isTunnel = false;
                    if (connectionTypes[clientSD].ssl != NULL) {
                        SSL_free(connectionTypes[clientSD].ssl);
                        connectionTypes[clientSD].ssl = NULL;
                    }
                } else if (FD_ISSET(i, &clients_set)) {
                    if (FD_ISSET(i, &ssl_handshakes)) {
                        int ssl_accept_res = SSL_accept(connectionTypes[i].ssl);
                        if (ssl_accept_res != 1) {
                            if (SSL_get_error(connectionTypes[i].ssl, ssl_accept_res) == SSL_ERROR_WANT_WRITE) {
                                FD_SET(i, &write_fd_set);
                            }
                            else if (SSL_get_error(connectionTypes[i].ssl, ssl_accept_res) != SSL_ERROR_WANT_READ && errno != EWOULDBLOCK) {
                                printf("ssl accept failed\n");
                                printf("SSL error code: %d\n", SSL_get_error(connectionTypes[i].ssl, ssl_accept_res));
                                printf("errno: %d\n", errno);
                                close_server(clientToServer[i]);
                                close_client(i);
                            }
                        } else {
                            /* if result was 1, socket is now ready for reading messages */
                            printf("successful ssl accept from client on socket %d\n", i);
                            FD_CLR(i, &ssl_handshakes);
                        }
                        continue;
                    }
                    if (connectionTypes[i].isTunnel) {
                        serverSD = clientToServer[i];
                        int bytes_read;
                        int bytes_written;
                        int bytes_to_read = BUFFER_SIZE;
                        if ((connectionTypes[i].isHTTPs) && !tunnelMode) {
                            do {
                                if (bytes_to_read > BUFFER_SIZE) {
                                    bytes_to_read = BUFFER_SIZE;
                                }
                                bytes_read = SSL_read(connectionTypes[i].ssl, buffer, bytes_to_read);
                                // immediately tunnel data to server
                                if (bytes_read > 0) 
                                    bytes_written = SSL_write(connectionTypes[serverSD].ssl, buffer, bytes_read);
                            } while (bytes_written > 0 && bytes_read > 0 && 
                                        (bytes_to_read = SSL_pending(connectionTypes[i].ssl)) > 0);
                            if (bytes_written <= 0 ||
                                (bytes_read <= 0 && SSL_get_error(connectionTypes[i].ssl, bytes_read) != SSL_ERROR_WANT_READ &&
                                    errno != EWOULDBLOCK)) {
                                /* close client socket and close server socket */
                                close_server(serverSD);
                                close_client(i);
                            }
                        } else {
                            /* read into buffer and send immediately */
                            bytes_read = read(i, buffer, BUFFER_SIZE);
                            // immediately tunnel data to server
                            if (bytes_read > 0) 
                                write(serverSD, buffer, bytes_read);
                            else {
                                close_server(serverSD);
                                close_client(i);
                            }
                        }
                        continue;
                    }

                    int read_result = add_to_Message(&(partialMessages[i]), i, &(connectionTypes[i]));
                    /* check for pending data in underlying ssl object */
                    if (read_result == 1 && connectionTypes[i].isHTTPs) {
                        while (SSL_pending(connectionTypes[i].ssl)) {
                            printf("found pending\n");
                            read_result = add_to_Message(&(partialMessages[i]), i, &(connectionTypes[i]));
                            if (read_result != 1) {
                                break;
                            }
                        }
                    }
                    if (read_result == 4) {
                        FD_SET(i, &write_fd_set);
                        continue;
                    }
                    if (read_result == 0) {
                        if (strstr(partialMessages[i].buffer, "CONNECT") != NULL) {
                            printf("connect received from socket %d!: \n%s\n", i, partialMessages[i].buffer);
                            int serverSD = get_server_socket(partialMessages[i].buffer);
                            if (serverSD == -1) {
                                close_client(i);
                                continue;
                            }
                            fdMax = fdMax > serverSD ? fdMax : serverSD + 1;

                            if (tunnelMode) {
                                printf("setting tunnel mode on for client socket %d and server socket %d\n", i, serverSD);
                                connectionTypes[i].isTunnel = true;
                                connectionTypes[serverSD].isTunnel = true;
                            } else {
                                connectionTypes[i].isTunnel = false;
                                connectionTypes[serverSD].isTunnel = false;
                            }
                            
                            /* add https server to socket we are expecting a write from */
                            FD_SET(serverSD, &write_fd_set);
                            FD_SET(serverSD, &servers_set);

                            /* clear client while we wait for server to connect */
                            FD_CLR(i, &read_fd_set);
                            FD_CLR(i, &write_fd_set);
                            clientToServer[i] = serverSD;
                            serverToClient[serverSD] = i;
                            printf("serverToClient[%d]=%d\n", serverSD, i);

                            connectionTypes[i].isHTTPs = true;
                            connectionTypes[serverSD].isHTTPs = true;

                            /* no ssl connection yet */
                            if (connectionTypes[serverSD].ssl != NULL) {
                                SSL_free(connectionTypes[serverSD].ssl);
                                connectionTypes[serverSD].ssl = NULL;
                            }

                            if (identifiers[serverSD] != NULL) {
                                free(identifiers[serverSD]);
                                identifiers[serverSD] = NULL;
                            }
                            identifiers[serverSD] = get_host(partialMessages[i].buffer);    
                            continue;

                        } else if (strstr(partialMessages[i].buffer, "GET") != NULL) {
                            // check if response is already cached
                            char *identifier = get_identifier(partialMessages[i].buffer);
                            Cached_item cached_response = Cache_get(cache, identifier);
                            /* for debugging: avoid serving from cache */
                            cached_response = NULL;
                            free(identifier);
                            if (cached_response != NULL) {		
                                // printf("hit cache! max age = %d\n", cached_response->max_age);		
                                /* TODO: need to add age field to response */	
                                int write_result;
                                if (connectionTypes[i].isHTTPs) {
                                    /* TODO: SSL write may fail with large values - maybe check if we should break this up into smaller chunks*/
                                    write_result = SSL_write(connectionTypes[i].ssl, cached_response->value, cached_response->value_size);
                                    if (printMode) {
                                        fwrite(cached_response->value, 1, cached_response->value_size, stdout);
                                    }
                                } else {
                                    write_result = write(i, cached_response->value, cached_response->value_size);
                                }
                                if (write_result == -1) {
                                    // remove client
                                    printf("writing to client failed - removing socket %d from client and read set\n", i);
                                    if (SSL_get_error(connectionTypes[i].ssl, write_result) == SSL_ERROR_WANT_WRITE || errno == 35) {
                                        printf("write blocked\n");
                                        struct timeval *timeout;
                                        timeout = malloc(sizeof(*timeout));
                                        timeout->tv_sec = 0;
                                        timeout->tv_usec = 500000;

                                        fd_set solo_fd_set;
                                        FD_ZERO(&solo_fd_set);
                                        FD_SET(i, &solo_fd_set);
                                        
                                        if (select (i + 1, NULL, &solo_fd_set, NULL, timeout) < 0)
                                        {
                                            perror ("select");
                                            exit (EXIT_FAILURE);
                                        }
                                        if (FD_ISSET(i, &solo_fd_set)) {
                                            if (SSL_write(connectionTypes[i].ssl, cached_response->value, cached_response->value_size) < 0) {
                                                printf("write failed again\n");
                                                close_client(i);
                                                continue;
                                            }
                                        } else {
                                            printf("write still blocking");
                                            close_client(i);
                                            continue;
                                        }
                                    } else {
                                        close_client(i);
                                    }

                                }
                            } else if (connectionTypes[i].isHTTPs) {
                                // printf("read GET message from https client\n");
                                /* ssl connection to server is already established */
                                int serverSD = clientToServer[i];
                                /* TODO: check if serverSD = -1*/
                                if (!FD_ISSET(serverSD, &ssl_handshakes)) {
                                    // printf("sending request to server at socket %d\n", serverSD);
                                }
                                if (!FD_ISSET(serverSD, &ssl_handshakes) && 
                                    SSL_write(connectionTypes[serverSD].ssl, partialMessages[i].buffer, partialMessages[i].total_length) <= 0) {
                                    /* we have to wait for the ssl handshake w/ the server to complete before sending the request */
                                    printf("ssl write of GET message to server failed line 247\n");
                                    /* error occured - close client and server sockets */
                                    close_server(serverSD);
                                    close_client(i);
                                    continue;
                                }
                                
                            } else { /* invariant: partialMessages[i].buffer != NULL */
                                /* check if -1 and handle accordingly */
                                serverSD = get_server_socket(partialMessages[i].buffer);
                                if (serverSD == -1) {
                                    close_client(i);
                                    continue;
                                }
                                fdMax = fdMax > serverSD ? fdMax : serverSD + 1;

                                if (identifiers[serverSD] != NULL) {
                                    free(identifiers[serverSD]);
                                    identifiers[serverSD] = NULL;
                                }
                                identifiers[serverSD] = get_identifier(partialMessages[i].buffer);

                                /* update data structures */
                                FD_SET(serverSD, &servers_set);
                                FD_SET(serverSD, &write_fd_set);
                                FD_CLR(i, &read_fd_set);
                                clientToServer[i] = serverSD;
                                serverToClient[serverSD] = i;
                                connectionTypes[serverSD].isHTTPs = false;
                                connectionTypes[serverSD].isTunnel = false;

                                if (connectionTypes[serverSD].ssl != NULL) {
                                    SSL_free(connectionTypes[serverSD].ssl);
                                    connectionTypes[serverSD].ssl = NULL;
                                }
                            }
                        } else {
                            /* TODO: would it make sense to just forward the message here but not cache the result? */
                            if (connectionTypes[i].isHTTPs) {
                                serverSD = clientToServer[i];
                                if (!FD_ISSET(serverSD, &ssl_handshakes) &&
                                    SSL_write(connectionTypes[serverSD].ssl, partialMessages[i].buffer, partialMessages[i].total_length) <= 0) {
                                    /* close client and server connections */
                                    close_client(i);
                                    close_server(serverSD);
                                    continue;
                                }
                            }
                            
                        }
                        
                    } else if (read_result == -1) {
                        // remove client and corresponding server 
                        close_server(clientToServer[i]);
                        close_client(i); 
                        continue;      
                    } else if (read_result == 2) {
                        connectionTypes[i].isTunnel = true;
                        
                        /* tunnel request to server */
                        if (connectionTypes[i].isHTTPs) {
                            /* we don't know if the ssl handshake has been completed yet */
                            serverSD = clientToServer[i];
                            connectionTypes[serverSD].isTunnel = true;
                            if (!FD_ISSET(serverSD, &ssl_handshakes) &&
                                SSL_write(connectionTypes[serverSD].ssl, partialMessages[i].buffer, partialMessages[i].bytes_read) <= 0) {
                                /* close client and server connections */
                                close_client(i);
                                close_server(serverSD);
                                continue;
                            }
                        } else {
                            /* wait for server to expect writes for http req */
                            serverSD = get_server_socket(partialMessages[i].buffer);
                            if (serverSD == -1) {
                                close_client(i);
                                continue;
                            }
                            connectionTypes[serverSD].isTunnel = true;
                            connectionTypes[serverSD].isHTTPs = false;
                            fdMax = fdMax > serverSD ? fdMax : serverSD + 1;

                            /* update data structures */
                            FD_SET(serverSD, &servers_set);
                            FD_SET(serverSD, &write_fd_set);
                            FD_CLR(i, &read_fd_set);
                            clientToServer[i] = serverSD;
                            serverToClient[serverSD] = i;

                            if (connectionTypes[serverSD].ssl != NULL) {
                                SSL_free(connectionTypes[serverSD].ssl);
                                connectionTypes[serverSD].ssl = NULL;
                            }
                            
                        }
                    }
                } else if (FD_ISSET(i, &servers_set)) {
                    if (FD_ISSET(i, &ssl_handshakes)) {
                        int ssl_connect_res = SSL_connect(connectionTypes[i].ssl);
                        if (ssl_connect_res != 1) {
                            if (SSL_get_error(connectionTypes[i].ssl, ssl_connect_res) == SSL_ERROR_WANT_WRITE) {
                                FD_SET(i, &write_fd_set);
                                continue;
                            }
                            else if (SSL_get_error(connectionTypes[i].ssl, ssl_connect_res) != SSL_ERROR_WANT_READ && errno != EWOULDBLOCK) {
                                printf("ssl connect failed on socket %d\n", i);
                                close_server(i);
                                close_client(clientSD);
                                continue;
                            } else {
                                continue;
                            }
                        } else {
                            /* if result was 1, socket is now ready for reading messages */
                            FD_CLR(i, &ssl_handshakes);
                            /* check if there is a message from the client that is ready to be sent */
                            clientSD = serverToClient[i];
                            int write_result = 1;
                            if (partialMessages[clientSD].total_length > 0 &&
                                partialMessages[clientSD].bytes_read >= partialMessages[clientSD].total_length) {
                                write_result = SSL_write(connectionTypes[i].ssl, partialMessages[clientSD].buffer, partialMessages[clientSD].total_length);
                            } else if (connectionTypes[clientSD].isTunnel && partialMessages[clientSD].bytes_read > 0) {
                                write_result = SSL_write(connectionTypes[i].ssl, partialMessages[clientSD].buffer, partialMessages[clientSD].bytes_read);
                            }
                            if (write_result <= 0) {
                                /* close client and server connections */
                                close_client(clientSD);
                                close_server(i);
                                continue;
                            }
                        }
                        continue;
                    } 
                    
                    clientSD = serverToClient[i];

                    // if corresponding client has closed the connection
                    if (clientToServer[clientSD] == -1) {
                        // close this connection and remove from sets
                        close_client(clientSD);
                        close_server(i);
                        continue;
                    }

                    if (connectionTypes[i].isTunnel) {
                        clientSD = serverToClient[i];
                        int bytes_read;
                        int bytes_written;
                        if ((connectionTypes[i].isHTTPs) && !tunnelMode) {
                            do {
                                bytes_read = SSL_read(connectionTypes[i].ssl, buffer, BUFFER_SIZE);
                                // immediately tunnel data to client
                                if (bytes_read > 0) {
                                    bytes_written = SSL_write(connectionTypes[clientSD].ssl, buffer, bytes_read);
                                    if (printMode) 
                                        fwrite(buffer, 1, bytes_read, stdout);
                                    if (bytes_written <= 0) {
                                        printf("error writing to client\n");
                                    }
                                }
                            } while (bytes_written > 0 && bytes_read > 0 && SSL_pending(connectionTypes[i].ssl) > 0);
                            /* if bytes read is less than 0, check to see if error code is not ssl_want_read */
                            if (bytes_written <= 0 ||
                                (bytes_read <= 0 && SSL_get_error(connectionTypes[i].ssl, bytes_read) != SSL_ERROR_WANT_READ && errno != EWOULDBLOCK)) {
                                /* close client socket and close server socket */
                                close_server(i);
                                close_client(clientSD);
                            }
                        } else {
                            /* read into buffer and send immediately */
                            bytes_read = read(i, buffer, BUFFER_SIZE);
                            // immediately tunnel data to server
                            if (bytes_read > 0) {
                                write(clientSD, buffer, bytes_read);
                            } else {
                                close_server(i);
                                close_client(clientSD);
                            }
                        }
                        
                        continue;
                    }
                    
                    // read in response and immediately forward data to client
                    if (partialMessages[i].buffer == NULL) {
                        create_Message(&(partialMessages[i]));
                    }
                    int old_bytes_read = partialMessages[i].bytes_read;
                    int read_result = add_to_Message(&(partialMessages[i]), i, &(connectionTypes[i]));

                    /* check for pending data in underlying ssl struct */
                    if (read_result == 1 && connectionTypes[i].isHTTPs) {
                        while (SSL_pending(connectionTypes[i].ssl)) {
                            read_result = add_to_Message(&(partialMessages[i]), i, &(connectionTypes[i]));
                            if (read_result != 1) {
                                break;
                            }
                        }
                    }
                    if (read_result == 4) {
                        FD_SET(i, &write_fd_set);
                    }
                    // if response is fully read, then cache it and move up any extra data
                    if (read_result == -1) { /* error reading response */
                        // close connection
                        close_server(i);
                        close_client(clientSD);
                        continue;
                    } else if (partialMessages[i].bytes_read != old_bytes_read) {
                        // send chunk we just read in (from old bytes read to current bytes read)
                        int write_result;
                        if (connectionTypes[i].isHTTPs) {
                            write_result = SSL_write(connectionTypes[clientSD].ssl, partialMessages[i].buffer + old_bytes_read, 
                                partialMessages[i].bytes_read - old_bytes_read);
                            if (printMode)
                                fwrite(partialMessages[i].buffer + old_bytes_read, 1, partialMessages[i].bytes_read - old_bytes_read, stdout);
                        } else {
                            write_result = write(clientSD, partialMessages[i].buffer + old_bytes_read, 
                                partialMessages[i].bytes_read - old_bytes_read);
                        }
                        if (write_result <= 0) {
                            printf("writing to client failed with errno %d\n", errno);
                            if (SSL_get_error(connectionTypes[clientSD].ssl, write_result) == SSL_ERROR_WANT_WRITE || errno == 35) {
                                printf("write blocked\n");
                                /* make fd set containing only the client and use select w/ timeout val of 500ms to wait for it to write */
                                struct timeval *timeout;
                                timeout = malloc(sizeof(*timeout));
                                timeout->tv_sec = 0;
                                timeout->tv_usec = 500000;

                                fd_set solo_fd_set;
                                FD_ZERO(&solo_fd_set);
                                FD_SET(clientSD, &solo_fd_set);
                                
                                if (select (clientSD + 1, NULL, &solo_fd_set, NULL, timeout) < 0)
                                {
                                    perror ("select");
                                    exit (EXIT_FAILURE);
                                }
                                if (FD_ISSET(clientSD, &solo_fd_set)) {
                                    if (SSL_write(connectionTypes[clientSD].ssl, partialMessages[i].buffer + old_bytes_read, 
                                                partialMessages[i].bytes_read - old_bytes_read) < 0) {
                                        printf("write failed again\n");
                                        close_server(i);
                                        close_client(clientSD);
                                        continue;
                                    }
                                } else {
                                    printf("write still blocking");
                                    close_server(i);
                                    close_client(clientSD);
                                    continue;
                                }

                            } else {
                                printf("errno: %d\n", errno);
                                close_server(i);
                                close_client(clientSD);
                                continue;
                            }
                        }
                        if (read_result == 2) {
                            /* turn on tunnel mode for client and server */
                            connectionTypes[clientSD].isTunnel = true;
                            connectionTypes[i].isTunnel = true;
                        } else if (read_result == 0) {
                            // cache only if entire response has been received
                            /* TODO: should we test for best max age value or is there a good default? */
                            /* there should only be one response in the buffer */
                            /*Cache_put(cache, 
                                      identifiers[i], 
                                      partialMessages[i].buffer, 
                                      partialMessages[i].total_length, 
                                      get_max_age(partialMessages[i].buffer));*/
                            if (partialMessages[i].bytes_read != partialMessages[i].total_length) {
                                printf("unexpected read of more than one response\n");
                                printf("partialMessages[i].bytes_read: %d, partialMessages[i].total_length: %d\n", partialMessages[i].bytes_read, partialMessages[i].total_length);
                                printf("%s", partialMessages[i].buffer);
                            }

                            free(partialMessages[i].buffer);
                            partialMessages[i].buffer = NULL;
                            create_Message(&partialMessages[i]);

                            /*
                            close(i);
                            FD_CLR(i, &servers_set);
                            FD_CLR(i, &read_fd_set);
                            FD_CLR(i, &write_fd_set);
                            clientToServer[clientSD] = -1;
                            serverToClient[i] = -1;
                            free(identifiers[i]);
                            identifiers[i] = NULL;
                            */
                            
                            if (update_Message(&(partialMessages[clientSD])) == 0) {
                                /* if https connection then connection to server is already established so
                                    we can just send the message */
                                if (connectionTypes[clientSD].isHTTPs) {
                                    /* forward message to server */
                                    if (SSL_write(connectionTypes[i].ssl, partialMessages[clientSD].buffer, partialMessages[clientSD].total_length) == -1) {
                                        /* close client and server connections */
                                        printf("sending request to server at socket %d failed\n", i);
                                        close_client(clientSD);
                                        close_server(i);
                                        continue;
                                    }
                                } else {
                                    int serverSD = get_server_socket(partialMessages[clientSD].buffer);
                                    connectionTypes[serverSD].isHTTPs = false;
                                    connectionTypes[serverSD].isTunnel = false;
                                    fdMax = fdMax > serverSD ? fdMax : serverSD + 1;

                                    /* update data structures */
                                    FD_SET(serverSD, &servers_set);
                                    FD_SET(serverSD, &write_fd_set);
                                    FD_CLR(clientSD, &read_fd_set);
                                    clientToServer[clientSD] = serverSD;
                                    serverToClient[serverSD] = clientSD;

                                    if (connectionTypes[serverSD].ssl != NULL) {
                                        SSL_free(connectionTypes[serverSD].ssl);
                                        connectionTypes[serverSD].ssl = NULL;
                                    }
                                }
                            }
                        } 
                    }
                } else {
                    // don't expect code to ever reach here
                    printf("TODO: unexpected socket %d open\n", i);
                }
            }
        }
    }

    if (close(proxySD) == -1) { return -1; }
    return 0;
}