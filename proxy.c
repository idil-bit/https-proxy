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

/* TODO: test with different cache sizes for optimization */
#define CACHE_SIZE 10
#define BUFFER_SIZE 1024

int proxySD;
Cache cache;

void signal_handler(int signal) {
        close(proxySD);
	Cache_free(&cache);
        exit(EXIT_FAILURE);
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		return -1;
	}

	int portNumber = atoi(argv[1]);

	proxySD = socket(AF_INET, SOCK_STREAM, 0);
	if (proxySD == -1) {
		return -1;
	}

	struct sockaddr_in saddr, caddr;
	memset(&saddr, '\0', sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(portNumber);

	int optval = 1;
	setsockopt(proxySD, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	if (bind(proxySD, (struct sockaddr *) &saddr, sizeof(saddr)) == -1) {
		return -1;
	}

	if (listen(proxySD, 0) == -1) {
		return -1;
	}

	cache = Cache_new(CACHE_SIZE);
	Message partialMessages[FD_SETSIZE];
	int clientToServer[FD_SETSIZE]; // for each clientSD, the serverSD they talk to
	int serverToClient[FD_SETSIZE]; // for each serverSD, the clientSD they talk to
	for (int i = 0; i < FD_SETSIZE; i++) {
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

	int clientSD;
	int clen = sizeof(caddr);
	
	char buffer[BUFFER_SIZE];
	int bytes_read;

    	while (1) {
		read_fd_set_copy = read_fd_set;
		write_fd_set_copy = write_fd_set;
		if (select (FD_SETSIZE, &read_fd_set_copy, &write_fd_set_copy, NULL, NULL) < 0) {	
            		perror("select");
            		exit (EXIT_FAILURE);
		}

		for (int i = 0; i < FD_SETSIZE; i++) {
			if (FD_ISSET(i, &read_fd_set_copy)) {
				if (i == proxySD) {
					
					// accept connection 
                    			clientSD = accept(proxySD, (struct sockaddr *) &caddr, &clen);
                    			FD_SET(clientSD, &read_fd_set);
					FD_SET(clientSD, &clients_set);
					create_Message(&(partialMessages[clientSD]));
				} else if (FD_ISSET(i, &clients_set)) {
					
					int read_result = add_to_Message(&(partialMessages[i]), i);
					if (read_result == 0) {
						
						// check if response is already cached
						char *placeholder_host;
						int placeholder_port;
						// char *host = get_host(partialMessages[i].buffer, &placeholder_host, &placeholder_port);
						char *host = get_host(partialMessages[i].buffer);
						Cached_item cached_response = Cache_get(cache, host);
						free(host);
						if (cached_response != NULL) {
							
							if (write(i, cached_response->value, cached_response->value_size) == -1) {
								// remove client
								close(i);
								FD_CLR(clientSD, &clients_set);
								FD_CLR(clientSD, &read_fd_set);
								free(partialMessages[clientSD].buffer);
								partialMessages[clientSD].buffer = NULL;
								clientToServer[clientSD] = -1;
							}
						} else {
							
							int serverSD = get_server_socket(partialMessages[i].buffer);
							/* TODO: check if -1 and handle accordingly */

							// add to clientToServer and serverToClient
							FD_SET(serverSD, &servers_set);
							FD_SET(serverSD, &write_fd_set);
							clientToServer[i] = serverSD;
							serverToClient[serverSD] = i;
						}
					} else if (read_result == -1) {
						
						// remove client
						close(i);
						FD_CLR(clientSD, &clients_set);
						FD_CLR(clientSD, &read_fd_set);
						free(partialMessages[clientSD].buffer);
						partialMessages[clientSD].buffer = NULL;
						clientToServer[clientSD] = -1;
					}
				} else if (FD_ISSET(i, &servers_set)) {
					
					clientSD = serverToClient[i];

					// if corresponding client has closed the connection
					if (clientToServer[clientSD] == -1) {
						// close this connection and remove from sets
						close(i);
						FD_CLR(i, &servers_set);
						FD_CLR(i, &write_fd_set);
						FD_CLR(i, &read_fd_set);
						serverToClient[i] = -1;
						free(partialMessages[i].buffer);
						partialMessages[i].buffer = NULL;
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
						FD_CLR(i, &servers_set);
						FD_CLR(i, &write_fd_set);
						FD_CLR(i, &read_fd_set);
						serverToClient[i] = -1;
						free(partialMessages[i].buffer);
						partialMessages[i].buffer = NULL;
					} else {
						
						// send chunk we just read in (from old bytes read to current bytes read)
						if (write(clientSD, partialMessages[i].buffer + old_bytes_read, 
								partialMessages[i].bytes_read - old_bytes_read) == -1) {
							close(i);
						}
						if (read_result == 0) {
							// cache only if entire response has been received
							char *placeholder_host;
							int placeholder_port;
							/* TODO: should we test for best max age value or is there a good default? */
							do {
								Cache_put(cache, 
										get_host(partialMessages[i].buffer), 
									partialMessages[i].buffer, 
									partialMessages[i].total_length, 
									get_max_age(partialMessages[i].buffer));
								
							} while (update_Message(&partialMessages[i]) == 0);
						}
					}
				} else {
					// don't expect code to ever reach here
					printf("TODO: unexpected socket open\n");
                		}
            		}
			if (FD_ISSET(i, &write_fd_set_copy)) {
				
				clientSD = serverToClient[i];
				if (write(i, partialMessages[clientSD].buffer, partialMessages[clientSD].total_length) == -1) { close(i); }
				FD_CLR(i, &write_fd_set);
				FD_SET(i, &read_fd_set);
				// keep on sending requests as long as they are ready
				
				if (update_Message(&(partialMessages[clientSD])) == 0) {
					int serverSD = get_server_socket(partialMessages[i].buffer);

					// add to clientToServer and serverToClient
					FD_SET(serverSD, &servers_set);
					clientToServer[i] = serverSD;
					serverToClient[serverSD] = i;
				}
				
			}
		}
    	}

    	if (close(proxySD) == -1) { return -1; }
        return 0;
}