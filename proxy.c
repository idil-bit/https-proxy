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

#define CACHE_SIZE 10
#define BUFFER_SIZE 1024

int proxySD;
Cache cache;

void signal_handler(int signal) {
        close(proxySD);
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
    fd_set clients_set, servers_set; // holds client and server sockets

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
	signal(SIGPIPE, SIG_IGN);

	fd_set active_fd_set, read_fd_set;
	FD_ZERO(&active_fd_set);
	FD_SET(proxySD, &active_fd_set);

    int clientSD;
    int clen = sizeof(caddr);
	
	char buffer[BUFFER_SIZE];
	int bytes_read;

    while (1) {
		read_fd_set = active_fd_set;
		if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {	
            perror("select");
            exit (EXIT_FAILURE);
		}

		for (int i = 0; i < FD_SETSIZE; i++) {
			if (FD_ISSET(i, &read_fd_set)) {
				if (i == proxySD) {
					// accept connection 
                    clientSD = accept(proxySD, (struct sockaddr *) &caddr, &clen);
                    FD_SET(clientSD, &active_fd_set);
					FD_SET(clientSD, &clients_set);
				} else if (FD_ISSET(i, &clients_set)) {
					
				} else if (FD_ISSET(i, &servers_set)) {
					clientSD = serverToClient[i];
					// read in data from server
                    // add_to_Message(Message *message, int sd)
					if ((bytes_read = read(i, buffer, BUFFER_SIZE)) <= 0) {
						// error - close connection
						close(i);
						continue;
					} 

                    // if entire response has been received
                        // forward data to client socket	
                        write(clientSD, buffer, bytes_read);
                        // store in cache
				} else {
					// don't expect code to ever reach here

                }
            }
		}
    }

    if (close(proxySD) == -1) {
		return -1;
	}

        return 0;
}