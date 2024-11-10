#include "proxy_helpers.h"
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>

// -1 if error
// otherwise socket descriptor for the server
int get_server_socket(char *message) {
    char *host = get_host(message);
    char *port_ptr = host;
    while(*port_ptr != ':') {
        port_ptr++;
    }
    *port_ptr = '\0'; // null terminate host
    port_ptr ++;
    int port = atoi(port_ptr);

    struct hostent *server = gethostbyname(host);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", host);
        return -1;
    }

    free(host);

    /* build the server's Internet address */
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    memcpy((char *)&serveraddr.sin_addr.s_addr,
           (char *)server->h_addr,  
           server->h_length);
    serveraddr.sin_port = htons(port);

    /* create the socket */
    int serverSD = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSD < 0) 
        fprintf(stderr, "ERROR opening socket");

    // set socket as non blocking
    int flags = fcntl(serverSD, F_GETFL, 0);
    flags = flags | O_NONBLOCK;
    if (fcntl(serverSD, F_SETFL, flags) < 0) {
        perror("fcntl(F_SETFL)");
        return 1;
    }

    /* connect: create a connection with the server */
    /* TODO: check for timeout to see if connect request failed */
    connect(serverSD, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    printf("sending connect request to server at socket %d\n", serverSD);
    
    return serverSD;
}

// -1 if error
// 0 if success
/*
int get_server_socket(char *message) {
    char *hostname = NULL;
    int portnumber;
    get_host(message, &hostname, &portnumber);

    struct hostent *server = gethostbyname(hostname);
	if (server == NULL) { return -1; }

    struct sockaddr_in serv_addr;
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portnumber);
	
    int serverSD = socket(AF_INET, SOCK_STREAM, 0);

    // set socket as non blocking
    int flags = fcntl(serverSD, F_GETFL, 0);
    flags = flags | O_NONBLOCK;
    if (fcntl(serverSD, F_SETFL, flags) < 0) {
        perror("fcntl(F_SETFL)");
        return 1;
    }
    
    // socket is non blocking so connect call will be in progress when returning
    // check if connect was successful by checking if socket is ready for writing in select call    
    connect(serverSD, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    return serverSD;
}
*/

// returns heap allocated string of host:port
// sets hostname and portnumber pointers
/*
char *get_host(char *message, char **hostname, int *portnumber) {
    char *host_ptr = strstr(message, "Host: ");
    if (host_ptr == NULL) {
        return NULL;
    }
    char *host_start = host_ptr + strlen("Host: ");
    char *host_end = host_start;
    char *port = NULL;
    while (*host_end != '\r') {
        if (*host_end == ':') {
            port = host_end;
        }
        host_end++;
    }
    int host_length = host_end - host_start;
    char *host = malloc(host_length + 4); // + 3 for :80, + 1 for \n
    memcpy(host, host_start, host_length);

    // *hostname = malloc(host_length + 1);
    // memcpy(*hostname, host, host_length);
    // *hostname[host_length] = '\0';

    if (port == NULL) {
        // TODO: change to 443 when using HTTPS 
        memcpy(host + host_length, ":80", 4);
        // *portnumber = 80;
    } else {
        host[host_length] = '\0';
        // *portnumber = atoi(host + host_length  + 1);
    }
    return host;
}
*/

// returns heap allocated string of host:port
char *get_host(char *message) {
    char *host_ptr = strstr(message, "Host: ");
    if (host_ptr == NULL) {
        return NULL;
    }
    char *host_start = host_ptr + strlen("Host: ");
    char *host_end = host_start;
    char *port = NULL;
    while (*host_end != '\r') {
        if (*host_end == ':') {
            port = host_end;
        }
        host_end++;
    }
    int host_length = host_end - host_start;
    char *host = malloc(host_length + 4); // + 3 for :80, + 1 for \n
    memcpy(host, host_start, host_length);
    if (port == NULL) {
        memcpy(host + host_length, ":80", 4);
    } else {
        host[host_length] = '\0';
    }
    return host;
}

int get_max_age(char *request) {
    char *line_start = strstr(request, "Cache-Control: ");
    if (line_start == NULL) {
        return 3600;
    }
    char *line_end = strstr(line_start, "\r\n");
    int line_length = line_end - line_start;
    char *line = malloc(line_length + 1);
    memcpy(line, line_start, line_length);
    line[line_length] = '\0';
    char *max_age_ptr = strstr(line, "max-age=");
    int max_age = 3600;
    if (max_age_ptr != NULL) {
        max_age = atoi(max_age_ptr + strlen("max-age="));
    }
    free(line);
    return max_age;
}
