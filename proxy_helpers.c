#include "proxy_helpers.h"
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <ctype.h>

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
    if (serverSD < 0) {
        fprintf(stderr, "ERROR opening socket");
        return -1;
    }

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
    char *host = malloc(host_length + 5); // + 4 for :443, + 1 for \0
    memcpy(host, host_start, host_length);
    if (port == NULL) {
        if (strstr(message, "CONNECT") != NULL) {
            memcpy(host + host_length, ":443", 5);
        } else {
            memcpy(host + host_length, ":80", 4);
        }
    } else {
        host[host_length] = '\0';
    }
    return host;
}

int get_max_age(char *request) {
    return 10; // for debugging 
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

/* assumes request is a get request */
/* returns heap allocated string containing request identifier domain:port/url */
char *get_identifier(char *request) { 
    char *host = get_host(request);
    char *url_start = strstr(request, " ") + 1;
    char *url_end = url_start;
    while (!isspace(*url_end)) {
        url_end++;
    }
    /* malloc enough memory for host, url and null terminator */
    int host_len = strlen(host);
    int url_len = url_end - url_start;
    char *identifier = malloc(host_len + url_len + 2);
    memcpy(identifier, host, host_len);
    identifier[host_len] = '/';
    memcpy(identifier + host_len + 1, url_start, url_len);
    identifier[host_len + url_len + 1] = '\0';
    free(host);
    return identifier;
}

//     method = TLS_server_method();

//     ctx = SSL_CTX_new(method);
//     if (!ctx) {
//         perror("Unable to create SSL context");
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }

//     return ctx;
// }

// // -1 error
// // 0 success
// void configure_context_client(SSL_CTX *ctx) {
//     /* will use domain specific certificate that is created dynamically */
//     /* get_domain_certificate will return a X509 * object */
//     if (SSL_CTX_use_certificate(ctx, get_domain_certificate()) <= 0) {
//         ERR_print_errors_fp(stderr);
//         return -1;
//     }

//     if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
//         ERR_print_errors_fp(stderr);
//         return -1;
//     }

//     return 0;
// }

// /* takes in hostname:port */
// void configure_context_server(SSL_CTX *ctx, char *host) {
//     /* make sure to verify server's certificate */
//     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

//     /* remove port from hostname */
//     char *port_ptr = host;
//     while(*port_ptr != ':') {
//         port_ptr++;
//     }
//     *port_ptr = '\0'; // null terminate host
    
//     X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ctx);
//     X509_VERIFY_PARAM_set1_host(vpm, host, 0);

//     /* restore host w/ port */
//     *port_ptr = ':';

//     if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
// }