#include "proxy_helpers.h"

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
        /* TODO: change to 443 when using HTTPS */
        memcpy(host + host_length, ":80", 4);
    } else {
        host[host_length] = '\0';
    }
    return host;
}
