#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>

char *get_host(char *message);
int get_server_socket(char *message);
int get_max_age(char *request);
// void configure_context_server(SSL_CTX *ctx, char *host);
// void configure_context_client(SSL_CTX *ctx);
// SSL_CTX *create_context();