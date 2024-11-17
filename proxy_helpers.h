#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>

char *get_host(char *message);
int get_server_socket(char *message);
int get_max_age(char *request);
char *get_identifier(char *request);
X509 *generate_x509(EVP_PKEY *publicKey, EVP_PKEY *privateKey, char *host);
int configure_context_server(SSL_CTX *ctx, EVP_PKEY *privateKey, char *host);
int configure_context_client(SSL_CTX *ctx, EVP_PKEY *publicKey, EVP_PKEY *privateKey, char *host);
SSL_CTX *create_context(const SSL_METHOD *method);