#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
struct data {
    char *response_data;
    size_t response_size;
};
typedef struct data data;

char *get_host(char *message);
int get_server_socket(char *message);
int get_max_age(char *request);
char *get_identifier(char *request);
X509 *generate_x509(EVP_PKEY *publicKey, EVP_PKEY *privateKey, char *host);
int configure_context_server(SSL_CTX *ctx, EVP_PKEY *privateKey, char *host);
int configure_context_client(SSL_CTX *ctx, EVP_PKEY *publicKey, EVP_PKEY *privateKey, char *host);
SSL_CTX *create_context(const SSL_METHOD *method);
char *simplifyHTML(char *html_content, size_t content_length);
void get_wiki_content(char *wiki_url, data *d);
void llmproxy_request(char *model, char *system, char *query, char *response_body, int lastk, char *session_id);
char *make_summary_response(char *summary);