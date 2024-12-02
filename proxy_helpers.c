#include "proxy_helpers.h"

#include <curl/curl.h>
#include <stdbool.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <strings.h>

// provided to us
const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";
const char *x_api_key = "x-api-key: comp112rGOLJUIz2s5ptwXUDSytIOnpBuuDdHKXzjsck72r"; // Our API key

// provided to us
size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb; // Total size of received data
    strncat(data, ptr, total_size); // Append the received data to the buffer
    return total_size;
}

size_t write_callback_wiki(void *ptr, size_t size, size_t nmemb, char *curl_response) {
    size_t total_size = size * nmemb; 
    data *d = (data *)curl_response;

    char *temp = realloc(d->response_data, d->response_size + total_size + 1);
    if (temp == NULL) {
        fprintf(stderr, "Not enough memory to store response.\n");
        return 0;
    }

    d->response_data = temp;
    memcpy(&(d->response_data[d->response_size]), ptr, total_size);
    d->response_size += total_size;
    d->response_data[d->response_size] = '\0';
    
    return total_size;
}

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

    /* build the server's Internet address */
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr)); 
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &serveraddr.sin_addr) <= 0) {
        // Not an IP address, resolve hostname
        struct hostent *server = gethostbyname(host);
        if (server == NULL) {
            fprintf(stderr, "ERROR: No such host as %s\n", host);
            free(host);
            return -1;
        }

        memcpy(&serveraddr.sin_addr.s_addr, server->h_addr, server->h_length);
    }

    free(host);

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
        memcpy(host + host_length, ":443", 5);
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
    memcpy(identifier + host_len, url_start, url_len);
    identifier[host_len + url_len] = '\0';
    free(host);
    return identifier;
}

X509 *generate_x509(EVP_PKEY *publicKey, EVP_PKEY *privateKey, char *host)
{
    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    if(!x509)
    {
        fprintf(stderr, "Unable to create X509 structure.");
        return NULL;
    }
    
    /* Set the serial number. */
    // ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    unsigned char serial_bytes[15];
    RAND_bytes(serial_bytes, sizeof(serial_bytes));

    // Convert the byte array to a BIGNUM
    BIGNUM *bn_serial = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);

    // Ensure the serial number is positive
    if (BN_is_negative(bn_serial)) {
        BN_set_negative(bn_serial, 0); // Make sure the serial number is positive
    }

    // Set the serial number for the certificate
    ASN1_INTEGER *serial_number = X509_get_serialNumber(x509);
    BN_to_ASN1_INTEGER(bn_serial, serial_number);
    BN_free(bn_serial);

    
    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    
    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, publicKey);
    
    /* We want to copy the subject name to the issuer name. */
    X509_NAME * name = X509_get_subject_name(x509);

    /* allow passing in identifier as host */
    char *port_ptr = host;
    while (*port_ptr != ':' && *port_ptr != '\0') {
        port_ptr++;
    }
    *port_ptr = '\0';
    
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"US",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"Massachusetts", -1, -1, 0); 
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"IandKProxy", -1, -1, 0);
    /* set common name to server hostname*/
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)host, -1, -1, 0);
    
    /* set issuer name to match ca.crt */
    const char *ca = "CA_NAME";
    X509_NAME *issuer = X509_get_issuer_name(x509);
    X509_NAME_add_entry_by_txt(issuer, "CN", MBSTRING_ASC,  (unsigned char *)ca, -1, -1, 0);


    /* TODO: add SAN extension with host */
    X509_EXTENSION *san_ext = NULL;
    X509V3_CTX ctx;

    // Initialize the X509V3 context
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);

    // Create the SAN extension
    // The format is "DNS:hostname", for example, "DNS:example.com"
    /* TODO: may want to check if host is ip and not dns */
    char san_value[strlen(host) + 5]; // + 5 for "DNS:" and null terminator

    struct in_addr ipv4_addr;
    if (inet_pton(AF_INET, host, &ipv4_addr) == 1) {
        snprintf(san_value, sizeof(san_value), "IP:%s", host);
    } else {
        snprintf(san_value, sizeof(san_value), "DNS:%s", host);
    }

    /* restore identifier w/ port */
    *port_ptr = ':';
    san_ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san_value);
    if (!san_ext) {
        fprintf(stderr, "Error creating SAN extension\n");
        X509_free(x509);
        return NULL;
    }

    // Add the san extension to the certificate
    if (!X509_add_ext(x509, san_ext, -1)) {
        fprintf(stderr, "Error adding SAN extension to certificate\n");
        X509_free(x509);
        X509_EXTENSION_free(san_ext);
        return NULL;
    }

    X509_EXTENSION_free(san_ext);

    /* adding serverAuth */
    X509_EXTENSION *eku_ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth");
    if (!eku_ext) {
        fprintf(stderr, "Error creating EKU extension\n");
        X509_free(x509);
        return NULL;
    }

    if (!X509_add_ext(x509, eku_ext, -1)) {
        fprintf(stderr, "Error adding EKU extension\n");
        X509_free(x509);
        X509_EXTENSION_free(eku_ext);
        return NULL;
    }

    X509_EXTENSION_free(eku_ext);

    
    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, privateKey, EVP_sha256()))
    {
        fprintf(stderr, "Error signing certificate.\n");
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}


SSL_CTX *create_context(const SSL_METHOD *method) {
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// -1 error
// 0 success
int configure_context_client(SSL_CTX *ctx, EVP_PKEY *publicKey, EVP_PKEY *privateKey, char *host) {
    /* will use domain specific certificate that is created dynamically */
    /* get_domain_certificate will return a X509 * object */
    X509 *cert = generate_x509(publicKey, privateKey, host);
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    X509_free(cert);

    if (SSL_CTX_use_PrivateKey(ctx, privateKey) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

/* takes in hostname:port */
int configure_context_server(SSL_CTX *ctx, EVP_PKEY *privateKey, char *host) {
    /* make sure to verify server's certificate */
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);

    /* remove port from hostname */
    char *port_ptr = host;
    while(*port_ptr != ':') {
        port_ptr++;
    }
    *port_ptr = '\0'; // null terminate host
    
    // X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ctx);
    // X509_VERIFY_PARAM_set1_host(vpm, host, 0);

    /* restore host w/ port */
    *port_ptr = ':';

    if (SSL_CTX_use_PrivateKey(ctx, privateKey) <= 0 ) {
        ERR_print_errors_fp(stderr);
        return -1;
    }


    /* verify using the OS's trusted CAs*/
    /*
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    */

    return 0;
}

/*char *simplifyHTML(char *response, int response_size) {
    char *simplified_content = malloc(response_size);
    simplified_content[0] = '\0';

 
    char *c = strstr(response, "<body");
    if (c == NULL) {
        printf("no llm response body\n");
        return simplified_content;
    }
    printf("at llm response body\n");
    c = strstr(c, ">");
    if (c == NULL) {
        printf("no llm response body\n");
        return simplified_content;
    }
    c++;
    int i = 0;
    bool inside_tag = false;
    char *response_end = response + response_size;
    bool inside_script = false; // Track if inside a <script> block
    bool inside_style = false;


    while (c < response_end) {
        if ((*c == '<') || (*c == '{')) {
            inside_tag = true;
            // Check if entering a <script> block
            if (strncasecmp(c, "<script", 7) == 0) {
                inside_script = true;
            }
        } else if ((*c == '>') || (*c == '}')) {
            inside_tag = false;
            // Check if exiting a <script> block
            if (inside_script && strncasecmp(c - 7, "</script", 8) == 0) {
                inside_script = false;
            }
        } else if (!inside_tag && !inside_script) {
            if ((*c != '\"') && (*c != '\\') && (*c != '/') && 
                (*c != '\'') && (*c != '\n') && (*c != 9)) {
                simplified_content[i] = *c;
                i++;
            }
        }
        c++;
    }

    simplified_content[i] = '\0';

    
    

    printf("made simplified content:\n%s\n", simplified_content);

    return simplified_content;
}*/

char *simplifyHTML(char *html_content, size_t content_length) {
    char *simplified_content = malloc(strlen(html_content));
    bool inside_tag = false;
    size_t i = 0;
    char c;
    size_t j = 0;

    bool inside_script = false; // Track if inside a <script> block
    bool inside_style = false; // track if inside a <style> block

    while ((c = html_content[j]) != '\0' && j < content_length) {
        if (c == '<') {
            inside_tag = true;
            // Check if entering a <script> block
            if (strncasecmp(html_content + j, "<script", 7) == 0) {
                inside_script = true;
            }
            // check if entering a <style> block
            if (strncasecmp(html_content + j, "<style", 6) == 0) {
                inside_style = true;
            }
        } else if (c == '>') {
            inside_tag = false;
            // Check if exiting a <script> block
            if (inside_script && strncasecmp(html_content + j - 8, "</script", 8) == 0) {
                inside_script = false;
            }
            // Check if exiting a <style> block
            if (inside_style && strncasecmp(html_content + j - 7, "</style", 7) == 0) {
                inside_style = false;
            }
        } else if (!inside_tag && !inside_script && !inside_style) {
            if (c != '\"' && c != '\\' && c != '/' &&
                c != '\'' && c != '\n' && c != '\t') {
                simplified_content[i] = c;
                i++;
            }
        }
        j++;
    }

    simplified_content[i] = '\0';

    /* NOTE: I think this will just use the wikipedia header sections, but it seems to be working so maybe keep it? 
     * Otherwise the request will time out */
    /*
    char *end_of_content = strstr(simplified_content, "References");
    if (end_of_content != NULL) {
        *end_of_content = '\0';
    }
    */

    printf("made simplified content:\n%s\n", simplified_content);
    return simplified_content;
}

// provided to us
void llmproxy_request(char *model, char *system, char *query, char *response_body, int lastk, char *session_id) {
    session_id = session_id == NULL? "GenericSession" : session_id;
    CURL *curl;
    CURLcode res;


    char *request_fmt = "{\n"
                        "  \"model\": \"%s\",\n"
                        "  \"system\": \"%s\",\n"
                        "  \"query\": \"%s\",\n"
                        "  \"temperature\": %.2f,\n"
                        "  \"lastk\": %d,\n"
                        "  \"session_id\": \"%s\"\n"
                        "}";

    // JSON data to send in the POST request
    int query_len = strlen(query);
    char request[4096 + query_len];
    memset(request, 0, 4096 + query_len);
    snprintf(request,
             sizeof(request),
             request_fmt,
             model,
             system,
             query,
             0.0,
             lastk,
             session_id);


    printf("Initiating request: %s\n", request);

    // Initialize CURL
    curl = curl_easy_init();
    if (curl) {
        // Set the URL of the Proxy Agent server server
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set the Content-Type to application/json
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        // Add x-api-key to header
        headers = curl_slist_append(headers, x_api_key);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // add request 
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);


        // Set the write callback function to capture response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // Set the buffer to write the response into
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_body);

        // Perform the POST request
        res = curl_easy_perform(curl);

        // Check if the request was successful
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize CURL.\n");
    }
}

void get_wiki_content(char *wiki_url, data *d) {
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, wiki_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_wiki);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)d);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize curl\n");
    }
}

char *make_summary_response(char *summary) {
    // HTTP response template
    const char *response_template = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s";

    // Calculate content length
    size_t content_length = strlen(summary);

    // Allocate memory for the full response
    size_t response_size = strlen(response_template) + content_length + 10;
    char *response = malloc(response_size);

    if (response == NULL) {
        perror("Failed to allocate memory for response");
        return NULL;
    }

    // Format the response
    snprintf(response, response_size, response_template, content_length, summary);

    return response;

}
