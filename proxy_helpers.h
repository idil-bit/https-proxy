#include <string.h>
#include <stdlib.h>

// char *get_host(char *message, char **hostname, int *portnumber);
char *get_host(char *message);
int get_server_socket(char *message);
int get_max_age(char *request);