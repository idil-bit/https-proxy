#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "cJSON.h"

const char *llm_url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";
const char *x_api_key = "x-api-key: comp112rGOLJUIz2s5ptwXUDSytIOnpBuuDdHKXzjsck72r"; 

struct data {
    char *response_data;
    size_t response_size;
};
typedef struct data data;

size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb;
    strncat(data, ptr, total_size);
    return total_size;
}

void llmproxy_request(char *model, char *system, char *query, char *response_body){
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

    char request[4096];
    memset(request, 0, 4096);
    snprintf(request,
             sizeof(request),
             request_fmt,
             model,
             system,
             query,
             0.0,
             0,
             "GenericSession");

    printf("Initiating request: %s\n", request);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, llm_url);
        
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        headers = curl_slist_append(headers, x_api_key);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_body);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    } else {
        fprintf(stderr, "Failed to initialize CURL.\n");
    }
}

void replaceCharacter(char* str, char target, char replacement, int size) {
    if (!str) {
        return;
    }
    
    char* ptr = str;
    for (int i = 0; i < size; i++) {
        if (*ptr == target) {
            *ptr = replacement;
        }
        ++ptr;
    }
}

void simplifyHTML(char *html_content, char *simplified_content, size_t max_len) {
    bool inside_tag = false;
    size_t i = 0;
    char c;
    size_t j = 0;

    while ((c = html_content[j]) != '\0' && i < max_len - 1) {
        if (c == '<' || c == '{') {
            inside_tag = true;
        } else if (c == '>' || c == '}') {
            inside_tag = false;
        } else if (!inside_tag) {
            if (c != '\"' && c != '\\' && c != '/' &&
                c != '\'' && c != '\n' && c != '\t') {
                simplified_content[i] = c;
                i++;
            }
        }
        j++;
    }

    simplified_content[i] = '\0';
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

int main(int argc, char* argv[]) {
    if (argc != 2) { printf("Usage: ./%s <wikipedia_url>!\n", argv[0]); return -1; }

    data d = {NULL, 0};
    get_wiki_content(argv[1], &d);
 
    size_t max_len = 1024 * 10 * 10; // TODO: decide how big we want our simplified webpage to be
    char *simplified_wikipage = (char *) malloc(max_len);

    simplifyHTML(d.response_data, simplified_wikipage, max_len);
    free(d.response_data);

    char *end_of_content = strstr(simplified_wikipage, "References");
    if (end_of_content != NULL) {
        *end_of_content = '\0';
    } else {
        end_of_content = simplified_wikipage + 200; // TODO: decide on how many characters to send to the gpt
        *end_of_content = '\0';
    }

    char response_body[4096] = "";
    llmproxy_request("4o-mini", "Summarize the wikipedia page in a couple sentences", simplified_wikipage, response_body); // TODO: test with different prompts
    cJSON *json = cJSON_Parse(response_body);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
    if (cJSON_IsString(result) && (result->valuestring != NULL)) {
        printf("Result: %s\n", result->valuestring);
    }

    return 0;
}
