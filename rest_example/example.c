#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "cJSON.h"

// provided to us
const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";
const char *x_api_key = "x-api-key: comp112rGOLJUIz2s5ptwXUDSytIOnpBuuDdHKXzjsck72r"; // Our API key

// provided to us
size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb; // Total size of received data
    strncat(data, ptr, total_size); // Append the received data to the buffer
    return total_size;
}

// provided to us
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

    // JSON data to send in the POST request
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

void simplifyHTML(const char *html_filename, char *simplified_content, size_t max_len) {
    FILE *html_file = fopen(html_filename, "r");
    if (html_file == NULL) {
        fclose(html_file);
        return;
    }

    bool inside_tag = false;
    size_t i = 0;
    char c;

    while (((c = fgetc(html_file)) != EOF) && i < max_len) {
        if ((c == '<') || (c == '{')) {
            inside_tag = true;
        } else if ((c == '>') || (c == '}')) {
            inside_tag = false;
        } else if (!inside_tag) {
            if ((c != '\"') && (c != '\\') && (c != '/') && 
                (c != '\'') && (c != '\n') && (c != 9)) {
                simplified_content[i] = c;
                i++;
            }
        }
    }

    simplified_content[i] = '\0';
    fclose(html_file);
}

int main(int argc, char* argv[]) {
    if (argc != 2) { printf("Usage: ./%s <wikipedia_url>!\n", argv[0]); return -1; }

    char curl_command[512];
    snprintf(curl_command, sizeof(curl_command), "curl \"%s\" > %s", argv[1], "curled_wikipage.html");
    system(curl_command);

    size_t max_len = 1024 * 10 * 10; // TODO: decide how big we want our simplified webpage to be
    char *simplified_wikipage = (char *) malloc(max_len);
    simplifyHTML("curled_wikipage.html", simplified_wikipage, max_len);

    char *end_of_content = strstr(simplified_wikipage, "References");
    if (end_of_content != NULL) {
        *end_of_content = '\0';
    } else {
        end_of_content = simplified_wikipage + 200; // TODO: decide on how many characters to send to the gpt
        *end_of_content = '\0';
    }

    // TODO: test with different prompts
    char response_body[4096] = "";
    llmproxy_request("4o-mini", "Summarize the wikipedia page in a couple sentences", simplified_wikipage, response_body);
    cJSON *json = cJSON_Parse(response_body);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
    if (cJSON_IsString(result) && (result->valuestring != NULL)) {
        printf("Result: %s\n", result->valuestring);
    }

    return 0;
}
