#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "cJSON.h"

// dont change
const char *url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev";

// add your API key
const char *x_api_key = "x-api-key: comp112rGOLJUIz2s5ptwXUDSytIOnpBuuDdHKXzjsck72r"; // Your API key


// This function is called by libcurl to write data into a string buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, char *data) {
    size_t total_size = size * nmemb; // Total size of received data
    strncat(data, ptr, total_size); // Append the received data to the buffer
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

void simplifyHTML(const char *inputFileName, const char *outputFileName) {
    FILE *inputFile = fopen(inputFileName, "r");
    FILE *outputFile = fopen(outputFileName, "w");

    if (inputFile == NULL || outputFile == NULL) {
        perror("Error opening files");
        if (inputFile) fclose(inputFile);
        if (outputFile) fclose(outputFile);
        return;
    }

    char ch;
    bool insideTag = false;

    while ((ch = fgetc(inputFile)) != EOF) {
        if ((ch == '<') || (ch == '{')) {
            insideTag = true; // Entering an HTML tag
        } else if ((ch == '>') || (ch == '}')) {
            insideTag = false; // Exiting an HTML tag
        } else if (!insideTag) {
            if ((ch != '\"') && (ch != '\\') && (ch != '/') && (ch != '\'') && (ch != '\n') && (ch != 9)) {
                fputc(ch, outputFile); // Write non-tag characters to the output file
            }
        }
    }

    fclose(inputFile);
    fclose(outputFile);
    printf("HTML simplified and written to %s\n", outputFileName);
}

int main(int argc, char* argv[]) {
    if (argc != 2) { printf("pls put url to get html from!\n"); return -1; }

    char command[512];
    snprintf(command, sizeof(command), "curl \"%s\" > %s", argv[1], "automated-inputfile.html");
    // Execute the command
    system(command);

    simplifyHTML("automated-inputfile.html", "automated-simplified-input.txt");
    FILE *fp = fopen("automated-simplified-input.txt", "rb");
    struct stat fileStat;
    if (stat("automated-simplified-input.txt", &fileStat) != 0) { printf("error with stat\n"); }
    int pagesize = fileStat.st_size;
    char wikipage[pagesize + 1];
    fread(wikipage, sizeof(char), pagesize, fp);
    wikipage[pagesize] = '\0';

    char *indexEnd = strstr(wikipage, "References");
    if (indexEnd != NULL) {
        *indexEnd = '\0';
    }
    fclose(fp);

    // Buffer to store response data
    char response_body[4096] = "";
    llmproxy_request("4o-mini", "Summarize the wikipedia page in a couple sentences", wikipage, response_body);
    cJSON *json = cJSON_Parse(response_body);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(json, "result");
    if (cJSON_IsString(result) && (result->valuestring != NULL)) {
        printf("Result: %s\n", result->valuestring);
    }

    // printf("Response: %s\n", response_body);

    return 0;
}
