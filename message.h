#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#include <stdbool.h>
#include <openssl/ssl.h>

#define SUMMARY_START "<style> \n\
                                .gray-box { \n\
                                    background-color: #f0f0f0; /* Light gray background */ \n\
                                    border: 1px solid #ccc;   /* Thin gray border */ \n\
                                    padding: 0px 15px;           /* Space inside the box */ \n\
                                    border-radius: 5px;      /* Rounded corners */ \n\
                                    margin: 15px 0;          /* Spacing above and below */ \n\
                                } \n\
                            </style> \n\
                            <div class=\"gray-box\"> \n\
                                <div class=\"mw-heading mw-heading2\"> \n\
                                    <h2 id=\"AI-Summary\">AI-Generated Summary</h2> \n\
                                </div> \n\
                    <p id=\"summary-text\">\n\
                        Loading summary...\n\
                    </p>\n\
                </div>\n\
                \n\
                <script>\n\
                    async function fetchSummary() { \n\
                        try { \n\
                            const response = await fetch(\""
                            
#define SUMMARY_END "\", {\n\
                                method: 'GET',\n\
                                headers: {\n\
                                    'summary': 'true'\n\
                                }\n\
                            });\n\
                            if (!response.ok) {\n\
                                throw new Error(`Error: ${response.statusText}`);\n\
                            }\n\
                            const summary = await response.text(); /* assuming the summary is plain text */ \n\
                            document.getElementById('summary-text').textContent = summary;\n\
                        } catch (error) {\n\
                            document.getElementById('summary-text').textContent = 'Failed to load summary.';\n\
                            console.error('Summary fetch error:', error);\n\
                        }\n\
                    }\n\
                    window.onload = fetchSummary;\n\
                </script>"


struct Message {
    char *buffer;
    int buffer_size;
    int bytes_read;
    bool header_read;
    int total_length;
    /* if use_llm is true then we want to read in the whole response before sending any data */
    /* need to edit content length of response and/or just close the connection when we are done sending */
    bool use_llm; /* set this for true for wikipedia requests/responses */
};
typedef struct Message Message;

struct ConnectionType {
    bool isHTTPs;
    bool isTunnel;
    SSL *ssl;
};
typedef struct ConnectionType ConnectionType;

void create_Message(Message *msg);
int add_to_Message(Message *message, int sd, ConnectionType *ct);
void expand_buffer(Message *message);
int check_message(Message *message, int sd);
int update_Message(Message *message);
void remove_header(Message *message, char *header);
int make_llm_enhanced_response(Message *message, char *summary_endpoint, int summary_size);

#endif