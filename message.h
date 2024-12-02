#ifndef MESSAGE_INCLUDED
#define MESSAGE_INCLUDED

#include <stdbool.h>
#include <openssl/ssl.h>

#define LLM_ADDITION \
"<style> \n\
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
    const response = await fetch(\"%s\", {\n\
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
</script>\n\
<style>\n\
    .qa-container {\n\
        background-color: #f0f0f0; /* light gray background */\n\
        border: 1px solid #ddd;\n\
        padding: 15px;\n\
        border-radius: 5px;\n\
        margin-top: 10px;\n\
        padding-top: 5px;\n\
    }\n\
\n\
    .qa-container h2 {\n\
        margin-top: 0;  /* Reduces the space above the heading */\n\
        margin-bottom: 10px;  /* Adjust space below the heading if needed */\n\
    }\n\
\n\
    .qa-input {\n\
        width: 100%%; /* Full width minus padding */\n\
        padding: 15px; /* Equal padding on left and right */\n\
        margin-bottom: 10px;\n\
        margin-top: 10px;\n\
        border: 1px solid #ccc;\n\
        border-radius: 4px;\n\
        font-size: 14px;\n\
        box-sizing: border-box; /* Ensures padding doesn't affect width calculation */\n\
    }\n\
\n\
    .qa-button {\n\
        padding: 10px 20px;\n\
        background-color: #007bff;\n\
        color: white;\n\
        border: none;\n\
        border-radius: 4px;\n\
        cursor: pointer;\n\
        font-size: 14px;\n\
    }\n\
\n\
    .qa-button:disabled {\n\
        background-color: #aaa;\n\
        cursor: not-allowed;\n\
    }\n\
\n\
    .loading-indicator {\n\
        display: none;\n\
        font-size: 14px;\n\
        color: #555;\n\
    }\n\
\n\
    .qa-answer {\n\
        margin-top: 10px;\n\
        background-color: #f0f0f0;\n\
        border-left: 4px solid #007bff;\n\
        padding: 10px;\n\
        border-radius: 4px;\n\
    }\n\
</style>\n\
<div class=\"qa-container\">\n\
    <div class=\"mw-heading mw-heading2\">\n\
        <h2>Ask a Question</h2>\n\
    </div>\n\
    <input type=\"text\" id=\"question-input\" class=\"qa-input\" placeholder=\"Type your question here...\"/>\n\
    <button id=\"submit-question\" class=\"qa-button\" onclick=\"askQuestion()\">Ask</button>\n\
    <p id=\"loading-indicator\" class=\"loading-indicator\">Loading answer...</p>\n\
    <!-- Initially hidden -->\n\
    <div id=\"qa-result\" class=\"qa-answer\" style=\"display:none;\"></div>\n\
</div>\n\
<script>\n\
    async function askQuestion() {\n\
        const questionInput = document.getElementById('question-input');\n\
        const question = questionInput.value.trim();\n\
        const loadingIndicator = document.getElementById('loading-indicator');\n\
        const qaResult = document.getElementById('qa-result');\n\
\n\
        if (!question) {\n\
            alert(\"Please type a question before asking!\");\n\
            return;\n\
        }\n\
\n\
        // Show the loading indicator before sending the request\n\
        loadingIndicator.style.display = 'block';\n\
        qaResult.innerHTML = '';\n\
        // Clear previous answer (if any)\n\
        qaResult.style.display = 'none';\n\
        // Hide the answer container\n\
\n\
        try {\n\
            const response = await fetch(\"%s\", {\n\
                method: 'POST',\n\
                headers: {\n\
                    'Content-Type': 'text/plain',\n\
                    'question': 'true'\n\
                },\n\
                body: question\n\
            });\n\
\n\
            if (!response.ok) {\n\
                throw new Error(`Error: ${response.statusText}`);\n\
            }\n\
\n\
            const data = await response.text();\n\
            // Hide the loading indicator\n\
            loadingIndicator.style.display = 'none';\n\
\n\
            // Display the question and answer\n\
            qaResult.innerHTML = `\n\
                <p><strong>Question:</strong> ${question}</p>\n\
                <p><strong>Answer:</strong> ${data}</p>\n\
            `;\n\
            qaResult.style.display = 'block';\n\
            // Show the answer section\n\
\n\
            // Clear the input for new questions\n\
            questionInput.value = '';\n\
        } catch (error) {\n\
            loadingIndicator.style.display = 'none';\n\
            qaResult.innerHTML = `<p><strong>Error:</strong> Could not retrieve an answer.</p>`;\n\
            qaResult.style.display = 'block';\n\
            // Show error message\n\
            console.error('Error fetching answer:', error);\n\
        }\n\
    }\n\
</script>\n"

#define LLM_ADDITION_SIZE strlen(LLM_ADDITION) - 6 /* - 4 for two %s's and -2 for %%*/

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
int make_llm_enhanced_response(Message *message, char *endpoint);

#endif