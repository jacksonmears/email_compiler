#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include "../external/json.hpp" // https://github.com/nlohmann/json
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <chrono>
#include "../include/gmail_types.hpp"

using json = nlohmann::json;
using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;


constexpr int BUFFER_SIZE = 4096;

//////// NEED TO CHANGE TO WEBSOCKET FOR SOOOOO MANY REASONS (current reason is ability to detect when web browser is closed and we can end the exe)

json threadIdSetToJson(const std::set<ThreadID, ThreadSortByDateDesc>* s) {
    json arr = json::array();
    for (const auto& t : *s) {
        arr.push_back({
            {"id", t.id},
            {"threadDate", t.threadDate}   
        });
    }
    return arr;
}


json messageToJson(const MessageInfo* msg) {
    return {
        {"internalDate", msg->internalDate},
        {"id", msg->id},
        {"labelIds", msg->labelIds},
        {"from", msg->from},
        {"to", msg->to},
        {"bodyPlain", msg->bodyPlain}, // keep as-is, Base64URL
        {"bodyHtml", msg->bodyHtml}    // keep as-is, Base64URL
    };
}

json threadToJson(const ThreadInfo* thread) {
    json j_messages = json::array();
    for (const auto& msg : thread->messages)
        j_messages.push_back(messageToJson(&msg));


    return {
        {"threadId", thread->threadId},
        {"threadDate", thread->threadDate},
        {"threadSubject", thread->subject},
        {"readThread", thread->read},
        {"unsubscribeLink", thread->unsubscribe_link}, 
        {"messages", j_messages}
    };
}


json exportMailboxJson(const Indicies* indicies, const std::unordered_map<std::string, ThreadInfo>* threadInfo) {
    json j;

    // ----------------------
    // 1. BUCKETS
    // ----------------------
    j["buckets"] = {
        { "inbox", {
            { "Primary",    threadIdSetToJson(&indicies->inbox.Primary) },
            { "Promotions", threadIdSetToJson(&indicies->inbox.Promotions) },
            { "Social",     threadIdSetToJson(&indicies->inbox.Social) },
            { "Forums",     threadIdSetToJson(&indicies->inbox.Forums) }
        }},
        { "labels", {
            { "Important", threadIdSetToJson(&indicies->Important) },
            { "Starred",   threadIdSetToJson(&indicies->Starred) },
            { "Sent",      threadIdSetToJson(&indicies->Sent) },
            { "Draft",     threadIdSetToJson(&indicies->Draft) },
            { "Spam",      threadIdSetToJson(&indicies->Spam) },
            { "Chat",      threadIdSetToJson(&indicies->Chat) },
            { "Snoozed",   threadIdSetToJson(&indicies->Snoozed) },
            { "Trash",     threadIdSetToJson(&indicies->Trash) }
        }}
    };

    // ----------------------
    // 2. FULL THREAD DETAILS
    // ----------------------
    json threadsJson;

    for (const auto& [id, thread] : *threadInfo)
        threadsJson[id] = threadToJson(&thread);

    j["threads"] = threadsJson;

    return j;
}



void runServer(const Indicies* indicies, const std::unordered_map<std::string, ThreadInfo>* threadInfo, TimePoint* start, int port = 8080) {

    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listen_sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed\n";
        closesocket(listen_sock);
        WSACleanup();
        return;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed\n";
        closesocket(listen_sock);
        WSACleanup();
        return;
    }

    std::cout << "HTTP server running at http://localhost:8080\n";

    // Open the default browser automatically
    ShellExecuteA(nullptr, "open", "http://localhost:8080", nullptr, nullptr, SW_SHOWNORMAL);



    bool running = true;
    while (running) {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
        if (client_sock == INVALID_SOCKET) continue;

        char buffer[4096];
        int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            closesocket(client_sock);
            continue;
        }

        std::string request(buffer, bytes);
        // std::cout << request << std::endl;

        // Parse request path
        std::string path = "/";
        size_t pos = request.find(" ");
        if (pos != std::string::npos) {
            size_t pos2 = request.find(" ", pos + 1);
            if (pos2 != std::string::npos) {
                path = request.substr(pos + 1, pos2 - pos - 1);
            }
        }

        // Serve API JSON
        if (path == "/api/threads") {
            std::string jsonResponse = exportMailboxJson(indicies, threadInfo).dump();

            std::string response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + std::to_string(jsonResponse.size()) + "\r\n"
                "Connection: close\r\n\r\n" +
                jsonResponse;

            send(client_sock, response.c_str(), response.size(), 0);
            closesocket(client_sock);
            running = false;

            TimePoint end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> diff = end - *start;
            std::cout << "Elapsed time: " << diff.count() << " seconds\n";

            continue;
        }


        if (path == "/shutdown") {
            std::string ok =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send(client_sock, ok.c_str(), ok.size(), 0);
            running = false;
            closesocket(client_sock);
            break;
        }

        // Map request to file
        // if (path == "/") path = "/index.html";
        if (path == "/") path = "/index.html";
        std::string filePath = "../public" + path;




        // Load static file
        FILE* file = fopen(filePath.c_str(), "rb");
        if (!file) {
            std::string notFound =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n\r\n";
            send(client_sock, notFound.c_str(), notFound.size(), 0);
            closesocket(client_sock);
            continue;
        }

        fseek(file, 0, SEEK_END);
        long fileLen = ftell(file);
        fseek(file, 0, SEEK_SET);

        std::string fileData(fileLen, '\0');
        fread(&fileData[0], 1, fileLen, file);
        fclose(file);

        std::string contentType = "text/plain";

        // c20
        // if (path.ends_with(".html")) contentType = "text/html";
        // else if (path.ends_with(".css")) contentType = "text/css";
        // else if (path.ends_with(".js")) contentType = "application/javascript";

        // c1-14 and later
        if (path.size() >= 5 && path.rfind(".html") == path.size() - 5) contentType = "text/html";
        else if (path.size() >= 4 && path.rfind(".css") == path.size() - 4) contentType = "text/css";
        else if (path.size() >= 3 && path.rfind(".js") == path.size() - 3) contentType = "application/javascript";


        std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: " + contentType + "\r\n"
            "Content-Length: " + std::to_string(fileData.size()) + "\r\n"
            "Connection: close\r\n\r\n" +
            fileData;

        send(client_sock, response.c_str(), response.size(), 0);
    }

    closesocket(listen_sock);
    WSACleanup();
    return;
}
































































// forward declaration
// void ShowThreadListGUI(std::vector<ThreadInfo>& threadResults);
// void runServer(const Indicies indicies, std::unordered_map<std::string, ThreadInfo> threadInfo, TimePoint start, int port = 8080);



std::string cleanToField(const std::string* v) {
    std::string ans;
    const std::string& value = *v;
    
    int i = 0;
    while (i < value.size() && value[i] != '@') ++i;

    if (i == value.size()) return ans;

    while (i > 0 && value[i-1] != ' ' && value[i-1] != '<' && value[i-1] != '\"') --i;

    while (i < value.size() && value[i] != ' ' && value[i] != '>' && value[i] != '\"') ans += value[i++];

    return ans;
}



void labelParser(std::unordered_map<std::string, ThreadInfo>* threadInfo, Indicies* indicies) {
    for (auto& [_, t] : *threadInfo) {

        ThreadID tId = {t.threadId, t.messages.back().internalDate};

        // bool isInbox = false;
        bool hasCategory = false;
        bool isUnread = false;

        for (auto& m : t.messages) {
            for (std::string& l : m.labelIds) {
                // indicies->everything.insert(tId);

                if (l == "UNREAD")  {
                    if (m.internalDate == t.threadDate) t.read = false;
                }

                // else if (l == "INBOX") isInbox = true;

                else if (l == "IMPORTANT")   indicies->Important.insert(tId);
                else if (l == "STARRED")     indicies->Starred.insert(tId);
                else if (l == "SENT")        indicies->Sent.insert(tId);
                else if (l == "DRAFT")       indicies->Draft.insert(tId);
                else if (l == "SPAM")        indicies->Spam.insert(tId);
                else if (l == "CHAT")        indicies->Chat.insert(tId);
                else if (l == "SNOOZED")     indicies->Snoozed.insert(tId);
                else if (l == "TRASH")       indicies->Trash.insert(tId);

                // Category labels:
                else if (l == "CATEGORY_SOCIAL") {
                    indicies->inbox.Social.insert(tId);
                    hasCategory = true;
                }
                else if (l == "CATEGORY_PROMOTIONS") {
                    indicies->inbox.Promotions.insert(tId);
                    hasCategory = true;
                }
                else if (l == "CATEGORY_FORUMS") {
                    indicies->inbox.Forums.insert(tId);
                    hasCategory = true;
                }
            }
        }

        // ⭐ PRIMARY LOGIC FIX ⭐
        // If msg is in INBOX but has no category, put it into PRIMARY
        if (!hasCategory)
            indicies->inbox.Primary.insert(tId);

    }
}



std::string base64url_decode_to_string(std::string* input) {
    std::string& s = *input;

    for (char &c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    size_t pad = (4 - (s.size() % 4)) % 4;
    s.append(pad, '=');

    static unsigned char dtable[256];
    static bool inited = false;
    if (!inited) {
        std::fill(std::begin(dtable), std::end(dtable), 0x80);
        for (unsigned char i = 'A'; i <= 'Z'; ++i) dtable[i] = i - 'A';
        for (unsigned char i = 'a'; i <= 'z'; ++i) dtable[i] = i - 'a' + 26;
        for (unsigned char i = '0'; i <= '9'; ++i) dtable[i] = i - '0' + 52;
        dtable[(unsigned char)'+'] = 62;
        dtable[(unsigned char)'/'] = 63;
        dtable[(unsigned char)'='] = 0;
        inited = true;
    }

    std::string out;
    out.reserve((s.size() * 3) / 4);

    unsigned int val = 0;
    int valb = -8;
    for (unsigned char c : s) {
        if (dtable[c] & 0x80) continue;
        val = (val << 6) + dtable[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}


std::string get_access_token(const std::string* token_file) {
    std::ifstream f{*token_file};

    if (!f.is_open()) {
        std::cerr << "Cannot open token file: " << *token_file << "\n";
        return "";
    }

    json j; f >> j;

    if (!j.contains("token")) {
        std::cerr << "Token field missing in " << *token_file << "\n";
        return "";
    }

    return j["token"].get<std::string>();
}





// ------------------ SSL Helpers ------------------

SSL* createSSLConnection(const std::string* host, uint16_t port, SOCKET* out_sock, SSL_CTX* ctx) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo((*host).c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cerr << "[DEBUG] getaddrinfo failed for host " << host << "\n";
        return nullptr;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[DEBUG] Socket creation failed\n";
        freeaddrinfo(res);
        return nullptr;
    }

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "[DEBUG] Connection to " << host << " failed\n";
        freeaddrinfo(res);
        closesocket(sock);
        return nullptr;
    }
    freeaddrinfo(res);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[DEBUG] SSL_new failed\n";
        closesocket(sock);
        return nullptr;
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "[DEBUG] SSL_connect failed\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sock);
        return nullptr;
    }

    out_sock = &sock;
    return ssl;
}

// ------------------ HTTP Handling ------------------

std::string parseChunkedBody(const std::string* raw) {
    std::string result;
    size_t pos = 0;
    while (pos < raw->size()) {
        size_t endline = (*raw).find("\r\n", pos);
        if (endline == std::string::npos) break;

        std::string chunk_size_str = (*raw).substr(pos, endline - pos);
        size_t chunk_size = std::stoul(chunk_size_str, nullptr, 16);
        if (chunk_size == 0) break;

        pos = endline + 2;
        result.append(*raw, pos, chunk_size);
        pos += chunk_size + 2;
    }
    return result;
}

std::string readHttpResponse(SSL* ssl) {
    char buf[BUFFER_SIZE];
    std::string headers, body;
    bool headers_done = false;
    bool chunked = false;
    size_t content_length = 0;

    while (true) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes <= 0) break;

        std::string chunk(buf, bytes);

        if (!headers_done) {
            headers += chunk;
            size_t header_end = headers.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string hdr = headers.substr(0, header_end + 4);
                headers_done = true;

                if (hdr.find("Transfer-Encoding: chunked") != std::string::npos)
                    chunked = true;

                size_t cl_pos = hdr.find("Content-Length:");
                if (cl_pos != std::string::npos) {
                    size_t endline = hdr.find("\r\n", cl_pos);
                    std::string cl_str = hdr.substr(cl_pos + 15, endline - (cl_pos + 15));
                    content_length = std::stoul(cl_str);
                }

                body = headers.substr(header_end + 4);
            }
        } else {
            body += chunk;
        }

        if (!chunked && content_length > 0 && body.size() >= content_length) break;
        if (chunked && body.find("\r\n0\r\n\r\n") != std::string::npos) break;
    }

    if (chunked) return parseChunkedBody(&body);
    return body;
}

// ------------------ Gmail Request ------------------

void generateRequest(const std::string* token, SSL* ssl, const std::string* nextPageToken) {
    std::string req = 
        "GET /gmail/v1/users/me/messages?"
        "q=after:2025/11/24"
        "&maxResults=500" +
        ((*nextPageToken).empty() ? "" : "&pageToken=" + *nextPageToken) +
        " HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + *token + "\r\n"
        "Connection: close\r\n\r\n";

    SSL_write(ssl, req.c_str(), req.size());
}


void generateThreadRequest(const std::string* token, const std::string* thread_id, SSL* ssl) {
    std::string req =
        "GET /gmail/v1/users/me/threads/" + *thread_id + "?format=full HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + *token + "\r\n"
        "Connection: close\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
    //std::cerr << "[DEBUG] Sent thread request for " << thread_id << "\n";
}

// ------------------ Thread Parsing ------------------

std::string getThreadIDs(std::string* body, std::unordered_map<std::string, ThreadInfo>* threadInfo, const std::string* token) {
    try {
        std::string& jsonBody = *body;
        size_t start = jsonBody.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) jsonBody = jsonBody.substr(start);

        json j = json::parse(jsonBody);

        if (!j.contains("messages") || !j["messages"].is_array()) return "";

        for (const auto& msg : j["messages"]) {
            if (!msg.contains("threadId")) continue;

            std::string threadId = msg["threadId"].get<std::string>();
            if ((*threadInfo).empty() || !(*threadInfo).count(threadId)) {
                ThreadInfo t{};
                t.token = *token;
                t.threadId = threadId;
                (*threadInfo)[t.threadId] = t;
            }
        }

        return (j.contains("nextPageToken") ? j["nextPageToken"] : "");

    } catch (const std::exception& e) {
        std::cerr << "[DEBUG] Failed to parse thread list JSON: " << e.what() << "\n";
        return "";
    }
}

void populateThreadInfo(std::string* response, ThreadInfo* thread) {
    try {

        std::string& jsonBody = *response;
        size_t start = jsonBody.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) jsonBody = jsonBody.substr(start);

        json j = json::parse(jsonBody);

        if (!j.contains("messages") || !j["messages"].is_array()) return;

        if (j.contains("historyId")) (*thread).threadDate = std::stoll(j["historyId"].get<std::string>());

        for (const auto& m : j["messages"]) {
            MessageInfo msg;

            if (m.contains("id")) msg.id = m["id"].get<std::string>();
            if (m.contains("internalDate")) {
                msg.internalDate = stoll(m["internalDate"].get<std::string>());
                (*thread).threadDate = std::max((*thread).threadDate, msg.internalDate);
            }
            if (m.contains("labelIds")) {
                for (auto& lbl : m["labelIds"])
                    msg.labelIds.push_back(lbl.get<std::string>());
            }
            if (m.contains("payload")) {
                if (m["payload"].contains("headers")) {
                    for (const auto& header : m["payload"]["headers"]) {

                        const std::string name = header["name"].get<std::string>();
                        const std::string value = header["value"].get<std::string>();
                        
                        if (name == "From") {
                            msg.from = value;
                        } else if (name == "To") {
                            msg.to = cleanToField(&value);
                        } else if (name == "Subject" && msg.internalDate == (*thread).threadDate) {
                            (*thread).subject = value;
                        } else if (name == "List-Unsubscribe") {
                            (*thread).unsubscribe_link = value;
                        }
                    }
                }


                // Check top-level payload body
                if (m["payload"].contains("body")) {
                    auto& bodyObj = m["payload"]["body"];
                    std::string mimeType = m["payload"]["mimeType"].get<std::string>();

                    if (mimeType == "text/plain") {
                        msg.bodyPlain_size = bodyObj["size"].get<long long>();
                        msg.bodyPlain = bodyObj["data"].get<std::string>();
                    } 
                    else if (mimeType == "text/html") {
                        msg.bodyHtml_size = bodyObj["size"].get<long long>();
                        msg.bodyHtml = bodyObj["data"].get<std::string>();
                    }
                }

                // Then process parts if they exist
                if (m["payload"].contains("parts")) {
                    for (const auto& part : m["payload"]["parts"]) {
                        if (!part.contains("body")) continue;

                        std::string mimeType = part["mimeType"].get<std::string>();
                        if (mimeType == "text/plain") {
                            msg.bodyPlain_size = part["body"]["size"].get<long long>();
                            msg.bodyPlain = part["body"]["data"].get<std::string>();
                        }
                        else if (mimeType == "text/html") {
                            msg.bodyHtml_size = part["body"]["size"].get<long long>();
                            msg.bodyHtml = part["body"]["data"].get<std::string>();
                        }
                    }
                }









            }

            (*thread).messages.push_back(msg);
        }

    } catch (const std::exception& e) {
        std::cerr << "[DEBUG] Failed to parse thread list JSON: " << e.what() << "\n";
    }
}



void debugPrintThreads(const std::vector<ThreadInfo>& threads) {
    for (const auto& t : threads) {
        // std::cout << "Thread ID: " << t.threadId 
        //           << " | History: " << t.historyId
        //           << " | Messages: " << t.messages.size() << "\n";

        std::cout << "Thread ID: " << t.threadId << ' ';

        for (const auto& m : t.messages) {
            // std::cout << "-- Message --\n";
            if (m.from.size() < 6) std::cerr << "\nFrom: " << m.from;
            if (m.to.size() < 6) std::cerr << "\nTo: " << m.to;
            if (t.subject.size() < 6) std::cerr << "\nSubject: " << m.from;

        std::cout << "\n";
        }
    }
}




// ------------------ Main ------------------

int main() {

    TimePoint start = std::chrono::high_resolution_clock::now();

    if (system("python ../auth/auth.py")) {
        std::cerr << "User authentication failed\n";
        return 1;
    }


    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData)) {
        std::cerr << "[DEBUG] WSAStartup failed\n";
        return 1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "[DEBUG] SSL_CTX_new failed\n";
        return 1;
    }




    std::filesystem::path dir = "../tokens";
    if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
        std::cerr << "Error: Directory does not exist or is not a directory." << std::endl;
        return 1;
    }

    std::vector<std::string> token_files;

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            if (std::filesystem::is_regular_file(entry.status())) {
                token_files.push_back(entry.path().string());
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return 1;
    }



    // std::vector<std::vector<std::string>> threadIds(token_files.size());
    std::unordered_map<std::string, ThreadInfo> threadInfo;



    for (std::string token_file : token_files) {
        std::cout << token_file << std::endl;

        bool morePages = true;
        std::string nextPageToken = "";

        while (morePages) {

            SOCKET sock;
            std::string destination = "www.googleapis.com";
            SSL* ssl = createSSLConnection(&destination, 443, &sock, ctx);
            if (!ssl) {
                std::cerr << "[DEBUG] Failed to create SSL connection\n";
                return 1;
            }

            std::string token = get_access_token(&token_file);
            // std::cout << token << std::endl;

            generateRequest(&token, ssl, &nextPageToken);

            std::string response = readHttpResponse(ssl);
            // std::cout << response << std::endl;

            nextPageToken = getThreadIDs(&response, &threadInfo, &token);
            // std::cout << nextPageToken.size() << " " << nextPageToken << std::endl;
            if (!nextPageToken.size()) morePages = false;

            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(sock);
        }

    }

    std::cout << threadInfo.size() << std::endl;
    for (auto& [_, t] : threadInfo) {

        SOCKET sock;
        std::string destination = "www.googleapis.com";
        SSL* ssl = createSSLConnection(&destination, 443, &sock, ctx);
        if (!ssl) {
            std::cerr << "[DEBUG] Failed to create SSL connection\n";
            return 1;
        }


        generateThreadRequest(&t.token, &t.threadId, ssl);

        std::string response = readHttpResponse(ssl);
        // std::cout << response << std::endl;

        populateThreadInfo(&response, &t);


        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock);
    }


    Indicies indicies{};
    labelParser(&threadInfo, &indicies);


    runServer(&indicies, &threadInfo, &start, 8080);


    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}
