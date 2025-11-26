#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include "external/json.hpp"  // https://github.com/nlohmann/json
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <chrono>
#include "include/threadInfo2.h"

using json = nlohmann::json;
using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;


constexpr int BUFFER_SIZE = 4096;

// forward declaration
// void ShowThreadListGUI(std::vector<ThreadInfo>& threadResults);
void runServer(const Indicies indicies, std::unordered_map<std::string, ThreadInfo> threadInfo, TimePoint start, int port = 8080);



std::string cleanToField(const std::string& value) {
    std::string ans;
    
    int i = 0;
    while (i < value.size() && value[i] != '@') ++i;

    if (i == value.size()) return ans;

    while (i > 0 && value[i-1] != ' ' && value[i-1] != '<' && value[i-1] != '\"') --i;

    while (i < value.size() && value[i] != ' ' && value[i] != '>' && value[i] != '\"') ans += value[i++];

    return ans;
}



void labelParser(std::unordered_map<std::string, ThreadInfo>& threadInfo,
                 Indicies& indicies) 
{
    for (auto& [_, t] : threadInfo) {

        ThreadID tId = {t.threadId, t.messages.back().internalDate};

        // bool isInbox = false;
        bool hasCategory = false;
        bool isUnread = false;

        for (auto& m : t.messages) {
            for (std::string& l : m.labelIds) {
                indicies.everything.insert(tId);

                if (l == "UNREAD")  {
                    if (m.internalDate == t.threadDate) t.read = false;
                }

                // else if (l == "INBOX") isInbox = true;

                else if (l == "IMPORTANT")   indicies.Important.insert(tId);
                else if (l == "STARRED")     indicies.Starred.insert(tId);
                else if (l == "SENT")        indicies.Sent.insert(tId);
                else if (l == "DRAFT")       indicies.Draft.insert(tId);
                else if (l == "SPAM")        indicies.Spam.insert(tId);
                else if (l == "CHAT")        indicies.Chat.insert(tId);
                else if (l == "SNOOZED")     indicies.Snoozed.insert(tId);
                else if (l == "TRASH")       indicies.Trash.insert(tId);

                // Category labels:
                else if (l == "CATEGORY_SOCIAL") {
                    indicies.inbox.Social.insert(tId);
                    hasCategory = true;
                }
                else if (l == "CATEGORY_PROMOTIONS") {
                    indicies.inbox.Promotions.insert(tId);
                    hasCategory = true;
                }
                else if (l == "CATEGORY_FORUMS") {
                    indicies.inbox.Forums.insert(tId);
                    hasCategory = true;
                }
            }
        }

        // ⭐ PRIMARY LOGIC FIX ⭐
        // If msg is in INBOX but has no category, put it into PRIMARY
        if (!hasCategory)
            indicies.inbox.Primary.insert(tId);

    }
}



std::string base64url_decode_to_string(const std::string& input) {
    std::string s = input;
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


std::string get_access_token(const std::string& token_file) {
    std::ifstream f{token_file};

    if (!f.is_open()) {
        std::cerr << "Cannot open token file: " << token_file << "\n";
        return "";
    }

    json j; f >> j;

    if (!j.contains("token")) {
        std::cerr << "Token field missing in " << token_file << "\n";
        return "";
    }

    return j["token"].get<std::string>();
}





// ------------------ SSL Helpers ------------------

SSL* createSSLConnection(const std::string& host, uint16_t port, SOCKET& out_sock, SSL_CTX* ctx) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
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

    out_sock = sock;
    return ssl;
}

// ------------------ HTTP Handling ------------------

std::string parseChunkedBody(const std::string& raw) {
    std::string result;
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t endline = raw.find("\r\n", pos);
        if (endline == std::string::npos) break;

        std::string chunk_size_str = raw.substr(pos, endline - pos);
        size_t chunk_size = std::stoul(chunk_size_str, nullptr, 16);
        if (chunk_size == 0) break;

        pos = endline + 2;
        result.append(raw, pos, chunk_size);
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

    if (chunked) return parseChunkedBody(body);
    return body;
}

// ------------------ Gmail Request ------------------

// void generateRequest(const std::string& token, SSL* ssl) {
//     std::string req =
//         "GET /gmail/v1/users/me/messages?maxResults=100 HTTP/1.1\r\n"
//         "Host: www.googleapis.com\r\n"
//         "Authorization: Bearer " + token + "\r\n"
//         "Connection: close\r\n\r\n";
//     SSL_write(ssl, req.c_str(), req.size());
// }


// YYYY/MM/DD
// void generateRequest(const std::string& token, SSL* ssl, std::string& nextPageToken) {
//     std::string req =
//         "GET /gmail/v1/users/me/messages?q=after:2025/11/01" + (nextPageToken.size() ? ("&pageToken=" + nextPageToken) : "") + "HTTP/1.1\r\n"
//         "Host: www.googleapis.com\r\n"
//         "Authorization: Bearer " + token + "\r\n"
//         "Connection: close\r\n\r\n";
//     SSL_write(ssl, req.c_str(), req.size());
// }


void generateRequest(const std::string& token, SSL* ssl, std::string& nextPageToken) {
    std::string req = 
        "GET /gmail/v1/users/me/messages?"
        "q=after:2025/11/24"
        "&maxResults=500" +
        (nextPageToken.empty() ? "" : "&pageToken=" + nextPageToken) +
        " HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + token + "\r\n"
        "Connection: close\r\n\r\n";

    SSL_write(ssl, req.c_str(), req.size());
}


void generateThreadRequest(const std::string& token, const std::string& thread_id, SSL* ssl) {
    std::string req =
        "GET /gmail/v1/users/me/threads/" + thread_id + "?format=full HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + token + "\r\n"
        "Connection: close\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
    //std::cerr << "[DEBUG] Sent thread request for " << thread_id << "\n";
}

// ------------------ Thread Parsing ------------------

std::string getThreadIDs(const std::string& body, std::unordered_map<std::string, ThreadInfo>& threadInfo, std::string& token) {
    try {
        std::string jsonBody = body;
        size_t start = jsonBody.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) jsonBody = jsonBody.substr(start);

        json j = json::parse(jsonBody);

        if (!j.contains("messages") || !j["messages"].is_array()) return "";

        for (const auto& msg : j["messages"]) {
            if (!msg.contains("threadId")) continue;

            std::string threadId = msg["threadId"].get<std::string>();
            if (threadInfo.empty() || !threadInfo.count(threadId)) {
                ThreadInfo t{};
                t.token = token;
                t.threadId = threadId;
                threadInfo[t.threadId] = t;
            }
        }

        return (j.contains("nextPageToken") ? j["nextPageToken"] : "");

    } catch (const std::exception& e) {
        std::cerr << "[DEBUG] Failed to parse thread list JSON: " << e.what() << "\n";
        return "";
    }
}

void populateThreadInfo(std::string& response, ThreadInfo& t) {
    try {

        std::string jsonBody = response;
        size_t start = jsonBody.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) jsonBody = jsonBody.substr(start);

        json j = json::parse(jsonBody);

        if (!j.contains("messages") || !j["messages"].is_array()) return;

        if (j.contains("historyId")) t.threadDate = std::stoll(j["historyId"].get<std::string>());

        for (const auto& m : j["messages"]) {
            MessageInfo msg;

            if (m.contains("id")) msg.id = m["id"].get<std::string>();
            if (m.contains("internalDate")) {
                msg.internalDate = stoll(m["internalDate"].get<std::string>());
                t.threadDate = std::max(t.threadDate, msg.internalDate);
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
                            msg.to = cleanToField(value);
                        } else if (name == "Subject" && msg.internalDate == t.threadDate) {
                            t.subject = value;
                        } else if (name == "List-Unsubscribe") {
                            t.unsubscribe_link = value;
                        }
                    }
                }






                // if (m["payload"].contains("parts")) {
                //     for (const auto& part : m["payload"]["parts"]) {
                //         if (part.contains("body")) {
                //             std::string check = part["mimeType"].get<std::string>();
                //             // std::cout << check << std::endl;

                //             if (check == "text/plain") {
                //                 msg.bodyPlain_size = part["body"]["size"].get<long long>();
                //                 // msg.bodyPlain = base64url_decode_bytes(part["body"]["data"].get<std::string>());
                //                 msg.bodyPlain = part["body"]["data"].get<std::string>();
                //             } 
                //             else if (check == "text/html") {
                //                 msg.bodyHtml_size = part["body"]["size"].get<long long>();
                //                 // msg.bodyHtml = base64url_decode_bytes(part["body"]["data"].get<std::string>());
                //                 msg.bodyHtml = part["body"]["data"].get<std::string>();
                //             }
                //         }
                //     }
                // }



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

            t.messages.push_back(msg);
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

            // if (!m.bodyHtml.empty())
            //     std::cout << "[HTML Body length: " << m.bodyHtml_size << "]\n";

            // if (!m.bodyPlain.empty())
            //     std::cout << "[Plain Body length: " << m.bodyPlain_size << "]\n";
        }
    }
}




// ------------------ Main ------------------

int main() {

    TimePoint start = std::chrono::high_resolution_clock::now();

    if (system("python auth.py")) {
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




    std::filesystem::path dir = "tokens";
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
            SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
            if (!ssl) {
                std::cerr << "[DEBUG] Failed to create SSL connection\n";
                return 1;
            }

            std::string token = get_access_token(token_file);
            // std::cout << token << std::endl;

            generateRequest(token, ssl, nextPageToken);

            std::string response = readHttpResponse(ssl);
            // std::cout << response << std::endl;

            nextPageToken = getThreadIDs(response, threadInfo, token);
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
        SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
        if (!ssl) {
            std::cerr << "[DEBUG] Failed to create SSL connection\n";
            return 1;
        }


        generateThreadRequest(t.token, t.threadId, ssl);

        std::string response = readHttpResponse(ssl);
        // std::cout << response << std::endl;

        populateThreadInfo(response, t);


        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock);
    }


    Indicies indicies{};
    labelParser(threadInfo, indicies);

    // for (auto& i : indicies.inbox.Primary) {
    //     if (i.id == "19abbf07c63ee515") {
    //         std::cout << threadInfo[i.id].messages.back().from << "\n";
    //         std::cout << threadInfo[i.id].messages.back().bodyHtml << std::endl;
    //     }
    // }

    // auto& it = threadInfo["19a3b3703b3be043"];

    // for (auto& i : it.messages) {
    //     std::cout << i.id << " " << i.bodyPlain << std::endl; 
    // }


    // for (auto& [_, v] : threadInfo) {
    //     std::cout << v.unsubscribe_link << std::endl;
    // }




    runServer(indicies, threadInfo, start, 8080);


    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}
