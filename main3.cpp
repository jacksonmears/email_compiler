#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include "external/json.hpp"  // https://github.com/nlohmann/json
#include <thread>
#include <mutex>
#include <vector>
#include <optional>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <windows.h>
#include <shellapi.h>
#include "include/threadInfo.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

constexpr uint16_t VALID_HTTP_RESPONSE_CODE = 299;
constexpr int BUFFER_SIZE = 4096;

std::mutex cout_mutex;
std::mutex storage_mutex;

// Forward declaration
void ShowThreadListGUI(const std::vector<ThreadInfo>& threads);

// ------------------ Utility ------------------

std::string get_access_token(const std::string& token_file) {
    std::ifstream f(token_file);
    if (!f.is_open()) {
        std::cerr << "[DEBUG] Cannot open token file: " << token_file << "\n";
        return "";
    }
    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        std::cerr << "[DEBUG] Failed to parse JSON from token file " << token_file << ": " << e.what() << "\n";
        return "";
    }
    if (!j.contains("token")) {
        std::cerr << "[DEBUG] Token field missing in " << token_file << "\n";
        return "";
    }
    //std::cerr << "[DEBUG] Token loaded from " << token_file << "\n";
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
    //std::cerr << "[DEBUG] SSL connection established to " << host << ":" << port << "\n";
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

                // check for chunked
                if (hdr.find("Transfer-Encoding: chunked") != std::string::npos) {
                    chunked = true;
                }

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

        // stop if body complete
        if (!chunked && content_length > 0 && body.size() >= content_length) break;
        if (chunked && body.find("\r\n0\r\n\r\n") != std::string::npos) break;
    }

    if (chunked) return parseChunkedBody(body);
    return body;
}





// std::string readHttpResponse(SSL* ssl) {
//     char buf[BUFFER_SIZE];
//     std::string response;
//     bool chunked = false;
//     size_t content_length = 0;

//     //std::cerr << "[DEBUG] Starting to read HTTP response\n";

//     // --- Read headers ---
//     while (true) {
//         int bytes = SSL_read(ssl, buf, sizeof(buf));
//         if (bytes <= 0) {
//             //std::cerr << "[DEBUG] SSL_read returned " << bytes << " while reading headers\n";
//             break;
//         }
//         response.append(buf, bytes);
//         size_t header_end = response.find("\r\n\r\n");
//         if (header_end != std::string::npos) {
//             std::string headers = response.substr(0, header_end + 4);
//             if (headers.find("Transfer-Encoding: chunked") != std::string::npos)
//                 chunked = true;

//             size_t cl_pos = headers.find("Content-Length:");
//             if (cl_pos != std::string::npos) {
//                 size_t endline = headers.find("\r\n", cl_pos);
//                 std::string cl_str = headers.substr(cl_pos + 15, endline - (cl_pos + 15));
//                 content_length = std::stoul(cl_str);
//             }

//             response = response.substr(header_end + 4);

//             // --- DEBUG: print headers and HTTP status ---
//             std::cerr << "[DEBUG] Headers read:\n" << headers << "\n";
//             size_t code_pos = headers.find("HTTP/");
//             if (code_pos != std::string::npos) {
//                 int code = std::stoi(headers.substr(code_pos + 9, 3));
//                 std::cerr << "[DEBUG] HTTP response code: " << code << "\n";
//             }


//             break;
//         }
//     }

//     std::cerr << "[DEBUG] Headers read. chunked=" << chunked << ", content_length=" << content_length << "\n";

//     // --- Read body ---
//     if (chunked) {
//         std::string raw_body = response;
//         while (raw_body.find("\r\n0\r\n\r\n") == std::string::npos) {
//             int bytes = SSL_read(ssl, buf, sizeof(buf));
//             if (bytes <= 0) break;
//             raw_body.append(buf, bytes);
//         }
//         return parseChunkedBody(raw_body);
//     } else if (content_length > 0) {
//         while (response.size() < content_length) {
//             int bytes = SSL_read(ssl, buf, sizeof(buf));
//             if (bytes <= 0) break;
//             response.append(buf, bytes);
//         }
//         return response;
//     } else {
//         int bytes;
//         while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
//             response.append(buf, bytes);
//         }
//         return response;
//     }
// }

void generateRequest(const std::string& token, SSL* ssl) {
    std::string req =
        "GET /gmail/v1/users/me/messages?maxResults=50 HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + token + "\r\n"
        "Connection: keep-alive\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
    //std::cerr << "[DEBUG] Sent list messages request\n";
}

void generateThreadRequest(const std::string& token, const std::string& thread_id, SSL* ssl) {
    std::string req =
        "GET /gmail/v1/users/me/threads/" + thread_id + "?format=full HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + token + "\r\n"
        "Connection: keep-alive\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
    //std::cerr << "[DEBUG] Sent thread request for " << thread_id << "\n";
}

// ------------------ Gmail Thread Parsing ------------------

// void getThreadIDs(std::string& body, std::vector<std::string>& threadIDs) {
//     int i = 1;
//     while (i < (int)body.size()) {
//         if (body[i] == ',' && body[i + 9] == 't') {
//             std::string thread;
//             i += 21;
//             for (; i < (int)body.size() && body[i] != '"'; ++i)
//                 thread.push_back(body[i]);
//             threadIDs.push_back(thread);
//             //std::cerr << "[DEBUG] Found thread ID: " << thread << "\n";
//         }
//         ++i;
//     }
// }


void getThreadIDs(const std::string& body, std::vector<std::string>& threadIDs) {
    try {
        std::string jsonBody = body; // make a mutable copy
        size_t start = jsonBody.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) jsonBody = jsonBody.substr(start);

        json j = json::parse(jsonBody);

        if (!j.contains("messages") || !j["messages"].is_array()) return;

        for (const auto& msg : j["messages"]) {
            if (msg.contains("threadId")) {
                threadIDs.push_back(msg["threadId"].get<std::string>());
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[DEBUG] Failed to parse thread list JSON: " << e.what() << "\n";
    }
}



// ------------------ Base64url Decode ------------------

std::vector<unsigned char> base64url_decode_bytes(const std::string& input) {
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

    std::vector<unsigned char> out;
    out.reserve((s.size() * 3) / 4);

    unsigned int val = 0;
    int valb = -8;
    for (unsigned char c : s) {
        if (dtable[c] & 0x80) continue;
        val = (val << 6) + dtable[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((unsigned char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    //std::cerr << "[DEBUG] Decoded base64url string of size " << out.size() << "\n";
    return out;
}

std::string base64url_decode_string(const std::string& input) {
    std::vector<unsigned char> bytes = base64url_decode_bytes(input);
    return std::string(bytes.begin(), bytes.end());
}

// ------------------ MIME / HTML Handling ------------------

std::optional<std::pair<std::string, std::string>> find_html_or_text_part(const json& part) {
    if (!part.is_object()) return std::nullopt;

    if (part.contains("mimeType") && part.contains("body") && part["body"].contains("data")) {
        std::string mime = part["mimeType"].get<std::string>();
        std::string data = part["body"]["data"].get<std::string>();
        if (mime == "text/html" || mime == "text/plain")
            return std::make_pair(mime, data);
    }

    if (part.contains("parts") && part["parts"].is_array()) {
        std::optional<std::pair<std::string, std::string>> plainCandidate;
        for (const auto& sub : part["parts"]) {
            auto res = find_html_or_text_part(sub);
            if (res.has_value()) {
                if (res->first == "text/html") return res;
                if (!plainCandidate.has_value()) plainCandidate = res;
            }
        }
        return plainCandidate;
    }
    return std::nullopt;
}

// ------------------ HTML Rendering ------------------

bool write_and_open_combined_html(const std::string& html_text, const std::string& hintName) {
    char tmpPath[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmpPath)) {
        std::cerr << "[DEBUG] GetTempPathA failed\n";
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream ss;
    ss << tmpPath << "gmail_thread_" << hintName << "_" << millis << ".html";
    std::string path = ss.str();

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "[DEBUG] Failed to open file for writing: " << path << "\n";
        return false;
    }
    ofs.write(html_text.data(), (std::streamsize)html_text.size());
    ofs.close();

    HINSTANCE r = ShellExecuteA(NULL, "open", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
    //std::cerr << "[DEBUG] Attempted to open HTML file: " << path << "\n";
    return ((intptr_t)r > 32);
}

void present_thread_html(const json& threadJson, const std::string& threadHint="thread") {
    if (!threadJson.contains("messages") || !threadJson["messages"].is_array()) {
        std::cerr << "[DEBUG] No messages in thread " << threadHint << "\n";
        return;
    }

    //std::cerr << "[DEBUG] Presenting thread HTML for " << threadHint << ", messages count: " << threadJson["messages"].size() << "\n";

    std::ostringstream html;
    html << "<html><head><meta charset='utf-8'><style>"
         << "body {font-family:Arial,sans-serif;background:#fafafa;}"
         << ".msg {border:1px solid #ccc;background:#fff;padding:12px;margin:12px 0;border-radius:8px;box-shadow:0 0 4px rgba(0,0,0,0.1);}"
         << ".meta {font-size:0.9em;color:#666;margin-bottom:8px;}"
         << ".sep {height:1px;background:#ddd;margin:10px 0;}"
         << "</style></head><body>";

    int idx = 0;
    for (const auto& msg : threadJson["messages"]) {
        ++idx;
        if (!msg.contains("payload")) {
            std::cerr << "[DEBUG] Message " << idx << " missing payload\n";
            continue;
        }

        const auto& payload = msg["payload"];
        std::string from, subject, date;

        if (payload.contains("headers") && payload["headers"].is_array()) {
            for (const auto& h : payload["headers"]) {
                if (!h.contains("name") || !h.contains("value")) continue;
                std::string name = h["name"];
                std::string value = h["value"];
                if (name == "From") from = value;
                else if (name == "Subject") subject = value;
                else if (name == "Date") date = value;
            }
        }

        auto partOpt = find_html_or_text_part(payload);
        if (!partOpt.has_value()) {
            std::cerr << "[DEBUG] No HTML or text part found in message " << idx << "\n";
            continue;
        }

        std::string mime = partOpt->first;
        auto bytes = base64url_decode_bytes(partOpt->second);
        std::string text(bytes.begin(), bytes.end());
        std::cerr << "[DEBUG] Decoded message " << idx << " with mime type " << mime << " and size " << bytes.size() << "\n";

        if (mime == "text/plain") {
            std::ostringstream safe;
            safe << "<pre style='white-space:pre-wrap;font-family:monospace;'>";
            for (unsigned char c : text) {
                switch (c) {
                    case '&': safe << "&amp;"; break;
                    case '<': safe << "&lt;"; break;
                    case '>': safe << "&gt;"; break;
                    default: safe << c; break;
                }
            }
            safe << "</pre>";
            text = safe.str();
        }

        html << "<div class='msg'><div class='meta'><b>Message " << idx << "</b>"
             << (from.empty() ? "" : (" | <b>From:</b> " + from))
             << (subject.empty() ? "" : (" | <b>Subject:</b> " + subject))
             << (date.empty() ? "" : (" | <b>Date:</b> " + date))
             << "</div><div class='sep'></div>" << text << "</div>";
    }

    html << "</body></html>";
    if (!write_and_open_combined_html(html.str(), threadHint))
        std::cerr << "[DEBUG] Failed to open HTML for thread " << threadHint << "\n";
}

// ------------------ Thread Fetch ------------------
void fetchThreadInfo(const std::string& token, const std::string& threadID, SSL_CTX* ctx, std::vector<ThreadInfo>& threadResults) {
    SOCKET sock;
    SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
    if (!ssl) {
        std::cerr << "[DEBUG] Failed to create SSL connection for thread " << threadID << "\n";
        return;
    }

    generateThreadRequest(token, threadID, ssl);
    std::string response = readHttpResponse(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);

    // --- Debug: first 100 chars of response ---
    std::cerr << "[DEBUG] Thread " << threadID << " response preview: "
              << response.substr(0, std::min(response.size(), size_t(100))) << "\n";

    try {
        size_t start = response.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) response = response.substr(start);

        json threadJson = json::parse(response);
        ThreadInfo threadInfo;
        threadInfo.threadId = threadID;

        if (threadJson.contains("snippet"))
            threadInfo.snippet = threadJson["snippet"].get<std::string>();

        if (threadJson.contains("historyId"))
            threadInfo.historyId = std::stoi(threadJson["historyId"].get<std::string>());

        long long latestTs = 0;

        if (threadJson.contains("messages")) {
            for (auto& m : threadJson["messages"]) {
                MessageInfo msg;

                if (m.contains("id")) msg.id = m["id"].get<std::string>();
                if (m.contains("internalDate")) {
                    msg.internalDate = std::stoll(m["internalDate"].get<std::string>());
                    if (msg.internalDate > latestTs)
                        latestTs = msg.internalDate;
                }
                if (m.contains("labelIds")) {
                    for (auto& lbl : m["labelIds"])
                        msg.labelIDs.push_back(lbl.get<std::string>());
                }
                if (m.contains("payload")) {
                    auto& payload = m["payload"];
                    if (payload.contains("headers")) {
                        for (auto& h : payload["headers"]) {
                            std::string name = h["name"];
                            std::string value = h["value"];
                            if (name == "From") msg.from = value;
                            else if (name == "To") msg.to = value;
                            else if (name == "Subject") msg.subject = value;
                        }
                    }

                    auto extractBody = [&](const json& part) {
                        if (part.contains("body") && part["body"].contains("data")) {
                            std::string encoded = part["body"]["data"].get<std::string>();
                            return base64url_decode_string(encoded);
                        }
                        return std::string();
                    };

                    if (payload.contains("parts")) {
                        for (auto& part : payload["parts"]) {
                            std::string mime = part.value("mimeType", "");
                            if (mime == "text/plain") msg.bodyPlain = extractBody(part);
                            else if (mime == "text/html") msg.bodyHtml = extractBody(part);
                        }
                    } else {
                        std::string mime = payload.value("mimeType", "");
                        if (mime == "text/plain") msg.bodyPlain = extractBody(payload);
                        else if (mime == "text/html") msg.bodyHtml = extractBody(payload);
                    }
                }

                threadInfo.messages.push_back(msg);
                if (!threadInfo.newest.has_value() || msg.internalDate > threadInfo.newest->internalDate)
                    threadInfo.newest = msg;
            }
        }

        threadInfo.latestTimestamp = latestTs;

        std::unordered_set<std::string> labelUnion;
        for (auto& msg : threadInfo.messages)
            for (auto& lbl : msg.labelIDs)
                labelUnion.insert(lbl);
        threadInfo.threadLabelSummary.assign(labelUnion.begin(), labelUnion.end());

        {
            std::lock_guard<std::mutex> lock(storage_mutex);
            threadResults.push_back(threadInfo);
        }
        std::cerr << "[DEBUG] Thread " << threadID << " processed and stored with " 
                  << threadInfo.messages.size() << " messages\n";

    } catch (const std::exception& ex) {
        std::cerr << "[DEBUG] Failed to parse thread JSON (" << threadID << "): " << ex.what() << "\n";
    }
}



// void fetchThreadInfo(const std::string& token, const std::string& threadID, SSL_CTX* ctx, std::vector<ThreadInfo>& threadResults) {
//     //std::cerr << "[DEBUG] Fetching thread info for " << threadID << "\n";

//     SOCKET sock;
//     SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
//     if (!ssl) {
//         std::cerr << "[DEBUG] Failed to create SSL connection for thread " << threadID << "\n";
//         return;
//     }

//     generateThreadRequest(token, threadID, ssl);
//     std::string response = readHttpResponse(ssl);
//     //std::cerr << "[DEBUG] HTTP response size for thread " << threadID << ": " << response.size() << "\n";

//     try {
//         size_t start = response.find_first_not_of(" \n\r\t");
//         if (start != std::string::npos) response = response.substr(start);

//         json threadJson = json::parse(response);
//         // std::cerr << "[DEBUG] Parsed JSON for thread " << threadID << "\n";

//         ThreadInfo threadInfo;
//         threadInfo.threadId = threadID;

//         if (threadJson.contains("snippet"))
//             threadInfo.snippet = threadJson["snippet"].get<std::string>();

//         if (threadJson.contains("historyId"))
//             threadInfo.historyId = std::stoi(threadJson["historyId"].get<std::string>());

//         long long latestTs = 0;

//         if (threadJson.contains("messages")) {
//             // std::cerr << "[DEBUG] Messages count for thread " << threadID << ": " << threadJson["messages"].size() << "\n";
//             for (auto& m : threadJson["messages"]) {
//                 MessageInfo msg;

//                 if (m.contains("id"))
//                     msg.id = m["id"].get<std::string>();

//                 if (m.contains("internalDate")) {
//                     msg.internalDate = std::stoll(m["internalDate"].get<std::string>());
//                     if (msg.internalDate > latestTs)
//                         latestTs = msg.internalDate;
//                 }

//                 if (m.contains("labelIds")) {
//                     for (auto& lbl : m["labelIds"])
//                         msg.labelIDs.push_back(lbl.get<std::string>());
//                 }

//                 if (m.contains("payload")) {
//                     auto& payload = m["payload"];

//                     if (payload.contains("headers")) {
//                         for (auto& h : payload["headers"]) {
//                             std::string name = h["name"].get<std::string>();
//                             std::string value = h["value"].get<std::string>();

//                             if (name == "From") msg.from = value;
//                             else if (name == "To") msg.to = value;
//                             else if (name == "Subject") msg.subject = value;
//                         }
//                     }

//                     auto extractBody = [&](const json& part) {
//                         if (part.contains("body") && part["body"].contains("data")) {
//                             std::string encoded = part["body"]["data"].get<std::string>();
//                             return base64url_decode_string(encoded);
//                         }
//                         return std::string();
//                     };

//                     if (payload.contains("parts")) {
//                         for (auto& part : payload["parts"]) {
//                             std::string mime = part.value("mimeType", "");
//                             if (mime == "text/plain") msg.bodyPlain = extractBody(part);
//                             else if (mime == "text/html") msg.bodyHtml = extractBody(part);
//                         }
//                     } else {
//                         std::string mime = payload.value("mimeType", "");
//                         if (mime == "text/plain") msg.bodyPlain = extractBody(payload);
//                         else if (mime == "text/html") msg.bodyHtml = extractBody(payload);
//                     }
//                 }

//                 threadInfo.messages.push_back(msg);
//                 if (!threadInfo.newest.has_value() || msg.internalDate > threadInfo.newest->internalDate) 
//                     threadInfo.newest = msg;
//             }
//         }

//         threadInfo.latestTimestamp = latestTs;

//         std::unordered_set<std::string> labelUnion;
//         for (auto& msg : threadInfo.messages) {
//             for (auto& lbl : msg.labelIDs)
//                 labelUnion.insert(lbl);
//         }
//         threadInfo.threadLabelSummary.assign(labelUnion.begin(), labelUnion.end());

//         {
//             std::lock_guard<std::mutex> lock(storage_mutex);
//             threadResults.push_back(threadInfo);
//         }

//         // std::cerr << "[DEBUG] Thread " << threadID << " processed and stored\n";

//     } catch (const std::exception& ex) {
//         std::lock_guard<std::mutex> lock(cout_mutex);
//         std::cerr << "[DEBUG] Failed to parse thread JSON (" << threadID << "): " << ex.what() << "\n";
//     }

//     SSL_shutdown(ssl);
//     SSL_free(ssl);
//     closesocket(sock);
//     //std::cerr << "[DEBUG] SSL connection closed for thread " << threadID << "\n";
// }

// ------------------ Main ------------------

int main() {
    std::cerr << "[DEBUG] Starting main\n";

    if (system("python auth.py")) {
        std::cerr << "[DEBUG] User authentication failed\n";
        return 1;
    }
    // std::cerr << "[DEBUG] Auth script executed successfully\n";

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
    //std::cerr << "[DEBUG] SSL context created\n";

    std::vector<std::string> tokens;
    for (const auto& entry : fs::directory_iterator("tokens"))
        if (fs::is_regular_file(entry.status())) {
            std::string tok = get_access_token(entry.path().string());
            if (!tok.empty()) tokens.push_back(tok);
        }

    if (tokens.empty()) {
        std::cerr << "[DEBUG] No tokens found\n";
        return 1;
    }

    //std::cerr << "[DEBUG] Tokens loaded, count: " << tokens.size() << "\n";

    std::vector<std::thread> workers;
    std::vector<ThreadInfo> threadResults;
    for (const auto& token : tokens) {
        SOCKET sock;
        SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
        if (!ssl) {
            std::cerr << "[DEBUG] Failed to create SSL connection for token\n";
            continue;
        }

        generateRequest(token, ssl);
        std::string body = readHttpResponse(ssl);
       // std::cerr << "[DEBUG] List messages response size: " << body.size() << "\n";

        std::vector<std::string> localThreadIDs;
        getThreadIDs(body, localThreadIDs);
        //std::cerr << "[DEBUG] Found " << localThreadIDs.size() << " threads for this token\n";

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock);

        for (const std::string& id : localThreadIDs) 
            workers.emplace_back(fetchThreadInfo, token, id, ctx, ref(threadResults));
    }

    for (auto& t : workers) t.join();
    //std::cerr << "[DEBUG] All worker threads joined, total threads fetched: " << threadResults.size() << "\n";

    sort(threadResults.begin(), threadResults.end(), 
        [](ThreadInfo& a, ThreadInfo& b){ return a.latestTimestamp > b.latestTimestamp; });

    for (size_t i = 1; i < threadResults.size(); ++i) 
        if (threadResults[i].threadId == threadResults[i-1].threadId) 
            threadResults[i].isDuplicate = true;

    std::vector<ThreadInfo> uniqueThreadIDs;
    for (ThreadInfo& t : threadResults) {
        if (!t.isDuplicate && !t.threadId.empty()) {
            uniqueThreadIDs.emplace_back(t);
        }
    }

    //std::cerr << "[DEBUG] Unique threads count: " << uniqueThreadIDs.size() << "\n";

    ShowThreadListGUI(uniqueThreadIDs);

    SSL_CTX_free(ctx);
    WSACleanup();
    std::cerr << "[DEBUG] Finished main\n";
    return 0;
}
