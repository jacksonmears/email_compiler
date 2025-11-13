#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
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

using json = nlohmann::json;
namespace fs = std::filesystem;

constexpr uint16_t VALID_HTTP_RESPONSE_CODE = 299;
constexpr int BUFFER_SIZE = 4096;

// Helper: read access token from JSON
std::string get_access_token(const std::string& token_file) {
    std::ifstream f(token_file);
    if (!f.is_open()) {
        std::cerr << "Cannot open token file: " << token_file << "\n";
        return "";
    }
    json j;
    f >> j;
    if (!j.contains("token")) {
        std::cerr << "Token field missing in " << token_file << "\n";
        return "";
    }
    return j["token"].get<std::string>();
}


SSL* createSSLConnection(const std::string& host, uint16_t port, SOCKET& out_sock) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cerr << "getaddrinfo failed\n";
        return nullptr;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        freeaddrinfo(res);
        return nullptr;
    }

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "Connection failed\n";
        freeaddrinfo(res);
        closesocket(sock);
        return nullptr;
    }
    freeaddrinfo(res);

    SSL* ssl = SSL_new(SSL_CTX_new(TLS_client_method()));
    if (!ssl) {
        std::cerr << "SSL_new failed\n";
        closesocket(sock);
        return nullptr;
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL_connect failed\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sock);
        return nullptr;
    }

    out_sock = sock;
    return ssl;
}


uint16_t checkAuthValidation(char* buffer) {
    char* it = buffer;
    while (*++it != ' ');

    ++it;

    uint16_t code = 0;
    for (int i = 0; i < 3; ++i) {
        code *= 10;
        code += *it++-'0';
    }

    return code;
}


bool cmp(char* code, char test[]) {
    for (int i = 0; code[i]!='\0'; ++i) {
        if (code[i] != test[i]) return false;
    }
    return true;
}


// --- small change here: request format=full so payload is returned ---
void generateRequest(std::string access_token, SSL* ssl) {
    std::string request =
        "GET /gmail/v1/users/me/messages?maxResults=5 HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + access_token + "\r\n"
        "Connection: keep-alive\r\n\r\n";

    SSL_write(ssl, request.c_str(), request.size());
}

// include format=full on thread fetch so Gmail returns message payloads
void generateThreadRequest(const std::string& access_token, const std::string& thread_id, SSL* ssl) {
    std::string request =
        "GET /gmail/v1/users/me/threads/" + thread_id + "?format=full HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + access_token + "\r\n"
        "Connection: keep-alive\r\n\r\n";

    SSL_write(ssl, request.c_str(), request.size());
}


void getThreadIDs(std::string& body, std::vector<std::string>& threadIDs) {

    int i = 1;
    while (body[i] != '\0') {
        if (body[i] == ',' && body[i+9] == 't') {
            std::string thread;
            i += 21;
            for (; body[i] != '\"'; ++i) thread.push_back(body[i]);
            threadIDs.push_back(thread);
        }
        ++i;
    }
}


std::string parseChunkedBody(const std::string& raw) {
    std::string result;
    size_t pos = 0;

    while (pos < raw.size()) {
        // Find the end of the chunk size line
        size_t endline = raw.find("\r\n", pos);
        if (endline == std::string::npos) break;

        // Get chunk size in hex
        std::string chunk_size_str = raw.substr(pos, endline - pos);
        size_t chunk_size = std::stoul(chunk_size_str, nullptr, 16);

        if (chunk_size == 0) break;  // end of body

        pos = endline + 2; // move past CRLF

        // Append chunk data
        result.append(raw, pos, chunk_size);

        pos += chunk_size + 2; // skip chunk and CRLF
    }

    return result;
}


std::string readHttpResponse(SSL* ssl) {
    char buf[BUFFER_SIZE];
    std::string response;
    bool chunked = false;
    size_t content_length = 0;

    // Step 1: Read until headers end
    while (true) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes <= 0) break;
        response.append(buf, bytes);

        size_t header_end = response.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            std::string headers = response.substr(0, header_end + 4);

            // Check for Transfer-Encoding: chunked
            if (headers.find("Transfer-Encoding: chunked") != std::string::npos) {
                chunked = true;
            }

            // Check for Content-Length
            size_t cl_pos = headers.find("Content-Length:");
            if (cl_pos != std::string::npos) {
                size_t endline = headers.find("\r\n", cl_pos);
                std::string cl_str = headers.substr(cl_pos + 15, endline - (cl_pos + 15));
                content_length = std::stoul(cl_str);
            }

            // Remove headers, keep only body portion we already read
            response = response.substr(header_end + 4);
            break;
        }
    }

    // Step 2: Read the rest of the body
    if (chunked) {
        // Read all chunks until final "0\r\n\r\n"
        std::string raw_body = response;
        while (raw_body.find("\r\n0\r\n\r\n") == std::string::npos) {
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes <= 0) break;
            raw_body.append(buf, bytes);
        }
        return parseChunkedBody(raw_body);
    } 
    else if (content_length > 0) {
        while (response.size() < content_length) {
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes <= 0) break;
            response.append(buf, bytes);
        }
        return response;
    } 
    else {
        // Fallback: read until connection closes
        int bytes;
        while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            response.append(buf, bytes);
        }
        return response;
    }
}

std::mutex cout_mutex;

// ------------------ new helpers for base64url decode + HTML extraction + display ------------------

// Convert base64url string to bytes
std::vector<unsigned char> base64url_decode_bytes(const std::string& input) {
    // Convert base64url -> base64
    std::string s = input;
    for (char &c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    size_t pad = (4 - (s.size() % 4)) % 4;
    s.append(pad, '=');

    // decoding table
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
    return out;
}

// Recursively search a payload part for text/html (preferred) or text/plain (fallback).
// Returns the base64url encoded data string if found.
std::optional<std::pair<std::string, std::string>> find_html_or_text_part(const json& part) {
    // returns pair<mimeType, data>
    if (!part.is_object()) return std::nullopt;

    if (part.contains("mimeType") && part.contains("body") && part["body"].contains("data")) {
        std::string mime = part["mimeType"].get<std::string>();
        std::string data = part["body"]["data"].get<std::string>();
        if (mime == "text/html") return std::make_pair(mime, data);
        if (mime == "text/plain") return std::make_pair(mime, data); // candidate
    }

    // check nested parts, prefer html
    if (part.contains("parts") && part["parts"].is_array()) {
        std::optional<std::pair<std::string, std::string>> plainCandidate;
        for (const auto &sub : part["parts"]) {
            if (!sub.is_object()) continue;
            // If sub is html, return immediately
            if (sub.contains("mimeType") && sub["mimeType"].is_string() &&
                sub["mimeType"].get<std::string>() == "text/html" &&
                sub.contains("body") && sub["body"].contains("data")) {
                return std::make_pair(std::string("text/html"), sub["body"]["data"].get<std::string>());
            }
            auto res = find_html_or_text_part(sub);
            if (res.has_value()) {
                // If res is html, return immediately; otherwise store plain as candidate.
                if (res->first == "text/html") return res;
                if (res->first == "text/plain" && !plainCandidate.has_value()) plainCandidate = res;
            }
        }
        if (plainCandidate.has_value()) return plainCandidate;
    }

    return std::nullopt;
}

// Write HTML string to unique temp file and open in default browser.
// Returns true on success.
bool write_and_open_html(const std::string &html_text, const std::string &hintName) {
    char tmpPath[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tmpPath)) return false;

    auto now = std::chrono::system_clock::now();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream ss;
    ss << tmpPath << "gmail_thread_" << hintName << "_" << millis << ".html";
    std::string path = ss.str();

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs.is_open()) return false;
    ofs.write(html_text.data(), (std::streamsize)html_text.size());
    ofs.close();

    HINSTANCE r = ShellExecuteA(NULL, "open", path.c_str(), NULL, NULL, SW_SHOWNORMAL);
    return ((intptr_t)r > 32);
}

// Given the thread JSON (response from GET /users/me/threads/{id}?format=full),
// find HTML/text parts for each message and open them in the default browser.
// threadHint used to name temp files.
void present_thread_html(const json &threadJson, const std::string &threadHint="thread") {
    if (!threadJson.contains("messages") || !threadJson["messages"].is_array()) {
        std::cerr << "No messages in thread\n";
        return;
    }

    int idx = 0;
    for (const auto &msg : threadJson["messages"]) {
        ++idx;
        if (!msg.contains("payload") || !msg["payload"].is_object()) continue;
        const auto &payload = msg["payload"];

        auto partOpt = find_html_or_text_part(payload);
        if (!partOpt.has_value()) {
            // If body is not inline, message might have an attachment body (attachmentId) - skip for now.
            continue;
        }

        std::string mime = partOpt->first;
        std::string base64url = partOpt->second;

        auto bytes = base64url_decode_bytes(base64url);
        std::string text(bytes.begin(), bytes.end());

        bool isPlain = (mime == "text/plain");
        if (isPlain) {
            std::string wrapped;
            wrapped.reserve(text.size() + 64);
            wrapped += "<html><body><pre style=\"white-space:pre-wrap;font-family:monospace;\">";
            // naive HTML-escape for safety
            for (unsigned char c : text) {
                switch (c) {
                    case '&': wrapped += "&amp;"; break;
                    case '<': wrapped += "&lt;"; break;
                    case '>': wrapped += "&gt;"; break;
                    default: wrapped.push_back((char)c); break;
                }
            }
            wrapped += "</pre></body></html>";
            text.swap(wrapped);
        }

        std::ostringstream hint;
        hint << threadHint << "_msg" << idx;
        if (!write_and_open_html(text, hint.str())) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "Failed to write/open HTML for " << threadHint << " message " << idx << "\n";
        }
    }
}

// ------------------------------------------------------------------------------------------------

void fetchThreadInfo(const std::string& token, const std::string& threadID) {
    SOCKET sock;
    SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock);
    if (!ssl) return;

    generateThreadRequest(token, threadID, ssl);
    std::string response = readHttpResponse(ssl);

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "ThreadID: " << threadID << "\n";
    }

    // Parse response body into JSON and present HTML
    try {
        // response should already be the HTTP body (your readHttpResponse strips headers)
        json threadJson = json::parse(response);
        present_thread_html(threadJson, threadID);
    } catch (const std::exception &ex) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Failed to parse thread JSON for " << threadID << ": " << ex.what() << "\n";
        // optionally print response for debugging (commented)
        // std::cerr << response << "\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
}




int main() {

    int result;
    if ((result = system("python auth.py"))) {
        std::cerr << "user authentication failed\n";
        return 1;
    }

    // --- Initialize Winsock ---
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
    }

    // --- Initialize OpenSSL ---
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed\n";
        return 1;
    }

    // --- Get access tokens ---
    std::vector<std::string> access_tokens;
    for (const auto& entry : fs::directory_iterator("tokens")) {
        if (fs::is_regular_file(entry.status())) {
            fs::path relative_path = entry.path(); 
            relative_path = fs::relative(relative_path, fs::current_path());

            std::cout << relative_path.string() << std::endl; 
            access_tokens.push_back(get_access_token(relative_path.string()));
        }
    }


    if (access_tokens.empty()) {
        std::cerr << "Failed to load access token\n";
        return 1;
    }

    std::vector<std::thread> workers;

    for (const auto &token : access_tokens) {
        // Each token needs its own connection for fetching messages
        SOCKET sock;
        SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock);
        if (!ssl) continue;

        generateRequest(token, ssl);
        std::string body = readHttpResponse(ssl);

        std::vector<std::string> threadIDs;
        getThreadIDs(body, threadIDs);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock);

        for (const std::string& threadID : threadIDs) {
            workers.emplace_back(fetchThreadInfo, token, threadID);
        }
    }

    // Wait for all threads to finish
    for (auto &t : workers) {
        t.join();
    }

    WSACleanup();

    return 0;
}
