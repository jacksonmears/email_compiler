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

std::mutex cout_mutex;

// ------------------ Utility ------------------

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

// ------------------ SSL Helpers ------------------

SSL* createSSLConnection(const std::string& host, uint16_t port, SOCKET& out_sock, SSL_CTX* ctx) {
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

    SSL* ssl = SSL_new(ctx);
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
    std::string response;
    bool chunked = false;
    size_t content_length = 0;

    // --- Read headers ---
    while (true) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes <= 0) break;
        response.append(buf, bytes);
        size_t header_end = response.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            std::string headers = response.substr(0, header_end + 4);
            if (headers.find("Transfer-Encoding: chunked") != std::string::npos)
                chunked = true;

            size_t cl_pos = headers.find("Content-Length:");
            if (cl_pos != std::string::npos) {
                size_t endline = headers.find("\r\n", cl_pos);
                std::string cl_str = headers.substr(cl_pos + 15, endline - (cl_pos + 15));
                content_length = std::stoul(cl_str);
            }

            response = response.substr(header_end + 4);
            break;
        }
    }

    // --- Read body ---
    if (chunked) {
        std::string raw_body = response;
        while (raw_body.find("\r\n0\r\n\r\n") == std::string::npos) {
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes <= 0) break;
            raw_body.append(buf, bytes);
        }
        return parseChunkedBody(raw_body);
    } else if (content_length > 0) {
        while (response.size() < content_length) {
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes <= 0) break;
            response.append(buf, bytes);
        }
        return response;
    } else {
        int bytes;
        while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            response.append(buf, bytes);
        }
        return response;
    }
}

void generateRequest(const std::string& token, SSL* ssl) {
    std::string req =
        "GET /gmail/v1/users/me/messages?maxResults=5 HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + token + "\r\n"
        "Connection: keep-alive\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
}

void generateThreadRequest(const std::string& token, const std::string& thread_id, SSL* ssl) {
    std::string req =
        "GET /gmail/v1/users/me/threads/" + thread_id + "?format=full HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + token + "\r\n"
        "Connection: keep-alive\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
}

// ------------------ Gmail Thread Parsing ------------------

void getThreadIDs(std::string& body, std::vector<std::string>& threadIDs) {
    int i = 1;
    while (i < (int)body.size()) {
        if (body[i] == ',' && body[i + 9] == 't') {
            std::string thread;
            i += 21;
            for (; i < (int)body.size() && body[i] != '"'; ++i)
                thread.push_back(body[i]);
            threadIDs.push_back(thread);
        }
        ++i;
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
    return out;
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

void present_thread_html(const json& threadJson, const std::string& threadHint="thread") {
    if (!threadJson.contains("messages") || !threadJson["messages"].is_array()) {
        std::cerr << "No messages in thread\n";
        return;
    }

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
        if (!msg.contains("payload")) continue;

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
        if (!partOpt.has_value()) continue;

        std::string mime = partOpt->first;
        auto bytes = base64url_decode_bytes(partOpt->second);
        std::string text(bytes.begin(), bytes.end());

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
        std::cerr << "Failed to open HTML for thread " << threadHint << "\n";
}

// ------------------ Thread Fetch ------------------

void fetchThreadInfo(const std::string& token, const std::string& threadID, SSL_CTX* ctx) {
    SOCKET sock;
    SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
    if (!ssl) return;

    generateThreadRequest(token, threadID, ssl);
    std::string response = readHttpResponse(ssl);

    try {
        // Trim leading whitespace for safety
        size_t start = response.find_first_not_of(" \n\r\t");
        if (start != std::string::npos) response = response.substr(start);

        json threadJson = json::parse(response);
        present_thread_html(threadJson, threadID);
    } catch (const std::exception& ex) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Failed to parse thread JSON (" << threadID << "): " << ex.what() << "\n";
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
}

// ------------------ Main ------------------

int main() {
    if (system("python auth.py")) {
        std::cerr << "User authentication failed\n";
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData)) return 1;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "SSL_CTX_new failed\n";
        return 1;
    }

    std::vector<std::string> tokens;
    for (const auto& entry : fs::directory_iterator("tokens"))
        if (fs::is_regular_file(entry.status()))
            tokens.push_back(get_access_token(entry.path().string()));

    if (tokens.empty()) {
        std::cerr << "No tokens found\n";
        return 1;
    }

    std::vector<std::thread> workers;
    for (const auto& token : tokens) {
        SOCKET sock;
        SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock, ctx);
        if (!ssl) continue;

        generateRequest(token, ssl);
        std::string body = readHttpResponse(ssl);
        std::vector<std::string> threadIDs;
        getThreadIDs(body, threadIDs);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock);

        for (const std::string& id : threadIDs)
            workers.emplace_back(fetchThreadInfo, token, id, ctx);
    }

    for (auto& t : workers) t.join();

    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}
