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



// char* checkAuthValidation(char* buffer) {
//     char* it = buffer;
//     while (*++it != ' ');

//     ++it;

//     char* code = new char[4];
//     code[3] = '\0';
//     for (int i = 0; i < 3; ++i) {
//         code[i] = *it++;
//     }

//     return code;
// }


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


void generateRequest(std::string access_token, SSL* ssl) {
    std::string request =
        "GET /gmail/v1/users/me/messages?maxResults=10 HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + access_token + "\r\n"
        "Connection: keep-alive\r\n\r\n";


    SSL_write(ssl, request.c_str(), request.size());
}


void generateThreadRequest(const std::string& access_token, const std::string& thread_id, SSL* ssl) {
    std::string request =
        "GET /gmail/v1/users/me/threads/" + thread_id + " HTTP/1.1\r\n"
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

// std::string readHttpResponse(SSL* ssl) {
//     char buf[BUFFER_SIZE];
//     std::string headers;
//     size_t content_length = 0;

//     // --- Step 1: Read headers ---
//     while (true) {
//         int bytes = SSL_read(ssl, buf, sizeof(buf));
//         if (bytes <= 0) break;
//         headers.append(buf, bytes);

//         size_t pos = headers.find("\r\n\r\n");
//         if (pos != std::string::npos) {
//             std::string header_only = headers.substr(0, pos + 4);

//             // --- parse Content-Length ---
//             size_t cl_pos = header_only.find("Content-Length:");
//             if (cl_pos != std::string::npos) {
//                 size_t endline = header_only.find("\r\n", cl_pos);
//                 std::string cl_str = header_only.substr(cl_pos + 15, endline - (cl_pos + 15));
//                 content_length = std::stoul(cl_str);
//             }
//             // Remove header from headers string
//             headers = headers.substr(pos + 4);
//             break;
//         }
//     }

//     // --- Step 2: Read body ---
//     while (headers.size() < content_length) {
//         int bytes = SSL_read(ssl, buf, sizeof(buf));
//         if (bytes <= 0) break;
//         headers.append(buf, bytes);
//     }

//     return headers; // full body
// }


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

void fetchThreadInfo(const std::string& token, const std::string& threadID) {
    SOCKET sock;
    SSL* ssl = createSSLConnection("www.googleapis.com", 443, sock);
    if (!ssl) return;

    generateThreadRequest(token, threadID, ssl);
    std::string response = readHttpResponse(ssl);

    // Lock console output
    static std::mutex cout_mutex;
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "ThreadID: " << threadID << "\n";
        // std::cout << response << "\n"; // optional
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


    // std::ofstream thread_file("thread_ids.txt", std::ios::app); // append mode
    // if (!thread_file.is_open()) {
    //     std::cerr << "Failed to open thread_ids.txt for writing\n";
    //     return 1;
    // }



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


    

    // for (auto s : threadIDs) {
    //     std::cout << s << std::endl;
    // }


    WSACleanup();

    return 0;
}
