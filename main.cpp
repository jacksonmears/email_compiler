#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
#include "external/json.hpp"  // https://github.com/nlohmann/json

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
        "GET /gmail/v1/users/me/messages?maxResults=1 HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + access_token + "\r\n"
        "Connection: keep-alive\r\n\r\n";


    SSL_write(ssl, request.c_str(), request.size());
} 


std::string readHttpResponse(SSL* ssl) {
    char buf[BUFFER_SIZE];
    std::string headers;
    size_t content_length = 0;

    // --- Step 1: Read headers ---
    while (true) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes <= 0) break;
        headers.append(buf, bytes);

        size_t pos = headers.find("\r\n\r\n");
        if (pos != std::string::npos) {
            std::string header_only = headers.substr(0, pos + 4);

            // --- parse Content-Length ---
            size_t cl_pos = header_only.find("Content-Length:");
            if (cl_pos != std::string::npos) {
                size_t endline = header_only.find("\r\n", cl_pos);
                std::string cl_str = header_only.substr(cl_pos + 15, endline - (cl_pos + 15));
                content_length = std::stoul(cl_str);
            }
            // Remove header from headers string
            headers = headers.substr(pos + 4);
            break;
        }
    }

    // --- Step 2: Read body ---
    while (headers.size() < content_length) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes <= 0) break;
        headers.append(buf, bytes);
    }

    return headers; // full body
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

    // --- Create TCP socket ---
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }

    // --- Resolve Gmail API server ---
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo("www.googleapis.com", "443", &hints, &res) != 0) {
        std::cerr << "getaddrinfo failed\n";
        return 1;
    }

    // --- Connect ---
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "Connection failed\n";
        freeaddrinfo(res);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(res);

    // --- Wrap socket with OpenSSL ---
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL_connect failed\n";
        ERR_print_errors_fp(stderr);
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


    for (const auto &token : access_tokens) {
        generateRequest(token, ssl);
        std::string body = readHttpResponse(ssl);

        std::cout << "Response body:\n" << body << "\n\n";
    }

    // --- Prepare HTTPS GET request with Authorization header ---
    // std::vector<std::array<char, BUFFER_SIZE>> buffers(access_tokens.size());

    // for (size_t i = 0; i < access_tokens.size(); ++i) {
    //     char* buf = buffers[i].data();
    //     generateRequest(access_tokens[i], ssl);

    //     int bytes;
    //     while ((bytes = SSL_read(ssl, buf, BUFFER_SIZE - 1)) > 0) {
    //         buf[bytes] = '\0';

    //         int code = checkAuthValidation(buf);
    //         if (code > VALID_HTTP_RESPONSE_CODE) {
    //             std::cerr << "something went wrong\n";
    //             return 1;
    //         }

    //         std::cout << buf << std::endl;
    //     }
    // }



    // --- Clean up ---
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}
