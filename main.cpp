#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
#include "external/json.hpp"  // https://github.com/nlohmann/json

using json = nlohmann::json;

constexpr uint16_t VALID_HTTP_RESPONSE_CODE = 299;

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


    // --- Get access token ---
    std::string access_token = get_access_token("tokens/tokens0.json");
    if (access_token.empty()) {
        std::cerr << "Failed to load access token\n";
        return 1;
    }

    // --- Prepare HTTPS GET request with Authorization header ---
    std::string request =
        "GET /gmail/v1/users/me/messages?maxResults=10 HTTP/1.1\r\n"
        "Host: www.googleapis.com\r\n"
        "Authorization: Bearer " + access_token + "\r\n"
        "Connection: close\r\n\r\n";

    SSL_write(ssl, request.c_str(), request.size());

    // --- Read response ---
    char buffer[4096];
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer)-1)) > 0) {
        buffer[bytes] = '\0';


        int code = checkAuthValidation(buffer);
        if (code>VALID_HTTP_RESPONSE_CODE) {
            std::cerr << "something went wrong in the http request idk\n";
            return 1;
        }
        
        std::cout << buffer << std::endl;
    }



    // --- Clean up ---
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}
