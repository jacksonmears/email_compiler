#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
#include "external/json.hpp"  // https://github.com/nlohmann/json

using json = nlohmann::json;

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



int main() {
    // --- Initialize Winsock ---
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
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
        std::cout << buffer;
    }

    // --- Clean up ---
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}
