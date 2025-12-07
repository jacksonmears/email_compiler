#include "../include/create_socket.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>





SSL* create_socket::createSSLConnection(const std::string* host, uint16_t port, SOCKET* out_sock, SSL_CTX* ctx) {
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

    // Set SNI
    if (!SSL_set_tlsext_host_name(ssl, host->c_str())) {
        std::cerr << "[DEBUG] SSL_set_tlsext_host_name failed\n";
        SSL_free(ssl);
        closesocket(sock);
        return nullptr;
    }

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "[DEBUG] SSL_connect failed\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sock);
        return nullptr;
    }


    *out_sock = sock;
    return ssl;
}