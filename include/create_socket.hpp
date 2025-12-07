#pragma once

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>



namespace create_socket {

SSL* createSSLConnection(const std::string* host, uint16_t port, SOCKET* out_sock, SSL_CTX* ctx);

}