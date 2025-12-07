#pragma once

#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace http_handling {

std::string parseChunkedBody(const std::string* raw);

std::string readHttpResponse(SSL* ssl);

}
