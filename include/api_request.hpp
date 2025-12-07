#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>


namespace api_request {

void games(SSL* ssl);

void players(SSL* ssl, const std::string& link_game);

}
