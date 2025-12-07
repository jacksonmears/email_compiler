
#include "../include/api_request.hpp"




void api_request::games(SSL* ssl) {
    std::string req =
        "GET /leagues/47/fixtures/premier-league?group=by-date&format=full HTTP/1.1\r\n"
        "Host: www.fotmob.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
}


void api_request::players(SSL* ssl, const std::string& link_game) {
    std::string req =
        "GET " + link_game + " format=full HTTP/1.1\r\n"
        "Host: www.fotmob.com\r\n"
        "Connection: keep-alive\r\n\r\n";
    SSL_write(ssl, req.c_str(), req.size());
}

