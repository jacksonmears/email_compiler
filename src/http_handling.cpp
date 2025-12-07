#include "../include/http_handling.hpp"
#include "../include/config.hpp"



std::string http_handling::parseChunkedBody(const std::string* raw) {
    std::string result;
    size_t pos = 0;
    while (pos < raw->size()) {
        size_t endline = (*raw).find("\r\n", pos);
        if (endline == std::string::npos) break;

        std::string chunk_size_str = (*raw).substr(pos, endline - pos);
        size_t chunk_size = std::stoul(chunk_size_str, nullptr, 16);
        if (chunk_size == 0) break;

        pos = endline + 2;
        result.append(*raw, pos, chunk_size);
        pos += chunk_size + 2;
    }
    return result;
}

std::string http_handling::readHttpResponse(SSL* ssl) {
    char buf[BUFFER_SIZE];
    std::string headers, body;
    bool headers_done = false;
    bool chunked = false;
    size_t content_length = 0;

    while (true) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes <= 0) break;

        std::string chunk(buf, bytes);

        if (!headers_done) {
            headers += chunk;
            size_t header_end = headers.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                std::string hdr = headers.substr(0, header_end + 4);
                headers_done = true;

                if (hdr.find("Transfer-Encoding: chunked") != std::string::npos)
                    chunked = true;

                size_t cl_pos = hdr.find("Content-Length:");
                if (cl_pos != std::string::npos) {
                    size_t endline = hdr.find("\r\n", cl_pos);
                    std::string cl_str = hdr.substr(cl_pos + 15, endline - (cl_pos + 15));
                    content_length = std::stoul(cl_str);
                }

                body = headers.substr(header_end + 4);
            }
        } else {
            body += chunk;
        }

        if (!chunked && content_length > 0 && body.size() >= content_length) break;
        if (chunked && body.find("\r\n0\r\n\r\n") != std::string::npos) break;
    }

    if (chunked) return parseChunkedBody(&body);
    return body;
}