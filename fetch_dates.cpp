#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include "include/api_request.hpp"
#include "include/create_socket.hpp"
#include "include/http_handling.hpp"
#include "external/json.hpp"
#include <fstream>
#include <unordered_map>

using json = nlohmann::json;




std::string extract_json(const std::string& html) {
    // Search for the <script> tag containing JSON
    size_t script_pos = html.find("<script id=\"__NEXT_DATA__\" type=\"application/json\"");
    if (script_pos == std::string::npos) {
        std::cerr << "JSON <script> tag not found\n";
        return "";
    }

    // Find '>' of the opening <script> tag
    size_t start = html.find(">", script_pos);
    if (start == std::string::npos) {
        std::cerr << "Malformed <script> tag\n";
        return "";
    }
    start += 1; // skip '>'

    // Find the closing </script>
    size_t end = html.find("</script>", start);
    if (end == std::string::npos) {
        std::cerr << "No closing </script> found\n";
        return "";
    }

    return html.substr(start, end - start);
}

int main() {


    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData)) {
        std::cerr << "[DEBUG] WSAStartup failed\n";
        return 1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "[DEBUG] SSL_CTX_new failed\n";
        return 1;
    }

    SOCKET sock;
    std::string destination = "www.fotmob.com";
    SSL* ssl = create_socket::createSSLConnection(&destination, 443, &sock, ctx);
    if (!ssl) {
        std::cerr << "[DEBUG] Failed to create SSL connection\n";
        return 1;
    }


    api_request::games(ssl);
    std::string response = http_handling::readHttpResponse(ssl);
    std::string json_str = extract_json(response);

    json j = json::parse(json_str);

    json output;

    for (auto& entry : j["props"]["pageProps"]["fixtures"]["allMatches"]) {
        std::string date_raw = entry["status"]["utcTime"];
        std::string date_narrowed;
        for (char c : date_raw) {
            if (!isdigit(c) && c != '-') break;
            date_narrowed.push_back(c);
        }

        // Construct the structured object
        json match_obj;
        match_obj["id"] = entry["id"];
        match_obj["pageUrl"] = entry["pageUrl"];
        match_obj["home"] = {
            {"homeId", entry["home"]["id"]},
            {"homeName", entry["home"]["name"]}
        };
        match_obj["away"] = {
            {"awayId", entry["away"]["id"]},
            {"awayName", entry["away"]["name"]}
        };

        // Append to the array under the date
        output[date_narrowed].push_back(match_obj);
    }

    // Save to JSON file
    try {
        std::ofstream out("matches_by_time_structured.json");
        if (!out.is_open()) {
            std::cerr << "Failed to open file for writing!\n";
            return 1;
        }
        out << output.dump(4);
        out.close();
        std::cout << "JSON file successfully saved: matches_by_time_structured.json\n";
    } catch (const std::exception& e) {
        std::cerr << "Error writing JSON: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}