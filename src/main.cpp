#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include <chrono>
#include "../include/gmail_types.hpp"
#include "../include/mailbox_export.hpp"
#include "../include/local_server.hpp"
#include "../include/parsing_utils.hpp"
#include "../include/http_handling.hpp"
#include "../include/create_socket.hpp"
#include "../include/api_request.hpp"
#include "../include/config.hpp"
#include <chrono>


using json = nlohmann::json;


std::string date_today_string() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::tm localTime;
#if defined(_WIN32) || defined(_WIN64)
    localtime_s(&localTime, &t);
#else
    localtime_r(&t, &localTime);
#endif

    std::ostringstream oss;
    oss << std::put_time(&localTime, "%Y-%m-%d");

    std::string yesterday = "2025-12-06";
    // return oss.str();
    return yesterday;
}



int matches_today_get(std::vector<json>* buffer) {
    std::ifstream inFile("matches_by_time_structured.json");
    if (!inFile) {
        std::cerr << "Failed to open JSON file.\n";
        return 1;
    }

    nlohmann::json j;
    inFile >> j;

    std::string today = date_today_string();

    if (j.contains(today)) {
        std::cout << "Matches for today (" << today << "):\n";
        for (const auto& match : j[today]) {
            buffer->push_back(match); // now we push the whole JSON object
        }
    } else {
        std::cout << "No matches for today (" << today << ")\n";
    }

    return 0;
}





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

    TimePoint start = std::chrono::high_resolution_clock::now();

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



    std::vector<json> matches;

    if (matches_today_get(&matches)) {
        std::cerr << "ERROR: getting match links from json file\n";
        return 1;
    }


    nlohmann::json finalJson;
    finalJson["games"] = nlohmann::json::array();

    for (const auto& match : matches) {
        nlohmann::json game;
        game["id"] = match["id"];
        game["pageUrl"] = match["pageUrl"];
        game["home"] = { {"id", match["home"]["homeId"]}, {"name", match["home"]["homeName"]} };
        game["away"] = { {"id", match["away"]["awayId"]}, {"name", match["away"]["awayName"]} };

        // Nested teams object with STRING keys
        std::string homeId = match["home"]["homeId"].get<std::string>();
        std::string awayId = match["away"]["awayId"].get<std::string>();

        game["teams"] = nlohmann::json::object();
        game["teams"][homeId] = {
            {"name", match["home"]["homeName"]},
            {"players", nlohmann::json::array()}
        };
        game["teams"][awayId] = {
            {"name", match["away"]["awayName"]},
            {"players", nlohmann::json::array()}
        };

        // Fetch players stats for this match
        SOCKET sock;
        SSL* ssl = create_socket::createSSLConnection(&destination, 443, &sock, ctx);
        if (!ssl) continue;

        api_request::players(ssl, match["pageUrl"]);
        std::string response = http_handling::readHttpResponse(ssl);
        std::string json_str = extract_json(response);
        nlohmann::json j = nlohmann::json::parse(json_str);
        nlohmann::json stats_players = j["props"]["pageProps"]["content"]["playerStats"];

        // Assign players to correct team (convert numeric teamId to string)
        for (const auto& [_, player] : stats_players.items()) {
            nlohmann::json playerJson;
            playerJson["id"] = player["id"];
            playerJson["name"] = player["name"];
            playerJson["shirt"] = player["shirtNumber"];
            playerJson["position"] = player["positionId"];
            playerJson["stats"] = player["stats"];

            std::string teamId = std::to_string(player["teamId"].get<int>()); // string key
            game["teams"][teamId]["players"].push_back(playerJson);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock);

        finalJson["games"].push_back(game);
    }

    server::run(finalJson, 8080);



    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    WSACleanup();
    return 0;
}
