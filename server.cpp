#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>   // For ShellExecute
#include <iostream>
#include <string>
#include "include/threadInfo2.h"
#include "external/json.hpp"

#pragma comment(lib, "ws2_32.lib") // Link Winsock library



using json = nlohmann::json;



json messageToJson(const MessageInfo& msg) {
    return {
        // {"internalDate", msg.internalDate},
        {"id", msg.id},
        {"labelIds", msg.labelIds},
        {"from", msg.from},
        {"to", msg.to},
        {"subject", msg.subject},
        {"bodyPlain", msg.bodyPlain}, // keep as-is, Base64URL
        {"bodyHtml", msg.bodyHtml}    // keep as-is, Base64URL
    };
}


json threadToJson(const ThreadInfo& thread) {
    json j_messages = json::array();
    for (const auto& msg : thread.messages)
        j_messages.push_back(messageToJson(msg));

    return {
        {"threadId", thread.threadId},
        {"historyId", thread.historyId},
        {"messages", j_messages}
    };
}

json threadsToJson(const std::vector<ThreadInfo>& threads) {
    json j_threads = json::array();
    for (const auto& t : threads)
        j_threads.push_back(threadToJson(t));
    return j_threads;
}


void runServer(const std::vector<ThreadInfo>& threads, int port = 8080) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listen_sock, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed\n";
        closesocket(listen_sock);
        WSACleanup();
        return;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed\n";
        closesocket(listen_sock);
        WSACleanup();
        return;
    }

    std::cout << "HTTP server running at http://localhost:8080\n";

    // Open the default browser automatically
    ShellExecuteA(nullptr, "open", "http://localhost:8080", nullptr, nullptr, SW_SHOWNORMAL);

    // while (true) {
    //     SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
    //     if (client_sock == INVALID_SOCKET) continue;

    //     char buffer[1024];
    //     int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
    //     if (bytes <= 0) {
    //         closesocket(client_sock);
    //         continue;
    //     }


    //     for (auto& t : threads) {
    //         for (auto& m : t.messages) {
    //             for (char c : m.bodyPlain) {
    //                 if ((c & 0x80) != 0) std::cout << "Non-ASCII char found in " << t.threadId << "\n";
    //             }
    //         }
    //     }

        
    //     std::string jsonResponse = threadsToJson(threads).dump();

    //     std::string response =
    //         "HTTP/1.1 200 OK\r\n"
    //         "Content-Type: application/json\r\n"
    //         "Content-Length: " + std::to_string(jsonResponse.size()) + "\r\n"
    //         "Connection: close\r\n"
    //         "\r\n" +
    //         jsonResponse;


    //     // std::string response =
    //     //     "HTTP/1.1 200 OK\r\n"
    //     //     "Content-Type: application/json\r\n"
    //     //     "Content-Length: " + std::to_string(11) + "\r\n"
    //     //     "Connection: close\r\n"
    //     //     "\r\n" +
    //     //     "Hello world";

    //     send(client_sock, response.c_str(), response.size(), 0);
    //     closesocket(client_sock);
    // }

    while (true) {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
        if (client_sock == INVALID_SOCKET) continue;

        char buffer[4096];
        int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            closesocket(client_sock);
            continue;
        }

        std::string request(buffer, bytes);
        std::cout << request << std::endl;

        // Parse request path
        std::string path = "/";
        size_t pos = request.find(" ");
        if (pos != std::string::npos) {
            size_t pos2 = request.find(" ", pos + 1);
            if (pos2 != std::string::npos) {
                path = request.substr(pos + 1, pos2 - pos - 1);
            }
        }

        // Serve API JSON
        if (path == "/api/threads") {
            std::string jsonResponse = threadsToJson(threads).dump();

            std::string response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + std::to_string(jsonResponse.size()) + "\r\n"
                "Connection: close\r\n\r\n" +
                jsonResponse;

            send(client_sock, response.c_str(), response.size(), 0);
            closesocket(client_sock);
            continue;
        }

        // Map request to file
        if (path == "/") path = "/index.html";
        std::string filePath = "public" + path;

        // Load static file
        FILE* file = fopen(filePath.c_str(), "rb");
        if (!file) {
            std::string notFound =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n\r\n";
            send(client_sock, notFound.c_str(), notFound.size(), 0);
            closesocket(client_sock);
            continue;
        }

        fseek(file, 0, SEEK_END);
        long fileLen = ftell(file);
        fseek(file, 0, SEEK_SET);

        std::string fileData(fileLen, '\0');
        fread(&fileData[0], 1, fileLen, file);
        fclose(file);

        std::string contentType = "text/plain";

        // c20
        // if (path.ends_with(".html")) contentType = "text/html";
        // else if (path.ends_with(".css")) contentType = "text/css";
        // else if (path.ends_with(".js")) contentType = "application/javascript";

        // c1-14 and later
        if (path.size() >= 5 && path.rfind(".html") == path.size() - 5) contentType = "text/html";
        else if (path.size() >= 4 && path.rfind(".css") == path.size() - 4) contentType = "text/css";
        else if (path.size() >= 3 && path.rfind(".js") == path.size() - 3) contentType = "application/javascript";


        std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: " + contentType + "\r\n"
            "Content-Length: " + std::to_string(fileData.size()) + "\r\n"
            "Connection: close\r\n\r\n" +
            fileData;

        send(client_sock, response.c_str(), response.size(), 0);
        closesocket(client_sock);
    }


    closesocket(listen_sock);
    WSACleanup();
    return;
}

