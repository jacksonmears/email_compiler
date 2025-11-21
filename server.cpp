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
        {"internalDate", msg.internalDate},
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

    while (true) {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
        if (client_sock == INVALID_SOCKET) continue;

        char buffer[1024];
        int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            closesocket(client_sock);
            continue;
        }


        for (auto& t : threads) {
            for (auto& m : t.messages) {
                for (char c : m.bodyPlain) {
                    if ((c & 0x80) != 0) std::cout << "Non-ASCII char found in " << t.threadId << "\n";
                }
            }
        }

        
        std::string jsonResponse = threadsToJson(threads).dump();

        std::string response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(jsonResponse.size()) + "\r\n"
            "Connection: close\r\n"
            "\r\n" +
            jsonResponse;


        // std::string response =
        //     "HTTP/1.1 200 OK\r\n"
        //     "Content-Type: application/json\r\n"
        //     "Content-Length: " + std::to_string(11) + "\r\n"
        //     "Connection: close\r\n"
        //     "\r\n" +
        //     "Hello world";

        send(client_sock, response.c_str(), response.size(), 0);
        closesocket(client_sock);
    }

    closesocket(listen_sock);
    WSACleanup();
    return;
}

