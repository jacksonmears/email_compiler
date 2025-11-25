#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>   // For ShellExecute
#include <iostream>
#include <string>
#include "include/threadInfo2.h"
#include "external/json.hpp"

#pragma comment(lib, "ws2_32.lib") // Link Winsock library



using json = nlohmann::json;

//////// NEED TO CHANGE TO WEBSOCKET FOR SOOOOO MANY REASONS (current reason is ability to detect when web browser is closed and we can end the exe)

json threadIdSetToJson(const std::set<ThreadID, ThreadSortByDateDesc>& s) {
    json arr = json::array();
    for (const auto& t : s) {
        arr.push_back({
            {"id", t.id},
            {"threadDate", t.threadDate}   
        });
    }
    return arr;
}


json messageToJson(const MessageInfo msg) {
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

json threadToJson(const ThreadInfo thread) {
    json j_messages = json::array();
    for (const auto& msg : thread.messages)
        j_messages.push_back(messageToJson(msg));

    return {
        {"threadId", thread.threadId},
        {"historyId", thread.threadDate},
        {"messages", j_messages}
    };
}


json exportMailboxJson(
    const Indicies indicies,
    const std::unordered_map<std::string, ThreadInfo> threadInfo)
{
    json j;

    // ----------------------
    // 1. BUCKETS
    // ----------------------
    j["buckets"] = {
        { "inbox", {
            { "Primary",    threadIdSetToJson(indicies.inbox.Primary) },
            { "Promotions", threadIdSetToJson(indicies.inbox.Promotions) },
            { "Social",     threadIdSetToJson(indicies.inbox.Social) },
            { "Forums",     threadIdSetToJson(indicies.inbox.Forums) }
        }},
        { "labels", {
            { "Important", threadIdSetToJson(indicies.Important) },
            { "Starred",   threadIdSetToJson(indicies.Starred) },
            { "Sent",      threadIdSetToJson(indicies.Sent) },
            { "Draft",     threadIdSetToJson(indicies.Draft) },
            { "Spam",      threadIdSetToJson(indicies.Spam) },
            { "Chat",      threadIdSetToJson(indicies.Chat) },
            { "Snoozed",   threadIdSetToJson(indicies.Snoozed) },
            { "Trash",     threadIdSetToJson(indicies.Trash) }
        }}
    };

    // ----------------------
    // 2. FULL THREAD DETAILS
    // ----------------------
    json threadsJson;

    for (const auto& [id, thread] : threadInfo)
        threadsJson[id] = threadToJson(thread);

    j["threads"] = threadsJson;

    return j;
}



void runServer(const Indicies indicies, const std::unordered_map<std::string, ThreadInfo> threadInfo, int port = 8080) {

    
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



    bool running = true;
    while (running) {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);
        if (client_sock == INVALID_SOCKET) continue;

        char buffer[4096];
        int bytes = recv(client_sock, buffer, sizeof(buffer), 0);
        if (bytes <= 0) {
            closesocket(client_sock);
            continue;
        }

        std::string request(buffer, bytes);
        // std::cout << request << std::endl;

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
            std::string jsonResponse = exportMailboxJson(indicies, threadInfo).dump();

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


        if (path == "/shutdown") {
            std::string ok =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send(client_sock, ok.c_str(), ok.size(), 0);
            running = false;
            closesocket(client_sock);
            break;
        }

        // Map request to file
        // if (path == "/") path = "/index.html";
        if (path == "/") path = "/i.html";
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
    }

























    closesocket(listen_sock);
    WSACleanup();
    return;
}

