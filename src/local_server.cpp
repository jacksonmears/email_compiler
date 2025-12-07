#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

#include "../include/gmail_types.hpp"
#include "../include/local_server.hpp"




void server::run(nlohmann::json& json_str, int port) {
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



        // Serve API playerInfo
        if (path == "/matchData") {

            std::string s = json_str.dump();
            std::string response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + std::to_string(s.size()) + "\r\n"
                "Connection: close\r\n\r\n" +
                s;

            send(client_sock, response.c_str(), response.size(), 0);
            closesocket(client_sock);
            running = false;
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
    }

    closesocket(listen_sock);
    WSACleanup();
    return;
}

