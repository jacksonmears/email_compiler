#include "server.h"
#include "parser.h"
#include <iostream>

int main() {
    // 1. Fetch Gmail threads
    std::vector<ThreadInfo> threads = fetchAllThreads();

    // 2. Start HTTP server with fetched threads
    runServer(threads, 8080);

    return 0;
}
