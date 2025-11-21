#pragma once

#include <string>
#include <vector>


struct MessageInfo {
    std::string internalDate; 
    std::string id;
    std::vector<std::string> labelIds;
    std::string from;
    std::string to;
    std::string subject;
    long long bodyPlain_size;
    // std::vector<unsigned char> bodyPlain;
    std::string bodyPlain;
    long long bodyHtml_size;
    // std::vector<unsigned char> bodyHtml;
    std::string bodyHtml;
};


struct ThreadInfo {
    std::string threadId;
    std::vector<MessageInfo> messages;
    int historyId;            
    std::string token;
};