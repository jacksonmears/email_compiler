#pragma once

#include <string>
#include <vector>
#include <optional>


struct MessageInfo {
    long long internalDate; 
    std::string id;
    std::vector<std::string> labelIDs;
    std::string from;
    std::string to;
    std::string subject;
    std::string bodyPlain;
    std::string bodyHtml;
};


struct ThreadInfo {
    std::string threadId;
    std::vector<MessageInfo> messages;
    long long latestTimestamp; 
    std::string snippet;       
    int historyId;            
    std::vector<std::string> threadLabelSummary; 
    bool isDuplicate = false;
    std::optional<MessageInfo> newest; // optional instead of raw value
};

