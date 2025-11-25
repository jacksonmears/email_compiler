#pragma once

#include <string>
#include <vector>
#include <set>


struct ThreadID {
    std::string id;
    long long threadDate;
};

struct ThreadSortByDateDesc {
    bool operator()(const ThreadID& a, const ThreadID& b) const { return a.threadDate > b.threadDate; }
};

struct Inbox {
    std::set<ThreadID, ThreadSortByDateDesc> Primary;
    std::set<ThreadID, ThreadSortByDateDesc> Promotions;
    std::set<ThreadID, ThreadSortByDateDesc> Social;
    std::set<ThreadID, ThreadSortByDateDesc> Forums;
};


struct MessageInfo {
    bool read = true;
    long long internalDate;
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
    long long threadDate;            
    std::string token;
};


struct Indicies {

    Inbox inbox{};
    std::set<ThreadID, ThreadSortByDateDesc> Starred;
    std::set<ThreadID, ThreadSortByDateDesc> Important;
    std::set<ThreadID, ThreadSortByDateDesc> Spam;
    std::set<ThreadID, ThreadSortByDateDesc> Sent;
    std::set<ThreadID, ThreadSortByDateDesc> Draft;
    std::set<ThreadID, ThreadSortByDateDesc> Chat;
    std::set<ThreadID, ThreadSortByDateDesc> Snoozed;
    std::set<ThreadID, ThreadSortByDateDesc> Trash;
    std::set<ThreadID, ThreadSortByDateDesc> everything;

};