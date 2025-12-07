#pragma once

#include <set> 
#include "../include/gmail_types.hpp"
#include "../external/json.hpp" // https://github.com/nlohmann/json


using json = nlohmann::json;


namespace mailbox_export {

json threadId(const std::set<ThreadID, ThreadSortByDateDesc>* s);

json message(const MessageInfo* msg);

json thread(const ThreadInfo* thread);

json export_mailbox(const Indicies* indicies, const std::unordered_map<std::string, ThreadInfo>* threadInfo);



}

