#pragma once

#include <string>
#include <unordered_map>
#include "gmail_types.hpp"


namespace parsing_utils {

std::string clean_to_field(const std::string* v);

void parse_labels(std::unordered_map<std::string, ThreadInfo>* threadInfo, Indicies* indicies);

std::string base64url_decode_to_string(std::string* input);

std::string parse_thread_id(std::string* body, std::unordered_map<std::string, ThreadInfo>* threadInfo, const std::string* token);

void parse_thread_info(std::string* response, ThreadInfo* thread);

}
