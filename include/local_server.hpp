#pragma once


#include <string>
#include <unordered_map>
#include <chrono>
#include "config.hpp"
#include "../external/json.hpp"


namespace server {

void run(nlohmann::json& json_str, int port = 8080);

}
