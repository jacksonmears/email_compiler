#pragma once

#include <chrono>
#include "../external/json.hpp" // https://github.com/nlohmann/json


using json = nlohmann::json;

using TimePoint = std::chrono::time_point<std::chrono::high_resolution_clock>;

constexpr int BUFFER_SIZE = 4096;