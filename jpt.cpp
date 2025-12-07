#include <iostream>
#include <fstream>
#include "external/json.hpp"

using json = nlohmann::json;

int main() {
    // Open JSON file
    std::ifstream in("match_data_pretty.json");
    if (!in.is_open()) {
        std::cerr << "Failed to open match_data_pretty.json\n";
        return 1;
    }

    json j;
    try {
        in >> j; // parse the JSON file
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse JSON: " << e.what() << "\n";
        return 1;
    }

    in.close();

    // Navigate to the player stats
    try {
        auto playerStats = j["props"]["pageProps"]["content"]["playerStats"];

        for (auto entry : playerStats) {
            std::cout << entry["name"] << std::endl;
            for (auto stats : entry["stats"]) {
                if (stats["title"] == "Top stats") {
                    auto t = stats["stats"]["Accurate passes"]["stat"];
                    std::cout << t["value"] << ' ' << t["total"] << std::endl;
                }
            }
        }


        // playerStats is usually an array of players
        // for (const auto& player : playerStats) {
        //     std::cout << "------------------------------------\n";
        //     std::cout << "ID: " << player.value("id", 0) << "\n";
        //     std::cout << "First Name: " << player.value("firstName", "") << "\n";
        //     std::cout << "Last Name: " << player.value("lastName", "") << "\n";
        //     std::cout << "Age: " << player.value("age", 0) << "\n";
        //     std::cout << "Country: " << player.value("countryName", "") << "\n";
        //     std::cout << "Market Value: " << player.value("marketValue", 0) << "\n";

        //     // Performance info (may not exist for all players)
        //     if (player.contains("performance")) {
        //         auto perf = player["performance"];
        //         if (perf.contains("fantasyScore"))
        //             std::cout << "Fantasy Score: " << perf["fantasyScore"] << "\n";
        //         if (perf.contains("seasonGoals"))
        //             std::cout << "Season Goals: " << perf["seasonGoals"] << "\n";
        //         if (perf.contains("seasonAssists"))
        //             std::cout << "Season Assists: " << perf["seasonAssists"] << "\n";
        //         if (perf.contains("seasonRating"))
        //             std::cout << "Season Rating: " << perf["seasonRating"] << "\n";
        //     }
        // }

    } catch (const std::exception& e) {
        std::cerr << "Failed to extract playerStats: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
