#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

// Simple JSON formatter to avoid external dependencies for the demo
std::string format_json(const std::string& key, const std::string& value, bool last=false) {
    return "\"" + key + "\": \"" + value + "\"" + (last ? "" : ",");
}

int main() {
    // Gather System Info (Cross-Platform)
    const char* user = std::getenv("USER");
    if (!user) user = std::getenv("USERNAME"); // Windows
    
    // Simulating OS Info logic
    #ifdef _WIN32
    std::string os = "Windows";
    #elif __linux__
    std::string os = "Linux";
    #elif __APPLE__
    std::string os = "macOS";
    #else
    std::string os = "Unknown";
    #endif

    // manual JSON construction
    std::cout << "{" << std::endl;
    std::cout << format_json("agent", "VortexAgent v1.0") << std::endl;
    std::cout << format_json("os", os) << std::endl;
    std::cout << format_json("user", user ? user : "unknown") << std::endl;
    
    std::cout << "\"processes\": [" << std::endl;
    std::cout << "  {\"pid\": 1, \"name\": \"init\", \"user\": \"root\"}," << std::endl;
    std::cout << "  {\"pid\": 1337, \"name\": \"vortex_agent\", \"user\": \"" << (user ? user : "unknown") << "\"}" << std::endl;
    std::cout << "]," << std::endl;

    std::cout << format_json("status", "stealth_mode_active", true) << std::endl;
    std::cout << "}" << std::endl;

    return 0;
}
