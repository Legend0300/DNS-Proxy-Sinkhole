#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class FilterMode {
    Blacklist,
    Whitelist
};

struct Upstream {
    std::string host;
    std::uint16_t port;
};

struct ServerConfig {
    FilterMode mode = FilterMode::Blacklist;
    std::string listFile;
    std::string blacklistFile = "blacklist.txt";
    std::string whitelistFile = "whitelist.txt";
    std::string sinkholeIPv4 = "0.0.0.0";
    std::string sinkholeIPv6 = "::";
    std::string bindIPv4 = "0.0.0.0";
    std::string bindIPv6 = "::";
    std::uint16_t port = 53;
    std::uint16_t apiPort = 8080;
    int socketTimeoutMs = 2000;
    std::string blackLogFile = "black_logs.txt";
    std::string whiteLogFile = "white_logs.txt";
    std::string dnsAssignIPv4 = "127.0.0.1";
    std::string dnsAssignIPv6 = "::1";
    std::vector<Upstream> upstreams;
};

ServerConfig parse_arguments(int argc, char** argv);

std::string mode_to_string(FilterMode mode);
