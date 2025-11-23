#include "config.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <system_error>

namespace {
constexpr std::string_view kModeBlacklist = "blacklist";
constexpr std::string_view kModeWhitelist = "whitelist";

std::uint16_t parse_port(std::string_view value) {
    unsigned int result = 0;
    auto first = value.data();
    auto last = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(first, last, result);
    if (ec != std::errc{} || ptr != last || result > 65535U) {
        throw std::invalid_argument("invalid port value");
    }
    return static_cast<std::uint16_t>(result);
}

int parse_timeout(std::string_view value) {
    unsigned int result = 0;
    auto first = value.data();
    auto last = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(first, last, result);
    if (ec != std::errc{} || ptr != last) {
        throw std::invalid_argument("invalid timeout value");
    }
    return static_cast<int>(result);
}

FilterMode parse_mode(std::string_view value) {
    if (value == kModeBlacklist) {
        return FilterMode::Blacklist;
    }
    if (value == kModeWhitelist) {
        return FilterMode::Whitelist;
    }
    throw std::invalid_argument("mode must be blacklist or whitelist");
}

std::string normalize_bind_value(const std::string& value) {
    if (value == "none" || value == "" || value == "-" ) {
        return {};
    }
    return value;
}

Upstream parse_upstream(std::string_view value) {
    auto pos = value.find(':');
    if (pos == std::string_view::npos) {
        return Upstream{std::string(value), 53};
    }
    Upstream upstream;
    upstream.host = std::string(value.substr(0, pos));
    upstream.port = parse_port(value.substr(pos + 1));
    return upstream;
}

void print_usage() {
    std::cout << "Usage: dns_proxy [options]\n"
                 "  --mode <blacklist|whitelist>\n"
                 "  --list-file <path>\n"
                 "  --blacklist-file <path>\n"
                 "  --whitelist-file <path>\n"
                 "  --sinkhole-ipv4 <address>\n"
                 "  --sinkhole-ipv6 <address>\n"
                 "  --bind-ipv4 <address|none>\n"
                 "  --bind-ipv6 <address|none>\n"
                 "  --port <number>\n"
                 "  --timeout-ms <milliseconds>\n"
                 "  --dns-assign-ipv4 <address[,address]>\n"
                 "  --dns-assign-ipv6 <address[,address]>\n"
                 "  --black-log <path>\n"
                 "  --white-log <path>\n"
                 "  --upstream <host[:port]>\n"
                 "  --help\n";
}

} // namespace

ServerConfig parse_arguments(int argc, char** argv) {
    ServerConfig config;
    config.upstreams = {
        {"1.1.1.1", 53},
        {"1.0.0.1", 53},
        {"2606:4700:4700::1111", 53},
        {"2606:4700:4700::1001", 53},
    };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            print_usage();
            std::exit(0);
        } else if (arg == "--mode") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--mode requires a value");
            }
            config.mode = parse_mode(argv[++i]);
        } else if (arg == "--list-file") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--list-file requires a value");
            }
            config.listFile = argv[++i];
        } else if (arg == "--blacklist-file") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--blacklist-file requires a value");
            }
            config.blacklistFile = argv[++i];
        } else if (arg == "--whitelist-file") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--whitelist-file requires a value");
            }
            config.whitelistFile = argv[++i];
        } else if (arg == "--sinkhole-ipv4") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--sinkhole-ipv4 requires a value");
            }
            config.sinkholeIPv4 = argv[++i];
        } else if (arg == "--sinkhole-ipv6") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--sinkhole-ipv6 requires a value");
            }
            config.sinkholeIPv6 = argv[++i];
        } else if (arg == "--bind-ipv4") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--bind-ipv4 requires a value");
            }
            config.bindIPv4 = normalize_bind_value(argv[++i]);
        } else if (arg == "--bind-ipv6") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--bind-ipv6 requires a value");
            }
            config.bindIPv6 = normalize_bind_value(argv[++i]);
        } else if (arg == "--port") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--port requires a value");
            }
            config.port = parse_port(argv[++i]);
        } else if (arg == "--timeout-ms") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--timeout-ms requires a value");
            }
            config.socketTimeoutMs = parse_timeout(argv[++i]);
        } else if (arg == "--dns-assign-ipv4") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--dns-assign-ipv4 requires a value");
            }
            config.dnsAssignIPv4 = argv[++i];
        } else if (arg == "--dns-assign-ipv6") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--dns-assign-ipv6 requires a value");
            }
            config.dnsAssignIPv6 = argv[++i];
        } else if (arg == "--black-log") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--black-log requires a value");
            }
            config.blackLogFile = argv[++i];
        } else if (arg == "--white-log") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--white-log requires a value");
            }
            config.whiteLogFile = argv[++i];
        } else if (arg == "--upstream") {
            if (i + 1 >= argc) {
                throw std::invalid_argument("--upstream requires a value");
            }
            auto upstream = parse_upstream(argv[++i]);
            config.upstreams.push_back(std::move(upstream));
        } else {
            throw std::invalid_argument("unknown option: " + arg);
        }
    }

    if (!config.listFile.empty()) {
        if (config.mode == FilterMode::Blacklist) {
            config.blacklistFile = config.listFile;
        } else {
            config.whitelistFile = config.listFile;
        }
    }

    if (config.upstreams.empty()) {
        throw std::invalid_argument("at least one upstream resolver is required");
    }

    return config;
}

std::string mode_to_string(FilterMode mode) {
    switch (mode) {
    case FilterMode::Blacklist:
        return "blacklist";
    case FilterMode::Whitelist:
        return "whitelist";
    }
    return "unknown";
}
