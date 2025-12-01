#pragma once

#include <atomic>
#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <mutex>

#include "config.hpp"
#include "rules.hpp"
#include "http_server.hpp"

class DnsServer {
public:
    DnsServer(ServerConfig config, RuleSet&& rules);
    ~DnsServer();

    int run();

private:
    struct SocketHandle {
        std::intptr_t value = -1;
        int family = 0;

        [[nodiscard]] bool valid() const noexcept { return value != -1; }
    };

    void start_udp_listener(const std::string& bindAddr, int family);
    void start_tcp_listener(const std::string& bindAddr, int family);

    void udp_loop(SocketHandle handle);
    void tcp_loop(SocketHandle handle);

    void handle_tcp_client(SocketHandle client);

    void setup_http_routes();

    std::optional<std::vector<std::uint8_t>> process_query(const std::vector<std::uint8_t>& request,
                                                           bool preferTcp);

    std::optional<std::vector<std::uint8_t>> query_upstreams(const std::vector<std::uint8_t>& request,
                                                             bool preferTcp);

    std::optional<std::vector<std::uint8_t>> query_udp_upstreams(const std::vector<std::uint8_t>& request);

    std::optional<std::vector<std::uint8_t>> query_tcp_upstreams(const std::vector<std::uint8_t>& request);

    static bool send_all(SocketHandle socketFd, const std::uint8_t* data, std::size_t len);
    static bool recv_all(SocketHandle socketFd, std::uint8_t* data, std::size_t len);

    void control_loop();
    void handle_command(const std::string& line);
    void print_help() const;
    void list_entries(bool blacklist) const;

    void open_log_files();
    void log_sinkhole(const std::string& domain, std::string_view reason);
    void log_whitelist(const std::string& domain);
    static std::string make_timestamp();

    ServerConfig config_;
    std::atomic<FilterMode> currentMode_; // Thread-safe mode
    RuleSet rules_;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_{true};
    mutable std::mutex logMutex_;
    std::ofstream blackLog_;
    std::ofstream whiteLog_;

    HttpServer httpServer_{8080}; // Default port, can be changed in config
};
