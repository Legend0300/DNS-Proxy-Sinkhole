#include "server.hpp"

#include "dns_configurator.hpp"
#include "dns_message.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cerrno>
#include <cstddef>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <regex>

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace {

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

NativeSocket to_native(std::intptr_t value) {
#ifdef _WIN32
    return static_cast<NativeSocket>(value);
#else
    return static_cast<NativeSocket>(value);
#endif
}

std::intptr_t from_native(NativeSocket value) {
#ifdef _WIN32
    return static_cast<std::intptr_t>(value);
#else
    return static_cast<std::intptr_t>(value);
#endif
}

void close_socket(NativeSocket socket) {
#ifdef _WIN32
    if (socket != INVALID_SOCKET) {
        ::closesocket(socket);
    }
#else
    if (socket >= 0) {
        ::close(socket);
    }
#endif
}

struct WinsockInitializer {
#ifdef _WIN32
    WinsockInitializer() {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }
    ~WinsockInitializer() {
        WSACleanup();
    }
#else
    WinsockInitializer() = default;
    ~WinsockInitializer() = default;
#endif
};

bool set_timeouts(NativeSocket socket, int timeoutMs) {
#ifdef _WIN32
    DWORD value = static_cast<DWORD>(timeoutMs);
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
        return false;
    }
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
        return false;
    }
    return true;
#else
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = static_cast<suseconds_t>((timeoutMs % 1000) * 1000);
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return false;
    }
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        return false;
    }
    return true;
#endif
}

bool resolve_address(const std::string& host,
                     std::uint16_t port,
                     int family,
                     int socktype,
                     sockaddr_storage& storage,
                     socklen_t& length) {
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = (socktype == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    std::string service = std::to_string(port);
    struct addrinfo* result = nullptr;
    int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        return false;
    }
    std::memcpy(&storage, result->ai_addr, result->ai_addrlen);
    length = static_cast<socklen_t>(result->ai_addrlen);
    ::freeaddrinfo(result);
    return true;
}

std::string lowercase_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string trim_copy(std::string_view value) {
    auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) {
        return {};
    }
    auto end = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(begin, end - begin + 1));
}

} // namespace

DnsServer::DnsServer(ServerConfig config, RuleSet&& rules)
    : config_(std::move(config)), rules_(std::move(rules)), httpServer_(config_.apiPort) {
    currentMode_ = config_.mode;
    open_log_files();
    setup_http_routes();
}

DnsServer::~DnsServer() {
    running_ = false;
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

int DnsServer::run() {
    WinsockInitializer winsock;

    if (!config_.bindIPv4.empty()) {
        start_udp_listener(config_.bindIPv4, AF_INET);
        start_tcp_listener(config_.bindIPv4, AF_INET);
    }
    if (!config_.bindIPv6.empty()) {
        start_udp_listener(config_.bindIPv6, AF_INET6);
        start_tcp_listener(config_.bindIPv6, AF_INET6);
    }

    if (threads_.empty()) {
        std::cerr << "No sockets bound; exiting" << std::endl;
        return 1;
    }

    std::cout << "Mode: " << mode_to_string(config_.mode) << std::endl;
    std::cout << "  blacklist entries: " << rules_.blacklist_size() << std::endl;
    std::cout << "  whitelist entries: " << rules_.whitelist_size() << std::endl;
    std::cout << "Listening on port " << config_.port << std::endl;
    std::cout << "API Server listening on port " << config_.apiPort << std::endl;
    
    httpServer_.run();

    // Keep running until signaled
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    httpServer_.stop();

    for (auto& thread : threads_) {
        thread.join();
    }
    return 0;
}

void DnsServer::start_udp_listener(const std::string& bindAddr, int family) {
    NativeSocket socketFd = ::socket(family, SOCK_DGRAM, 0);
    if (socketFd == kInvalidSocket) {
        std::cerr << "Failed to create UDP socket for " << bindAddr << std::endl;
        return;
    }

#ifdef _WIN32
    if (family == AF_INET6) {
        DWORD v6only = 1;
        setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }
#else
    if (family == AF_INET6) {
        int v6only = 1;
        setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }
#endif

#ifdef SO_REUSEADDR
    int reuse = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

    sockaddr_storage storage;
    socklen_t length = 0;
    if (!resolve_address(bindAddr.empty() ? (family == AF_INET ? std::string("0.0.0.0") : std::string("::")) : bindAddr,
                         config_.port,
                         family,
                         SOCK_DGRAM,
                         storage,
                         length)) {
        std::cerr << "Failed to resolve bind address " << bindAddr << std::endl;
        close_socket(socketFd);
        return;
    }

    if (::bind(socketFd, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
        std::cerr << "Failed to bind UDP socket on " << bindAddr << std::endl;
        close_socket(socketFd);
        return;
    }

    std::cout << "UDP listening on " << bindAddr << ":" << config_.port << std::endl;

    threads_.emplace_back(&DnsServer::udp_loop, this, SocketHandle{from_native(socketFd), family});
}

void DnsServer::start_tcp_listener(const std::string& bindAddr, int family) {
    NativeSocket socketFd = ::socket(family, SOCK_STREAM, 0);
    if (socketFd == kInvalidSocket) {
        std::cerr << "Failed to create TCP socket for " << bindAddr << std::endl;
        return;
    }

#ifdef _WIN32
    if (family == AF_INET6) {
        DWORD v6only = 1;
        setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only));
    }
#else
    if (family == AF_INET6) {
        int v6only = 1;
        setsockopt(socketFd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }
#endif

#ifdef SO_REUSEADDR
    int reuse = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#endif

    sockaddr_storage storage;
    socklen_t length = 0;
    if (!resolve_address(bindAddr.empty() ? (family == AF_INET ? std::string("0.0.0.0") : std::string("::")) : bindAddr,
                         config_.port,
                         family,
                         SOCK_STREAM,
                         storage,
                         length)) {
        std::cerr << "Failed to resolve bind address " << bindAddr << std::endl;
        close_socket(socketFd);
        return;
    }

    if (::bind(socketFd, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
        std::cerr << "Failed to bind TCP socket on " << bindAddr << std::endl;
        close_socket(socketFd);
        return;
    }

    if (::listen(socketFd, SOMAXCONN) != 0) {
        std::cerr << "Failed to listen on TCP socket " << bindAddr << std::endl;
        close_socket(socketFd);
        return;
    }

    std::cout << "TCP listening on " << bindAddr << ":" << config_.port << std::endl;

    threads_.emplace_back(&DnsServer::tcp_loop, this, SocketHandle{from_native(socketFd), family});
}

void DnsServer::setup_http_routes() {
    // GET /
    httpServer_.register_handler("GET", "/", [this](const HttpRequest& req) {
        HttpResponse resp;
        resp.body = "{\"message\": \"DNS Proxy API\", \"endpoints\": [\"/stats\", \"/blacklist\", \"/whitelist\"]}";
        return resp;
    });

    // GET /stats
    httpServer_.register_handler("GET", "/stats", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::ostringstream oss;
        oss << "{";
        oss << "\"blacklist_count\": " << rules_.blacklist_size() << ",";
        oss << "\"whitelist_count\": " << rules_.whitelist_size();
        oss << "}";
        resp.body = oss.str();
        return resp;
    });

    // GET /blacklist
    httpServer_.register_handler("GET", "/blacklist", [this](const HttpRequest& req) {
        HttpResponse resp;
        auto list = rules_.list_blacklist();
        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < list.size(); ++i) {
            oss << "\"" << list[i] << "\"";
            if (i < list.size() - 1) oss << ",";
        }
        oss << "]";
        resp.body = oss.str();
        return resp;
    });

    // POST /blacklist
    httpServer_.register_handler("POST", "/blacklist", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::regex re("\"domain\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(req.body, match, re) && match.size() > 1) {
            std::string domain = match[1].str();
            if (rules_.add_to_blacklist(domain)) {
                resp.body = "{\"status\": \"added\", \"domain\": \"" + domain + "\"}";
            } else {
                resp.status = 400;
                resp.body = "{\"error\": \"Already exists or invalid\"}";
            }
        } else {
            resp.status = 400;
            resp.body = "{\"error\": \"Invalid JSON\"}";
        }
        return resp;
    });

    // DELETE /blacklist
    httpServer_.register_handler("DELETE", "/blacklist", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::regex re("\"domain\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(req.body, match, re) && match.size() > 1) {
            std::string domain = match[1].str();
            if (rules_.remove_from_blacklist(domain)) {
                resp.body = "{\"status\": \"removed\", \"domain\": \"" + domain + "\"}";
            } else {
                resp.status = 404;
                resp.body = "{\"error\": \"Not found\"}";
            }
        } else {
            resp.status = 400;
            resp.body = "{\"error\": \"Invalid JSON\"}";
        }
        return resp;
    });

    // POST /reload
    httpServer_.register_handler("POST", "/reload", [this](const HttpRequest& req) {
        rules_.reload();
        HttpResponse resp;
        resp.body = "{\"status\": \"reloaded\"}";
        return resp;
    });

    // DELETE /blacklist/all
    httpServer_.register_handler("DELETE", "/blacklist/all", [this](const HttpRequest& req) {
        rules_.clear_blacklist();
        HttpResponse resp;
        resp.body = "{\"status\": \"cleared\"}";
        return resp;
    });

    // POST /blacklist/bulk
    httpServer_.register_handler("POST", "/blacklist/bulk", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::vector<std::string> domains;
        std::regex re("\"([^\"]+)\"");
        auto words_begin = std::sregex_iterator(req.body.begin(), req.body.end(), re);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
            std::smatch match = *i;
            std::string match_str = match.str();
            // Remove quotes
            if (match_str.size() >= 2) {
                domains.push_back(match_str.substr(1, match_str.size() - 2));
            }
        }
        
        // Filter out keys like "domains" if the user sends {"domains": ["a", "b"]}
        // This regex is a bit loose, it matches all quoted strings.
        // A better way is to look for the array content.
        // For simplicity, let's assume the body is just a JSON array of strings: ["a.com", "b.com"]
        
        // Refined parsing for ["a", "b"]
        domains.clear();
        size_t start = req.body.find('[');
        size_t end = req.body.rfind(']');
        if (start != std::string::npos && end != std::string::npos && end > start) {
            std::string content = req.body.substr(start + 1, end - start - 1);
            std::regex item_re("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(content.begin(), content.end(), item_re);
            for (auto i = begin; i != std::sregex_iterator(); ++i) {
                domains.push_back((*i)[1].str());
            }
        }

        int added = rules_.add_to_blacklist_bulk(domains);
        std::ostringstream oss;
        oss << "{\"status\": \"added\", \"count\": " << added << "}";
        resp.body = oss.str();
        return resp;
    });

    // GET /whitelist
    httpServer_.register_handler("GET", "/whitelist", [this](const HttpRequest& req) {
        HttpResponse resp;
        auto list = rules_.list_whitelist();
        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < list.size(); ++i) {
            oss << "\"" << list[i] << "\"";
            if (i < list.size() - 1) oss << ",";
        }
        oss << "]";
        resp.body = oss.str();
        return resp;
    });

    // POST /whitelist
    httpServer_.register_handler("POST", "/whitelist", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::regex re("\"domain\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(req.body, match, re) && match.size() > 1) {
            std::string domain = match[1].str();
            if (rules_.add_to_whitelist(domain)) {
                resp.body = "{\"status\": \"added\", \"domain\": \"" + domain + "\"}";
            } else {
                resp.status = 400;
                resp.body = "{\"error\": \"Already exists or invalid\"}";
            }
        } else {
            resp.status = 400;
            resp.body = "{\"error\": \"Invalid JSON\"}";
        }
        return resp;
    });

    // DELETE /whitelist
    httpServer_.register_handler("DELETE", "/whitelist", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::regex re("\"domain\"\\s*:\\s*\"([^\"]+)\"");
        std::smatch match;
        if (std::regex_search(req.body, match, re) && match.size() > 1) {
            std::string domain = match[1].str();
            if (rules_.remove_from_whitelist(domain)) {
                resp.body = "{\"status\": \"removed\", \"domain\": \"" + domain + "\"}";
            } else {
                resp.status = 404;
                resp.body = "{\"error\": \"Not found\"}";
            }
        } else {
            resp.status = 400;
            resp.body = "{\"error\": \"Invalid JSON\"}";
        }
        return resp;
    });
    // DELETE /whitelist/all
    httpServer_.register_handler("DELETE", "/whitelist/all", [this](const HttpRequest& req) {
        rules_.clear_whitelist();
        HttpResponse resp;
        resp.body = "{\"status\": \"cleared\"}";
        return resp;
    });

    // POST /whitelist/bulk
    httpServer_.register_handler("POST", "/whitelist/bulk", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::vector<std::string> domains;
        size_t start = req.body.find('[');
        size_t end = req.body.rfind(']');
        if (start != std::string::npos && end != std::string::npos && end > start) {
            std::string content = req.body.substr(start + 1, end - start - 1);
            std::regex item_re("\"([^\"]+)\"");
            auto begin = std::sregex_iterator(content.begin(), content.end(), item_re);
            for (auto i = begin; i != std::sregex_iterator(); ++i) {
                domains.push_back((*i)[1].str());
            }
        }

        int added = rules_.add_to_whitelist_bulk(domains);
        std::ostringstream oss;
        oss << "{\"status\": \"added\", \"count\": " << added << "}";
        resp.body = oss.str();
        return resp;
    });

    // GET /mode
    httpServer_.register_handler("GET", "/mode", [this](const HttpRequest& req) {
        HttpResponse resp;
        std::string modeStr = (currentMode_ == FilterMode::Blacklist) ? "blacklist" : "whitelist";
        resp.body = "{\"mode\": \"" + modeStr + "\"}";
        return resp;
    });

    // POST /mode
    httpServer_.register_handler("POST", "/mode", [this](const HttpRequest& req) {
        HttpResponse resp;
        if (req.body.find("blacklist") != std::string::npos) {
            currentMode_ = FilterMode::Blacklist;
            resp.body = "{\"status\": \"updated\", \"mode\": \"blacklist\"}";
        } else if (req.body.find("whitelist") != std::string::npos) {
            currentMode_ = FilterMode::Whitelist;
            resp.body = "{\"status\": \"updated\", \"mode\": \"whitelist\"}";
        } else {
            resp.status = 400;
            resp.body = "{\"error\": \"Invalid mode. Use 'blacklist' or 'whitelist'\"}";
        }
        return resp;
    });

    // POST /flushdns
    httpServer_.register_handler("POST", "/flushdns", [this](const HttpRequest& req) {
        HttpResponse resp;
#ifdef _WIN32
        system("ipconfig /flushdns");
        resp.body = "{\"status\": \"flushed\"}";
#else
        resp.status = 501;
        resp.body = "{\"error\": \"Not implemented on non-Windows\"}";
#endif
        return resp;
    });
}

void DnsServer::udp_loop(SocketHandle handle) {
    NativeSocket socketFd = to_native(handle.value);
    std::vector<std::uint8_t> buffer(65536);
    while (running_) {
        sockaddr_storage clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        int received = ::recvfrom(socketFd,
#ifdef _WIN32
                                   reinterpret_cast<char*>(buffer.data()),
                                   static_cast<int>(buffer.size()),
#else
                                   buffer.data(),
                                   static_cast<int>(buffer.size()),
#endif
                                   0,
                                   reinterpret_cast<sockaddr*>(&clientAddr),
                                   &addrLen);
        if (received <= 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
#else
            if (errno == EINTR) {
                continue;
            }
#endif
            if (!running_) {
                break;
            }
            continue;
        }
        std::vector<std::uint8_t> request(buffer.begin(), buffer.begin() + received);
        auto response = process_query(request, false);
        if (!response) {
            continue;
        }
        ::sendto(socketFd,
#ifdef _WIN32
                 reinterpret_cast<const char*>(response->data()),
                 static_cast<int>(response->size()),
#else
                 response->data(),
                 static_cast<int>(response->size()),
#endif
                 0,
                 reinterpret_cast<sockaddr*>(&clientAddr),
                 addrLen);
    }
    close_socket(socketFd);
}

void DnsServer::tcp_loop(SocketHandle handle) {
    NativeSocket socketFd = to_native(handle.value);
    while (running_) {
        sockaddr_storage clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        NativeSocket client = ::accept(socketFd, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
        if (client == kInvalidSocket) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
#else
            if (errno == EINTR) {
                continue;
            }
#endif
            if (!running_) {
                break;
            }
            continue;
        }
        std::thread(&DnsServer::handle_tcp_client, this, SocketHandle{from_native(client), handle.family}).detach();
    }
    close_socket(socketFd);
}

void DnsServer::handle_tcp_client(SocketHandle client) {
    NativeSocket socketFd = to_native(client.value);
    std::uint8_t lengthBuf[2];
    if (!recv_all(client, lengthBuf, sizeof(lengthBuf))) {
        close_socket(socketFd);
        return;
    }
    std::uint16_t length = static_cast<std::uint16_t>((lengthBuf[0] << 8) | lengthBuf[1]);
    std::vector<std::uint8_t> request(length);
    if (!recv_all(client, request.data(), request.size())) {
        close_socket(socketFd);
        return;
    }

    auto response = process_query(request, true);
    if (!response) {
        response = build_servfail_response(request);
    }
    std::uint16_t respLength = static_cast<std::uint16_t>(response->size());
    std::vector<std::uint8_t> buffer;
    buffer.reserve(respLength + 2);
    buffer.push_back(static_cast<std::uint8_t>((respLength >> 8) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>(respLength & 0xFF));
    buffer.insert(buffer.end(), response->begin(), response->end());
    send_all(client, buffer.data(), buffer.size());
    close_socket(socketFd);
}

std::optional<std::vector<std::uint8_t>> DnsServer::process_query(const std::vector<std::uint8_t>& request,
                                                                  bool preferTcp) {
    DnsQuestion question;
    if (!parse_question(request, question)) {
        return build_servfail_response(request);
    }

    auto action = rules_.evaluate(currentMode_, question.name);
    if (action == RuleAction::SinkholeBlacklist) {
        log_sinkhole(question.name, "blacklist");
        return build_sinkhole_response(request, question, config_);
    }
    if (action == RuleAction::SinkholeWhitelist) {
        log_sinkhole(question.name, "whitelist");
        return build_sinkhole_response(request, question, config_);
    }
    if (action == RuleAction::AllowWhitelist) {
        log_whitelist(question.name);
    }

    auto response = query_upstreams(request, preferTcp);
    if (response) {
        return response;
    }

    return build_servfail_response(request);
}

std::optional<std::vector<std::uint8_t>> DnsServer::query_upstreams(const std::vector<std::uint8_t>& request,
                                                                    bool preferTcp) {
    if (preferTcp) {
        if (auto tcp = query_tcp_upstreams(request)) {
            return tcp;
        }
        return query_udp_upstreams(request);
    }

    if (auto udp = query_udp_upstreams(request)) {
        if (is_truncated(*udp)) {
            if (auto tcp = query_tcp_upstreams(request)) {
                return tcp;
            }
        }
        return udp;
    }
    return query_tcp_upstreams(request);
}

std::optional<std::vector<std::uint8_t>> DnsServer::query_udp_upstreams(const std::vector<std::uint8_t>& request) {
    for (const auto& upstream : config_.upstreams) {
        sockaddr_storage storage;
        socklen_t length = 0;
        int family = upstream.host.find(':') != std::string::npos ? AF_INET6 : AF_INET;
        if (!resolve_address(upstream.host, upstream.port, family, SOCK_DGRAM, storage, length)) {
            continue;
        }
        NativeSocket socketFd = ::socket(family, SOCK_DGRAM, 0);
        if (socketFd == kInvalidSocket) {
            continue;
        }
        set_timeouts(socketFd, config_.socketTimeoutMs);
        auto sendResult = ::sendto(socketFd,
#ifdef _WIN32
                                   reinterpret_cast<const char*>(request.data()),
                                   static_cast<int>(request.size()),
#else
                                   request.data(),
                                   static_cast<int>(request.size()),
#endif
                                   0,
                                   reinterpret_cast<sockaddr*>(&storage),
                                   length);
        if (sendResult <= 0) {
            close_socket(socketFd);
            continue;
        }
        std::vector<std::uint8_t> buffer(65536);
        sockaddr_storage replyAddr;
        socklen_t replyLen = sizeof(replyAddr);
        int received = ::recvfrom(socketFd,
#ifdef _WIN32
                                   reinterpret_cast<char*>(buffer.data()),
                                   static_cast<int>(buffer.size()),
#else
                                   buffer.data(),
                                   static_cast<int>(buffer.size()),
#endif
                                   0,
                                   reinterpret_cast<sockaddr*>(&replyAddr),
                                   &replyLen);
        close_socket(socketFd);
        if (received > 0) {
            return std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + received);
        }
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> DnsServer::query_tcp_upstreams(const std::vector<std::uint8_t>& request) {
    for (const auto& upstream : config_.upstreams) {
        sockaddr_storage storage;
        socklen_t length = 0;
        int family = upstream.host.find(':') != std::string::npos ? AF_INET6 : AF_INET;
        if (!resolve_address(upstream.host, upstream.port, family, SOCK_STREAM, storage, length)) {
            continue;
        }
        NativeSocket socketFd = ::socket(family, SOCK_STREAM, 0);
        if (socketFd == kInvalidSocket) {
            continue;
        }
        set_timeouts(socketFd, config_.socketTimeoutMs);
        if (::connect(socketFd, reinterpret_cast<sockaddr*>(&storage), length) != 0) {
            close_socket(socketFd);
            continue;
        }
        std::uint16_t reqLength = static_cast<std::uint16_t>(request.size());
        std::vector<std::uint8_t> payload;
        payload.reserve(request.size() + 2);
        payload.push_back(static_cast<std::uint8_t>((reqLength >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(reqLength & 0xFF));
        payload.insert(payload.end(), request.begin(), request.end());
        if (!send_all(SocketHandle{from_native(socketFd), family}, payload.data(), payload.size())) {
            close_socket(socketFd);
            continue;
        }
        std::uint8_t lengthBuf[2];
        if (!recv_all(SocketHandle{from_native(socketFd), family}, lengthBuf, sizeof(lengthBuf))) {
            close_socket(socketFd);
            continue;
        }
        std::uint16_t respLength = static_cast<std::uint16_t>((lengthBuf[0] << 8) | lengthBuf[1]);
        std::vector<std::uint8_t> response(respLength);
        if (!recv_all(SocketHandle{from_native(socketFd), family}, response.data(), response.size())) {
            close_socket(socketFd);
            continue;
        }
        close_socket(socketFd);
        return response;
    }
    return std::nullopt;
}

bool DnsServer::send_all(SocketHandle socketFd, const std::uint8_t* data, std::size_t len) {
    NativeSocket native = to_native(socketFd.value);
    std::size_t sent = 0;
    while (sent < len) {
        int result = ::send(native,
#ifdef _WIN32
                            reinterpret_cast<const char*>(data + sent),
#else
                            data + sent,
#endif
                            static_cast<int>(len - sent),
                            0);
        if (result <= 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
#else
            if (errno == EINTR) {
                continue;
            }
#endif
            return false;
        }
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

bool DnsServer::recv_all(SocketHandle socketFd, std::uint8_t* data, std::size_t len) {
    NativeSocket native = to_native(socketFd.value);
    std::size_t received = 0;
    while (received < len) {
        int result = ::recv(native,
#ifdef _WIN32
                            reinterpret_cast<char*>(data + received),
#else
                            data + received,
#endif
                            static_cast<int>(len - received),
                            0);
        if (result <= 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
#else
            if (errno == EINTR) {
                continue;
            }
#endif
            return false;
        }
        received += static_cast<std::size_t>(result);
    }
    return true;
}

void DnsServer::control_loop() {
    std::string line;
    while (running_) {
        if (!std::getline(std::cin, line)) {
            if (std::cin.eof()) {
                break;
            }
            if (std::cin.fail()) {
                std::cin.clear();
                continue;
            }
            break;
        }
        if (line.empty()) {
            continue;
        }
        handle_command(line);
    }
}

void DnsServer::handle_command(const std::string& line) {
    auto start = line.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return;
    }
    auto end = line.find_last_not_of(" \t\r\n");
    auto trimmed = line.substr(start, end - start + 1);

    std::istringstream stream(trimmed);
    std::string token;
    if (!(stream >> token)) {
        return;
    }
    auto command = lowercase_copy(token);

    if (command == "help") {
        print_help();
        return;
    }

    if (command == "reload") {
        rules_.reload();
        std::cout << "Reloaded rules. blacklist=" << rules_.blacklist_size()
                  << " whitelist=" << rules_.whitelist_size() << std::endl;
        return;
    }

    if (command == "dns") {
        std::string actionToken;
        if (!(stream >> actionToken)) {
            std::cout << "DNS command requires an action (auto|list|select|set <alias>)." << std::endl;
            return;
        }
        auto action = lowercase_copy(actionToken);
        if (action == "auto") {
            configure_default_dns_targets(config_);
            return;
        }
        if (action == "list") {
            print_dns_interface_list();
            return;
        }
        if (action == "select" || action == "menu") {
            prompt_dns_interface_selection(config_);
            return;
        }
        if (action == "set") {
            std::string alias;
            std::getline(stream, alias);
            alias = trim_copy(alias);
            if (alias.empty()) {
                std::cout << "Specify an interface alias after 'dns set'." << std::endl;
                return;
            }
            configure_dns_for_alias(config_, alias);
            return;
        }
        if (action == "help") {
            std::cout << "dns commands:" << std::endl;
            std::cout << "  dns auto          # configure Ethernet/Wi-Fi" << std::endl;
            std::cout << "  dns list          # list interfaces" << std::endl;
            std::cout << "  dns select        # interactive selection" << std::endl;
            std::cout << "  dns set <alias>   # apply to specific alias" << std::endl;
            return;
        }
        std::cout << "Unknown dns action." << std::endl;
        return;
    }

    if (command == "blacklist" || command == "whitelist") {
        bool isBlacklist = (command == "blacklist");
        std::string actionToken;
        if (!(stream >> actionToken)) {
            std::cout << "Specify action (add|remove|list)." << std::endl;
            return;
        }
        auto action = lowercase_copy(actionToken);
        if (action == "list") {
            list_entries(isBlacklist);
            return;
        }
        if (action != "add" && action != "remove") {
            std::cout << "Unknown action: " << actionToken << std::endl;
            return;
        }
        std::string domain;
        if (!(stream >> domain)) {
            std::cout << "Specify a domain." << std::endl;
            return;
        }
        bool success = false;
        if (isBlacklist) {
            success = (action == "add") ? rules_.add_to_blacklist(domain)
                                          : rules_.remove_from_blacklist(domain);
        } else {
            success = (action == "add") ? rules_.add_to_whitelist(domain)
                                          : rules_.remove_from_whitelist(domain);
        }
        if (success) {
            const char* pastTense = (action == "add") ? "added" : "removed";
            std::cout << (isBlacklist ? "Blacklist" : "Whitelist") << ' ' << pastTense
                      << ' ' << domain << std::endl;
            std::cout << "  blacklist entries: " << rules_.blacklist_size() << std::endl;
            std::cout << "  whitelist entries: " << rules_.whitelist_size() << std::endl;
        } else {
            if (action == "add") {
                std::cout << domain << " is already present." << std::endl;
            } else {
                std::cout << domain << " was not found." << std::endl;
            }
        }
        return;
    }

    std::cout << "Unknown command. Type 'help' for a list of commands." << std::endl;
}

void DnsServer::print_help() const {
    std::cout << "Commands:" << std::endl;
    std::cout << "  help" << std::endl;
    std::cout << "  reload" << std::endl;
    std::cout << "  blacklist add <domain>" << std::endl;
    std::cout << "  blacklist remove <domain>" << std::endl;
    std::cout << "  blacklist list" << std::endl;
    std::cout << "  whitelist add <domain>" << std::endl;
    std::cout << "  whitelist remove <domain>" << std::endl;
    std::cout << "  whitelist list" << std::endl;
    std::cout << "  dns <auto|list|select|set>" << std::endl;
}

void DnsServer::list_entries(bool blacklist) const {
    auto entries = blacklist ? rules_.list_blacklist() : rules_.list_whitelist();
    if (entries.empty()) {
        std::cout << (blacklist ? "Blacklist" : "Whitelist") << " is empty." << std::endl;
        return;
    }
    std::cout << (blacklist ? "Blacklist" : "Whitelist") << " entries:" << std::endl;
    for (const auto& entry : entries) {
        std::cout << "  " << entry << std::endl;
    }
}

void DnsServer::open_log_files() {
    if (!config_.blackLogFile.empty()) {
        blackLog_.open(config_.blackLogFile, std::ios::app);
        if (!blackLog_.is_open()) {
            std::cerr << "Warning: unable to open black log file: " << config_.blackLogFile << std::endl;
        }
    }
    if (!config_.whiteLogFile.empty()) {
        whiteLog_.open(config_.whiteLogFile, std::ios::app);
        if (!whiteLog_.is_open()) {
            std::cerr << "Warning: unable to open white log file: " << config_.whiteLogFile << std::endl;
        }
    }
}

void DnsServer::log_sinkhole(const std::string& domain, std::string_view reason) {
    if (!blackLog_.is_open()) {
        return;
    }
    std::lock_guard<std::mutex> lock(logMutex_);
    blackLog_ << make_timestamp() << " " << domain << " (" << reason << ")" << std::endl;
}

void DnsServer::log_whitelist(const std::string& domain) {
    if (!whiteLog_.is_open()) {
        return;
    }
    std::lock_guard<std::mutex> lock(logMutex_);
    whiteLog_ << make_timestamp() << " " << domain << std::endl;
}

std::string DnsServer::make_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &timeT);
#else
    localtime_r(&timeT, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
