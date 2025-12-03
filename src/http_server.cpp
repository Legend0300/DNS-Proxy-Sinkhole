#include "http_server.hpp"

#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidSocket = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
using NativeSocket = int;
constexpr NativeSocket kInvalidSocket = -1;
#endif

namespace {
    void close_socket(NativeSocket s) {
#ifdef _WIN32
        ::closesocket(s);
#else
        ::close(s);
#endif
    }

    std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
}

HttpServer::HttpServer(int port) : port_(port) {}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::register_handler(const std::string& method, const std::string& path, HttpHandler handler) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    handlers_[method][path] = handler;
}

void HttpServer::run() {
    running_ = true;
    server_thread_ = std::thread(&HttpServer::accept_loop, this);
}

void HttpServer::stop() {
    running_ = false;
    if (server_socket_ != 0) {
        close_socket((NativeSocket)server_socket_);
        server_socket_ = 0;
    }
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
}

void HttpServer::accept_loop() {
    NativeSocket listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == kInvalidSocket) {
        std::cerr << "HttpServer: Failed to create socket" << std::endl;
        return;
    }

    server_socket_ = (std::uintptr_t)listen_fd;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "HttpServer: Failed to bind to port " << port_ << std::endl;
        close_socket(listen_fd);
        return;
    }

    if (::listen(listen_fd, 5) != 0) {
        std::cerr << "HttpServer: Failed to listen" << std::endl;
        close_socket(listen_fd);
        return;
    }

    std::cout << "HttpServer listening on port " << port_ << std::endl;

    while (running_) {
        sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
#ifdef _WIN32
        NativeSocket client_fd = ::accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
#else
        NativeSocket client_fd = ::accept(listen_fd, (struct sockaddr*)&client_addr, (socklen_t*)&client_len);
#endif
        if (client_fd == kInvalidSocket) {
            if (running_) {
                // std::cerr << "HttpServer: Accept failed" << std::endl;
            }
            continue;
        }

        std::thread(&HttpServer::handle_client, this, (std::uintptr_t)client_fd).detach();
    }
}

void HttpServer::handle_client(std::uintptr_t socket_ptr) {
    NativeSocket client_fd = (NativeSocket)socket_ptr;
    
    // Simple read buffer
    std::vector<char> buffer(4096);
    int bytes_read = ::recv(client_fd, buffer.data(), buffer.size(), 0);
    if (bytes_read <= 0) {
        close_socket(client_fd);
        return;
    }

    std::string raw_request(buffer.data(), bytes_read);
    
    // Parse request line
    std::istringstream stream(raw_request);
    std::string method, path, protocol;
    stream >> method >> path >> protocol;

    HttpRequest req;
    req.method = method;
    req.path = path;

    // Parse headers
    std::string line;
    std::getline(stream, line); // consume rest of request line
    while (std::getline(stream, line) && line != "\r") {
        if (line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = trim(line.substr(0, colon));
            std::string value = trim(line.substr(colon + 1));
            req.headers[key] = value;
        }
    }

    // Check for body
    if (req.headers.count("Content-Length")) {
        int content_length = std::stoi(req.headers["Content-Length"]);
        // Calculate how much body we already read
        auto body_start = raw_request.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            std::string initial_body = raw_request.substr(body_start + 4);
            req.body = initial_body;
            
            int remaining = content_length - (int)initial_body.size();
            if (remaining > 0) {
                std::vector<char> body_buffer(remaining);
                int total_read = 0;
                while (total_read < remaining) {
                    int n = ::recv(client_fd, body_buffer.data() + total_read, remaining - total_read, 0);
                    if (n <= 0) break;
                    total_read += n;
                }
                req.body += std::string(body_buffer.data(), total_read);
            }
        }
    }

    // Find handler
    HttpResponse resp;
    resp.status = 404;
    resp.body = "{\"error\": \"Not Found\"}";

    std::unique_lock<std::mutex> lock(handlers_mutex_);
    if (handlers_.count(method) && handlers_[method].count(path)) {
        auto handler = handlers_[method][path];
        lock.unlock();
        try {
            resp = handler(req);
        } catch (const std::exception& e) {
            resp.status = 500;
            resp.body = std::string("{\"error\": \"Internal Server Error: ") + e.what() + "\"}";
        }
    } else {
        lock.unlock();
    }

    // Send response
    std::ostringstream response_stream;
    response_stream << "HTTP/1.1 " << resp.status << " OK\r\n";
    response_stream << "Content-Type: " << resp.content_type << "\r\n";
    response_stream << "Content-Length: " << resp.body.size() << "\r\n";
    response_stream << "Access-Control-Allow-Origin: *\r\n"; // CORS for dashboard
    response_stream << "Connection: close\r\n";
    response_stream << "\r\n";
    response_stream << resp.body;

    std::string response_str = response_stream.str();
    ::send(client_fd, response_str.c_str(), (int)response_str.size(), 0);

    close_socket(client_fd);
}
