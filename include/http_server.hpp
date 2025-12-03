#pragma once

#include <string>
#include <functional>
#include <map>
#include <vector>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct HttpResponse {
    int status = 200;
    std::string body;
    std::string content_type = "application/json";
};

using HttpHandler = std::function<HttpResponse(const HttpRequest&)>;

class HttpServer {
public:
    HttpServer(int port);
    ~HttpServer();

    void register_handler(const std::string& method, const std::string& path, HttpHandler handler);
    void run();
    void stop();

private:
    void accept_loop();
    void handle_client(std::uintptr_t socket);

    int port_;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
    std::map<std::string, std::map<std::string, HttpHandler>> handlers_; // method -> path -> handler
    std::mutex handlers_mutex_;
    std::uintptr_t server_socket_ = 0; // SOCKET
};
