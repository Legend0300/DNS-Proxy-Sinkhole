# App Gate - DNS Proxy Sinkhole

App Gate is a high-performance DNS Proxy Sinkhole designed to filter DNS traffic based on customizable blacklist and whitelist rules. It features a robust C++ backend with a custom REST API and a modern Electron-based dashboard for real-time management.

## Features

*   **DNS Filtering:** Blocks or allows domains based on configurable rules.
*   **Dual Modes:** Switch between **Blacklist Mode** (block specific domains) and **Whitelist Mode** (allow only specific domains).
*   **REST API:** Fully functional HTTP REST API for managing rules and server state programmatically.
*   **Real-time Dashboard:** Electron-based GUI for easy management of domains, modes, and system stats.
*   **Bulk Operations:** Add or remove multiple domains at once.
*   **System Integration:** Includes utilities to flush system DNS cache (Windows only).
*   **High Performance:** Built with C++20 using native sockets (Winsock2 on Windows).

## Codebase Structure

```
DNS_server/
├── src/                # C++ Source files
│   ├── main.cpp        # Entry point
│   ├── server.cpp      # Core server logic & API endpoints
│   ├── http_server.cpp # Custom HTTP server implementation
│   ├── rules.cpp       # Rule management logic
│   └── ...
├── include/            # C++ Header files
├── dashboard/          # Electron Frontend
│   ├── main.js         # Electron main process
│   ├── renderer.js     # Frontend logic (API calls, UI updates)
│   ├── index.html      # Dashboard layout
│   └── styles.css      # Dashboard styling
├── CMakeLists.txt      # CMake build configuration
├── blacklist.txt       # Persistent blacklist storage
└── whitelist.txt       # Persistent whitelist storage
```

## Getting Started

### Prerequisites

*   **C++ Backend:**
    *   CMake (3.16+)
    *   C++ Compiler supporting C++20 (e.g., MSVC on Windows)
*   **Frontend:**
    *   Node.js & npm

### Building and Running the Backend (C++)

1.  Navigate to the project root.
2.  Create a build directory:
    ```bash
    mkdir build
    cd build
    ```
3.  Generate build files with CMake:
    ```bash
    cmake ..
    ```
4.  Build the project:
    ```bash
    cmake --build . --config Release
    ```
5.  Run the executable (requires Administrator privileges to bind to port 53):
    ```bash
    .\Release\dns_proxy.exe
    ```
    *The server will start listening on DNS port 53 and API port 8080.*

### Running the Dashboard (Electron)

1.  Open a new terminal and navigate to the `dashboard` folder:
    ```bash
    cd dashboard
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Start the application:
    ```bash
    npm start
    ```

## REST API Documentation

The backend exposes a REST API on port `8080` (default).

### General

*   **GET /**
    *   Returns API information and available endpoints.

*   **GET /stats**
    *   Returns the current count of rules in blacklist and whitelist.

*   **GET /mode**
    *   Returns the current operation mode (`blacklist` or `whitelist`).

*   **POST /mode**
    *   Switch operation mode.
    *   Body: `{"mode": "blacklist"}` or `{"mode": "whitelist"}`

*   **POST /reload**
    *   Reloads rules from `blacklist.txt` and `whitelist.txt` files.

*   **POST /flushdns**
    *   Flushes the Windows DNS cache.

### Blacklist Management

*   **GET /blacklist**
    *   Returns all domains in the blacklist.

*   **POST /blacklist**
    *   Add a single domain.
    *   Body: `{"domain": "example.com"}`

*   **DELETE /blacklist**
    *   Remove a single domain.
    *   Body: `{"domain": "example.com"}`

*   **POST /blacklist/bulk**
    *   Add multiple domains.
    *   Body: `["example.com", "ads.google.com"]`

*   **DELETE /blacklist/all**
    *   Clear the entire blacklist.

### Whitelist Management

*   **GET /whitelist**
    *   Returns all domains in the whitelist.

*   **POST /whitelist**
    *   Add a single domain.
    *   Body: `{"domain": "trusted.com"}`

*   **DELETE /whitelist**
    *   Remove a single domain.
    *   Body: `{"domain": "trusted.com"}`

*   **POST /whitelist/bulk**
    *   Add multiple domains.
    *   Body: `["trusted.com", "mysite.org"]`

*   **DELETE /whitelist/all**
    *   Clear the entire whitelist.

## Configuration

*   **Port:** DNS listens on port 53.
*   **API Port:** REST API listens on port 8080.
*   **Storage:** Rules are persisted in `blacklist.txt` and `whitelist.txt` in the executable's directory.

