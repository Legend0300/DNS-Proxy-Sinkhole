#include "dns_configurator.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <regex>
#include <sstream>
#include <string_view>
#include <vector>
#include <mutex>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")
#endif

namespace {

std::string trim_copy(std::string_view value) {
    auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) {
        return {};
    }
    auto end = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(begin, end - begin + 1));
}

std::string to_lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::vector<std::string> split_addresses(const std::string& addresses) {
    std::vector<std::string> result;
    std::string token;
    for (char ch : addresses) {
        if (ch == ',' || ch == ';' || std::isspace(static_cast<unsigned char>(ch))) {
            if (!token.empty()) {
                result.push_back(token);
                token.clear();
            }
        } else {
            token.push_back(ch);
        }
    }
    if (!token.empty()) {
        result.push_back(token);
    }
    for (auto& entry : result) {
        entry = trim_copy(entry);
    }
    result.erase(std::remove_if(result.begin(), result.end(), [](const std::string& value) {
        return value.empty();
    }), result.end());
    return result;
}

#ifdef _WIN32
std::wstring utf8_to_wstring(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, result.data(), size);
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

std::string wide_to_utf8(std::wstring_view input) {
    if (input.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring quote_argument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    for (wchar_t ch : value) {
        if (ch == L'"') {
            quoted += L"\\\"";
        } else {
            quoted.push_back(ch);
        }
    }
    quoted += L"\"";
    return quoted;
}

std::wstring netsh_prefix(bool ipv6) {
    return ipv6 ? L"netsh interface ipv6" : L"netsh interface ipv4";
}

void clear_dns_servers(const std::string& alias, bool ipv6) {
    std::wostringstream cmd;
    std::wstring aliasWide = utf8_to_wstring(alias);
    cmd << netsh_prefix(ipv6) << L" delete dnsservers " << quote_argument(aliasWide) << L" all >nul 2>&1";
    _wsystem(cmd.str().c_str());
}

int run_netsh_command(const std::wstring& command) {
    return _wsystem(command.c_str());
}

bool add_dns_servers(const std::string& alias, const std::vector<std::string>& addresses, bool ipv6) {
    if (addresses.empty()) {
        return false;
    }
    clear_dns_servers(alias, ipv6);
    bool success = true;
    int index = 1;
    std::wstring aliasWide = utf8_to_wstring(alias);
    for (const auto& entry : addresses) {
        std::wostringstream cmd;
        cmd << netsh_prefix(ipv6) << L" add dnsserver "
            << quote_argument(aliasWide)
            << L" address=" << utf8_to_wstring(entry)
            << L" index=" << index;
        cmd << L" validate=no";
        int rc = run_netsh_command(cmd.str());
        if (rc != 0) {
            std::cout << "Failed to add DNS server '" << entry << "' to '" << alias << "' (exit code " << rc << ")" << std::endl;
            success = false;
        }
        ++index;
    }
    return success;
}

bool set_dns_source_dhcp(const std::string& alias, bool ipv6) {
    std::wostringstream cmd;
    std::wstring aliasWide = utf8_to_wstring(alias);
    cmd << netsh_prefix(ipv6) << L" set dnsservers " << quote_argument(aliasWide) << L" source=dhcp";
    int rc = run_netsh_command(cmd.str());
    if (rc != 0) {
        std::cout << "Failed to revert " << (ipv6 ? "IPv6" : "IPv4") << " DNS for '" << alias << "' (exit code " << rc << ")" << std::endl;
        return false;
    }
    return true;
}

struct DnsAssignmentTracker {
    std::mutex mutex;
    std::vector<std::string> aliases;
    bool cleanupRegistered = false;
};

DnsAssignmentTracker& get_tracker() {
    static DnsAssignmentTracker tracker;
    return tracker;
}

void cleanup_dns_assignments();

void register_dns_assignment(const std::string& alias) {
    auto& tracker = get_tracker();
    std::lock_guard<std::mutex> lock(tracker.mutex);
    if (std::find(tracker.aliases.begin(), tracker.aliases.end(), alias) == tracker.aliases.end()) {
        tracker.aliases.push_back(alias);
    }
    if (!tracker.cleanupRegistered) {
        std::atexit(cleanup_dns_assignments);
        tracker.cleanupRegistered = true;
    }
}

void cleanup_dns_assignments() {
    auto& tracker = get_tracker();
    std::vector<std::string> aliases;
    {
        std::lock_guard<std::mutex> lock(tracker.mutex);
        aliases = tracker.aliases;
    }
    if (aliases.empty()) {
        return;
    }
    std::cout << "\nReverting DNS configuration to DHCP for managed adapters..." << std::endl;
    for (const auto& alias : aliases) {
        set_dns_source_dhcp(alias, false);
        set_dns_source_dhcp(alias, true);
    }
}
#endif

#ifdef _WIN32
std::vector<NetworkInterfaceInfo> enumerate_windows_interfaces() {
    std::vector<NetworkInterfaceInfo> result;
    ULONG bufferLength = 0;
    ULONG flags = GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &bufferLength) != ERROR_BUFFER_OVERFLOW) {
        return result;
    }
    std::vector<unsigned char> buffer(bufferLength);
    auto addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufferLength) != NO_ERROR) {
        return result;
    }
    for (auto adapter = addresses; adapter != nullptr; adapter = adapter->Next) {
        if (!adapter->FriendlyName) {
            continue;
        }
        NetworkInterfaceInfo info;
        info.alias = wide_to_utf8(std::wstring_view(adapter->FriendlyName));
        info.description = adapter->Description ? wide_to_utf8(std::wstring_view(adapter->Description)) : "";
        info.isUp = adapter->OperStatus == IfOperStatusUp;
        result.push_back(std::move(info));
    }
    std::sort(result.begin(), result.end(), [](const NetworkInterfaceInfo& a, const NetworkInterfaceInfo& b) {
        return a.alias < b.alias;
    });
    return result;
}
#endif // _WIN32

} // namespace

std::vector<NetworkInterfaceInfo> enumerate_network_interfaces() {
#ifdef _WIN32
    return enumerate_windows_interfaces();
#else
    return {};
#endif
}

void print_dns_interface_list() {
    auto interfaces = enumerate_network_interfaces();
    if (interfaces.empty()) {
#ifdef _WIN32
        std::cout << "No network interfaces detected." << std::endl;
#else
        std::cout << "DNS assignment automation is available only on Windows." << std::endl;
#endif
        return;
    }
    std::cout << "Available interfaces:" << std::endl;
    std::size_t index = 0;
    for (const auto& iface : interfaces) {
        std::cout << "  [" << ++index << "] " << iface.alias;
        if (!iface.description.empty()) {
            std::cout << " - " << iface.description;
        }
        std::cout << (iface.isUp ? " (up)" : " (down)") << std::endl;
    }
}

bool configure_dns_for_alias(const ServerConfig& config, const std::string& alias) {
#ifdef _WIN32
    auto ipv4Targets = split_addresses(config.dnsAssignIPv4);
    auto ipv6Targets = split_addresses(config.dnsAssignIPv6);
    bool success = false;
    if (!ipv4Targets.empty()) {
        success = add_dns_servers(alias, ipv4Targets, false) || success;
    }
    if (!ipv6Targets.empty()) {
        success = add_dns_servers(alias, ipv6Targets, true) || success;
    }
    if (!success) {
        std::cout << "No DNS addresses were applied to '" << alias << "'." << std::endl;
    } else {
        std::cout << "DNS servers applied to '" << alias << "'." << std::endl;
        register_dns_assignment(alias);
    }
    return success;
#else
    (void)config;
    (void)alias;
    std::cout << "DNS assignment automation is only supported on Windows." << std::endl;
    return false;
#endif
}

bool configure_default_dns_targets(const ServerConfig& config) {
#ifdef _WIN32
    auto interfaces = enumerate_network_interfaces();
    if (interfaces.empty()) {
        std::cout << "No interfaces available for DNS assignment." << std::endl;
        return false;
    }
    static const std::vector<std::string> kDefaultPatterns = {
        R"(ethernet.*)",
        R"(wi-?fi.*)"
    };
    std::vector<const NetworkInterfaceInfo*> matches;
    for (const auto& pattern : kDefaultPatterns) {
        std::regex regex(pattern, std::regex::icase);
        for (const auto& iface : interfaces) {
            auto already = std::find_if(matches.begin(), matches.end(), [&](const NetworkInterfaceInfo* info) {
                return info->alias == iface.alias;
            });
            if (already != matches.end()) {
                continue;
            }
            if (std::regex_match(iface.alias, regex)) {
                matches.push_back(&iface);
            }
        }
    }
    if (matches.empty()) {
        std::cout << "Unable to find default adapters (Ethernet/Wi-Fi)." << std::endl;
        return false;
    }

    std::cout << "Interfaces matching default patterns:" << std::endl;
    for (const auto* iface : matches) {
        std::cout << "  - " << iface->alias;
        if (!iface->description.empty()) {
            std::cout << " - " << iface->description;
        }
        std::cout << (iface->isUp ? " (up)" : " (down)") << std::endl;
    }
    std::cout << "Apply DNS settings to these adapters? (Y/n): ";
    std::string response;
    if (!std::getline(std::cin, response)) {
        std::cin.clear();
        return false;
    }
    response = to_lower_copy(trim_copy(response));
    if (!response.empty() && response != "y" && response != "yes") {
        std::cout << "Skipped DNS assignment for default adapters." << std::endl;
        return false;
    }

    bool applied = false;
    for (const auto* iface : matches) {
        if (configure_dns_for_alias(config, iface->alias)) {
            applied = true;
        }
    }
    if (!applied) {
        std::cout << "DNS assignment commands failed for default adapters." << std::endl;
    }
    return applied;
#else
    (void)config;
    std::cout << "DNS assignment automation is only supported on Windows." << std::endl;
    return false;
#endif
}

void prompt_dns_interface_selection(const ServerConfig& config) {
#ifdef _WIN32
    auto interfaces = enumerate_network_interfaces();
    if (interfaces.empty()) {
        std::cout << "No interfaces available for selection." << std::endl;
        return;
    }
    std::cout << "Select one or more interfaces by number (space separated), or press Enter to skip:" << std::endl;
    std::size_t idx = 0;
    for (const auto& iface : interfaces) {
        std::cout << "  [" << ++idx << "] " << iface.alias;
        if (!iface.description.empty()) {
            std::cout << " - " << iface.description;
        }
        std::cout << (iface.isUp ? " (up)" : " (down)") << std::endl;
    }
    std::cout << "> ";
    std::string line;
    if (!std::getline(std::cin, line)) {
        std::cin.clear();
        return;
    }
    line = trim_copy(line);
    if (line.empty()) {
        return;
    }
    std::istringstream stream(line);
    std::vector<int> selections;
    int value = 0;
    while (stream >> value) {
        if (value > 0 && static_cast<std::size_t>(value) <= interfaces.size()) {
            selections.push_back(value);
        }
    }
    if (selections.empty()) {
        std::cout << "No valid selections entered." << std::endl;
        return;
    }
    for (int selection : selections) {
        const auto& iface = interfaces[static_cast<std::size_t>(selection - 1)];
        configure_dns_for_alias(config, iface.alias);
    }
#else
    (void)config;
    std::cout << "DNS assignment automation is only supported on Windows." << std::endl;
#endif
}

void prompt_dns_assignment(const ServerConfig& config) {
#ifdef _WIN32
    std::cout << "Configure DNS automatically for Ethernet and Wi-Fi adapters? (Y/n): ";
    std::string response;
    if (!std::getline(std::cin, response)) {
        std::cin.clear();
        return;
    }
    response = to_lower_copy(trim_copy(response));
    if (response.empty() || response == "y" || response == "yes") {
        configure_default_dns_targets(config);
    } else {
        prompt_dns_interface_selection(config);
    }
#else
    (void)config;
#endif
}
