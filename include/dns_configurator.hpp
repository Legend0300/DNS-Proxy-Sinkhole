#pragma once

#include "config.hpp"

#include <string>
#include <vector>

struct NetworkInterfaceInfo {
    std::string alias;
    std::string description;
    bool isUp = false;
};

std::vector<NetworkInterfaceInfo> enumerate_network_interfaces();

void prompt_dns_assignment(const ServerConfig& config);

bool configure_default_dns_targets(const ServerConfig& config);

bool configure_dns_for_alias(const ServerConfig& config, const std::string& alias);

void prompt_dns_interface_selection(const ServerConfig& config);

void print_dns_interface_list();

bool reset_dns_to_dhcp(const std::string& alias);
