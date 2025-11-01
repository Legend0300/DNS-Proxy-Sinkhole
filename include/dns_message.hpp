#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

struct DnsQuestion {
    std::string name;
    std::uint16_t qtype = 0;
    std::uint16_t qclass = 0;
};

bool parse_question(const std::vector<std::uint8_t>& packet, DnsQuestion& out);

bool is_truncated(const std::vector<std::uint8_t>& packet);

std::vector<std::uint8_t> build_sinkhole_response(const std::vector<std::uint8_t>& request,
                                                  const DnsQuestion& question,
                                                  const ServerConfig& config);

std::vector<std::uint8_t> build_servfail_response(const std::vector<std::uint8_t>& request);
