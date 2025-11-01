#include "dns_message.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace {

constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;
constexpr std::uint16_t kClassIN = 1;
constexpr std::uint32_t kSinkholeTtl = 60;

std::uint16_t read_u16(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    return static_cast<std::uint16_t>((buffer[offset] << 8) | buffer[offset + 1]);
}

void write_u16(std::vector<std::uint8_t>& buffer, std::size_t offset, std::uint16_t value) {
    buffer[offset] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    buffer[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
}

void write_u32(std::vector<std::uint8_t>& buffer, std::uint32_t value) {
    buffer.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

bool decode_name(const std::vector<std::uint8_t>& packet, std::size_t& offset, std::string& out, int depth = 0) {
    if (depth > 8) {
        return false;
    }
    while (offset < packet.size()) {
        auto len = packet[offset];
        if (len == 0) {
            ++offset;
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= packet.size()) {
                return false;
            }
            auto ptr = static_cast<std::size_t>(((len & 0x3F) << 8) | packet[offset + 1]);
            offset += 2;
            std::size_t newOffset = ptr;
            return decode_name(packet, newOffset, out, depth + 1);
        }
        ++offset;
        if (offset + len > packet.size()) {
            return false;
        }
        if (!out.empty()) {
            out.push_back('.');
        }
        out.append(reinterpret_cast<const char*>(&packet[offset]), len);
        offset += len;
    }
    return false;
}

std::size_t question_end_offset(const std::vector<std::uint8_t>& packet) {
    std::size_t offset = 12;
    std::string tmp;
    if (!decode_name(packet, offset, tmp)) {
        return packet.size();
    }
    offset += 4;
    return offset;
}

bool encode_ipv4(const std::string& address, std::array<std::uint8_t, 4>& out) {
    return ::inet_pton(AF_INET, address.c_str(), out.data()) == 1;
}

bool encode_ipv6(const std::string& address, std::array<std::uint8_t, 16>& out) {
    return ::inet_pton(AF_INET6, address.c_str(), out.data()) == 1;
}

} // namespace

bool parse_question(const std::vector<std::uint8_t>& packet, DnsQuestion& out) {
    if (packet.size() < 12) {
        return false;
    }
    auto qdcount = read_u16(packet, 4);
    if (qdcount == 0) {
        return false;
    }
    std::size_t offset = 12;
    out.name.clear();
    if (!decode_name(packet, offset, out.name)) {
        return false;
    }
    if (offset + 4 > packet.size()) {
        return false;
    }
    out.qtype = read_u16(packet, offset);
    out.qclass = read_u16(packet, offset + 2);
    if (out.name.empty()) {
        return false;
    }
    return true;
}

bool is_truncated(const std::vector<std::uint8_t>& packet) {
    if (packet.size() < 4) {
        return false;
    }
    auto flags = read_u16(packet, 2);
    return (flags & 0x0200U) != 0;
}

std::vector<std::uint8_t> build_sinkhole_response(const std::vector<std::uint8_t>& request,
                                                  const DnsQuestion& question,
                                                  const ServerConfig& config) {
    std::vector<std::uint8_t> response;
    std::size_t end = question_end_offset(request);
    response.assign(request.begin(), request.begin() + static_cast<std::ptrdiff_t>(std::min(end, request.size())));
    if (response.size() < 12) {
        response.resize(12, 0);
    }
    auto flags = read_u16(request, 2);
    std::uint16_t newFlags = 0x8000U | (flags & 0x0100U) | 0x0400U;
    response[2] = static_cast<std::uint8_t>((newFlags >> 8) & 0xFF);
    response[3] = static_cast<std::uint8_t>(newFlags & 0xFF);
    write_u16(response, 6, 0);
    write_u16(response, 8, 0);
    write_u16(response, 10, 0);

    bool answered = false;
    if (question.qclass == kClassIN) {
        if (question.qtype == kTypeA && !config.sinkholeIPv4.empty()) {
            std::array<std::uint8_t, 4> addr{};
            if (encode_ipv4(config.sinkholeIPv4, addr)) {
                write_u16(response, 6, 1);
                response.push_back(0xC0);
                response.push_back(0x0C);
                response.push_back(0x00);
                response.push_back(0x01);
                response.push_back(0x00);
                response.push_back(0x01);
                write_u32(response, kSinkholeTtl);
                response.push_back(0x00);
                response.push_back(0x04);
                response.insert(response.end(), addr.begin(), addr.end());
                answered = true;
            }
        } else if (question.qtype == kTypeAAAA && !config.sinkholeIPv6.empty()) {
            std::array<std::uint8_t, 16> addr{};
            if (encode_ipv6(config.sinkholeIPv6, addr)) {
                write_u16(response, 6, 1);
                response.push_back(0xC0);
                response.push_back(0x0C);
                response.push_back(0x00);
                response.push_back(0x1C);
                response.push_back(0x00);
                response.push_back(0x01);
                write_u32(response, kSinkholeTtl);
                response.push_back(0x00);
                response.push_back(0x10);
                response.insert(response.end(), addr.begin(), addr.end());
                answered = true;
            }
        }
    }

    if (!answered) {
        auto nxdomainFlags = static_cast<std::uint16_t>((newFlags & 0xFFF0U) | 0x0003U);
        response[2] = static_cast<std::uint8_t>((nxdomainFlags >> 8) & 0xFF);
        response[3] = static_cast<std::uint8_t>(nxdomainFlags & 0xFF);
    }

    return response;
}

std::vector<std::uint8_t> build_servfail_response(const std::vector<std::uint8_t>& request) {
    std::vector<std::uint8_t> response(request.begin(), request.end());
    if (response.size() < 12) {
        response.resize(12, 0);
    }
    auto flags = read_u16(request, 2);
    std::uint16_t rd = flags & 0x0100U;
    std::uint16_t newFlags = 0x8000U | rd | 0x0002U;
    response[2] = static_cast<std::uint8_t>((newFlags >> 8) & 0xFF);
    response[3] = static_cast<std::uint8_t>(newFlags & 0xFF);
    write_u16(response, 6, 0);
    write_u16(response, 8, 0);
    write_u16(response, 10, 0);
    return response;
}
