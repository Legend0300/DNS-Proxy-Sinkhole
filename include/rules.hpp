#pragma once

#include <cstddef>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"

enum class RuleAction {
    AllowDefault,
    AllowWhitelist,
    SinkholeBlacklist,
    SinkholeWhitelist
};

class RuleSet {
public:
    RuleSet() = default;
    RuleSet(const RuleSet&) = delete;
    RuleSet& operator=(const RuleSet&) = delete;
    RuleSet(RuleSet&& other) noexcept;
    RuleSet& operator=(RuleSet&& other) noexcept;

    void configure(std::string blacklistPath, std::string whitelistPath);

    void load();

    void reload();

    [[nodiscard]] RuleAction evaluate(FilterMode mode, std::string_view hostname) const;

    bool add_to_blacklist(std::string_view hostname);
    bool remove_from_blacklist(std::string_view hostname);
    void clear_blacklist();
    int add_to_blacklist_bulk(const std::vector<std::string>& domains);

    bool add_to_whitelist(std::string_view hostname);
    bool remove_from_whitelist(std::string_view hostname);
    void clear_whitelist();
    int add_to_whitelist_bulk(const std::vector<std::string>& domains);

    [[nodiscard]] std::vector<std::string> list_blacklist() const;
    [[nodiscard]] std::vector<std::string> list_whitelist() const;

    [[nodiscard]] std::size_t blacklist_size() const;
    [[nodiscard]] std::size_t whitelist_size() const;

private:
    static std::string normalize_hostname(std::string_view host);
    static bool has_suffix(std::string_view name, std::string_view rule);
    static bool matches(const std::vector<std::string>& entries, std::string_view normalized);

    static bool insert_entry(std::vector<std::string>& entries, std::string&& entry);
    static bool erase_entry(std::vector<std::string>& entries, std::string_view normalized);

    void load_file(const std::string& path, std::vector<std::string>& entries);
    void persist_locked(const std::string& path, const std::vector<std::string>& entries) const;

    mutable std::shared_mutex mutex_;
    std::vector<std::string> blacklist_;
    std::vector<std::string> whitelist_;
    std::string blacklistPath_;
    std::string whitelistPath_;
};
