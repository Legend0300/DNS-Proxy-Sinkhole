#include "rules.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <mutex>

namespace {

std::string to_lower(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (char ch : input) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return result;
}

} // namespace

RuleSet::RuleSet(RuleSet&& other) noexcept {
    std::unique_lock otherLock(other.mutex_);
    blacklist_ = std::move(other.blacklist_);
    whitelist_ = std::move(other.whitelist_);
    blacklistPath_ = std::move(other.blacklistPath_);
    whitelistPath_ = std::move(other.whitelistPath_);
}

RuleSet& RuleSet::operator=(RuleSet&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    std::scoped_lock guard(mutex_, other.mutex_);
    blacklist_ = std::move(other.blacklist_);
    whitelist_ = std::move(other.whitelist_);
    blacklistPath_ = std::move(other.blacklistPath_);
    whitelistPath_ = std::move(other.whitelistPath_);
    return *this;
}

void RuleSet::configure(std::string blacklistPath, std::string whitelistPath) {
    std::unique_lock lock(mutex_);
    blacklistPath_ = std::move(blacklistPath);
    whitelistPath_ = std::move(whitelistPath);
}

void RuleSet::load() {
    std::unique_lock lock(mutex_);
    load_file(blacklistPath_, blacklist_);
    load_file(whitelistPath_, whitelist_);
}

void RuleSet::reload() {
    load();
}

RuleAction RuleSet::evaluate(FilterMode mode, std::string_view hostname) const {
    auto normalized = normalize_hostname(hostname);
    if (normalized.empty()) {
        return RuleAction::AllowDefault;
    }
    std::shared_lock lock(mutex_);
    bool blacklistHit = matches(blacklist_, normalized);
    bool whitelistHit = matches(whitelist_, normalized);

    if (blacklistHit) {
        return RuleAction::SinkholeBlacklist;
    }

    if (mode == FilterMode::Whitelist) {
        if (whitelistHit) {
            return RuleAction::AllowWhitelist;
        }
        return RuleAction::SinkholeWhitelist;
    }

    if (whitelistHit) {
        return RuleAction::AllowWhitelist;
    }

    return RuleAction::AllowDefault;
}

bool RuleSet::add_to_blacklist(std::string_view hostname) {
    auto normalized = normalize_hostname(hostname);
    if (normalized.empty()) {
        return false;
    }
    std::unique_lock lock(mutex_);
    if (!insert_entry(blacklist_, std::move(normalized))) {
        return false;
    }
    persist_locked(blacklistPath_, blacklist_);
    return true;
}

bool RuleSet::remove_from_blacklist(std::string_view hostname) {
    auto normalized = normalize_hostname(hostname);
    if (normalized.empty()) {
        return false;
    }
    std::unique_lock lock(mutex_);
    if (!erase_entry(blacklist_, normalized)) {
        return false;
    }
    persist_locked(blacklistPath_, blacklist_);
    return true;
}

void RuleSet::clear_blacklist() {
    std::unique_lock lock(mutex_);
    blacklist_.clear();
    persist_locked(blacklistPath_, blacklist_);
}

int RuleSet::add_to_blacklist_bulk(const std::vector<std::string>& domains) {
    std::unique_lock lock(mutex_);
    int added = 0;
    for (const auto& domain : domains) {
        auto normalized = normalize_hostname(domain);
        if (!normalized.empty()) {
            if (insert_entry(blacklist_, std::move(normalized))) {
                added++;
            }
        }
    }
    if (added > 0) {
        persist_locked(blacklistPath_, blacklist_);
    }
    return added;
}

bool RuleSet::add_to_whitelist(std::string_view hostname) {
    auto normalized = normalize_hostname(hostname);
    if (normalized.empty()) {
        return false;
    }
    std::unique_lock lock(mutex_);
    if (!insert_entry(whitelist_, std::move(normalized))) {
        return false;
    }
    persist_locked(whitelistPath_, whitelist_);
    return true;
}

bool RuleSet::remove_from_whitelist(std::string_view hostname) {
    auto normalized = normalize_hostname(hostname);
    if (normalized.empty()) {
        return false;
    }
    std::unique_lock lock(mutex_);
    if (!erase_entry(whitelist_, normalized)) {
        return false;
    }
    persist_locked(whitelistPath_, whitelist_);
    return true;
}

void RuleSet::clear_whitelist() {
    std::unique_lock lock(mutex_);
    whitelist_.clear();
    persist_locked(whitelistPath_, whitelist_);
}

int RuleSet::add_to_whitelist_bulk(const std::vector<std::string>& domains) {
    std::unique_lock lock(mutex_);
    int added = 0;
    for (const auto& domain : domains) {
        auto normalized = normalize_hostname(domain);
        if (!normalized.empty()) {
            if (insert_entry(whitelist_, std::move(normalized))) {
                added++;
            }
        }
    }
    if (added > 0) {
        persist_locked(whitelistPath_, whitelist_);
    }
    return added;
}

std::vector<std::string> RuleSet::list_blacklist() const {
    std::shared_lock lock(mutex_);
    return blacklist_;
}

std::vector<std::string> RuleSet::list_whitelist() const {
    std::shared_lock lock(mutex_);
    return whitelist_;
}

std::size_t RuleSet::blacklist_size() const {
    std::shared_lock lock(mutex_);
    return blacklist_.size();
}

std::size_t RuleSet::whitelist_size() const {
    std::shared_lock lock(mutex_);
    return whitelist_.size();
}

std::string RuleSet::normalize_hostname(std::string_view host) {
    auto lower = to_lower(host);
    while (!lower.empty() && lower.back() == '.') {
        lower.pop_back();
    }
    return lower;
}

bool RuleSet::has_suffix(std::string_view name, std::string_view rule) {
    if (name == rule) {
        return true;
    }
    if (name.size() <= rule.size()) {
        return false;
    }
    auto pos = name.size() - rule.size();
    if (pos == 0 || name[pos - 1] != '.') {
        return false;
    }
    return name.substr(pos) == rule;
}

bool RuleSet::matches(const std::vector<std::string>& entries, std::string_view normalized) {
    return std::any_of(entries.begin(), entries.end(), [&](const std::string& rule) {
        return has_suffix(normalized, rule);
    });
}

bool RuleSet::insert_entry(std::vector<std::string>& entries, std::string&& entry) {
    auto it = std::lower_bound(entries.begin(), entries.end(), entry);
    if (it != entries.end() && *it == entry) {
        return false;
    }
    entries.insert(it, std::move(entry));
    return true;
}

bool RuleSet::erase_entry(std::vector<std::string>& entries, std::string_view normalized) {
    auto it = std::lower_bound(entries.begin(), entries.end(), normalized,
                               [](const std::string& lhs, std::string_view rhs) { return lhs < rhs; });
    if (it == entries.end() || *it != normalized) {
        return false;
    }
    entries.erase(it);
    return true;
}

void RuleSet::load_file(const std::string& path, std::vector<std::string>& entries) {
    entries.clear();
    if (path.empty()) {
        return;
    }
    std::ifstream stream(path);
    if (!stream.is_open()) {
        std::cerr << "Warning: unable to open list file: " << path << std::endl;
        return;
    }
    std::string line;
    while (std::getline(stream, line)) {
        auto hashPos = line.find('#');
        if (hashPos != std::string::npos) {
            line.resize(hashPos);
        }
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) {
            continue;
        }
        auto end = line.find_last_not_of(" \t\r\n");
        auto trimmed = line.substr(start, end - start + 1);
        std::string token;
        auto lastSpace = trimmed.find_last_of(" \t");
        if (lastSpace == std::string::npos) {
            token = trimmed;
        } else {
            token = trimmed.substr(lastSpace + 1);
        }
        if (token.rfind("*.", 0) == 0) {
            token.erase(0, 2);
        }
        token = normalize_hostname(token);
        if (!token.empty()) {
            entries.push_back(std::move(token));
        }
    }
    std::sort(entries.begin(), entries.end());
    entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
}

void RuleSet::persist_locked(const std::string& path, const std::vector<std::string>& entries) const {
    if (path.empty()) {
        return;
    }
    std::ofstream stream(path, std::ios::trunc);
    if (!stream.is_open()) {
        std::cerr << "Warning: unable to write list file: " << path << std::endl;
        return;
    }
    for (const auto& entry : entries) {
        stream << entry << '\n';
    }
}
