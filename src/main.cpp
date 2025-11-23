#include "config.hpp"
#include "dns_configurator.hpp"
#include "rules.hpp"
#include "server.hpp"

#include <exception>
#include <iostream>
#include <utility>

int main(int argc, char** argv) {
    try {
        auto config = parse_arguments(argc, argv);
        RuleSet rules;
        rules.configure(config.blacklistFile, config.whitelistFile);
        rules.load();
        prompt_dns_assignment(config);
        DnsServer server(std::move(config), std::move(rules));
        return server.run();
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
