# DNS Proxy Sinkhole

A cross-platform DNS proxy written in modern C++ that can operate in two filtering modes:

- **Blacklist mode**: forwards all queries except those listed in a rule file; matching domains are sinkholed to configurable IPv4/IPv6 addresses.
- **Whitelist mode**: sinkholes every domain except those explicitly allowed in the rule file.

The proxy listens on both IPv4 and IPv6, relays queries to upstream resolvers over UDP/TCP, retries TCP on truncated responses, and synthesizes responses locally for sinkholed domains.

## Features

- IPv4/IPv6 dual-stack listeners with optional per-family binding control.
- Configurable blacklist or whitelist filtering.
- Sinkhole responses for A/AAAA records with fallback NXDOMAIN for other types.
- Hosts-style rule parser (supports wildcards via `*.example.com`).
- Upstream retry strategy with UDP first, TCP fallback, and truncation handling.
- Cross-platform socket abstraction (Windows Winsock, POSIX sockets).
- Interactive runtime management of blacklist/whitelist entries with automatic persistence.

## Prerequisites

- CMake 3.16+
- A C++20-compatible compiler (MSVC 19.3+, GCC 11+, or Clang 13+)
- Administrator/root privileges to bind to port 53
- Visual Studio 2022 (Windows) or build-essential (Linux)

## Build Instructions

### Windows (PowerShell)

```powershell
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

On Visual Studio generators replace the first command with `cmake -S . -B build -G "Visual Studio 17 2022"` and build via `cmake --build build --config Release`.

### Linux

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The resulting executable is `build/dns_proxy` (or `build\Release\dns_proxy.exe` on Visual Studio).

## Running the Proxy

The proxy exposes several CLI switches. Run `dns_proxy --help` for the full list.

Common flags:

- `--mode <blacklist|whitelist>` (default: `blacklist`)
- `--list-file <path>` domain list file (one domain per line; hosts format accepted)
- `--sinkhole-ipv4 <addr>` IPv4 sinkhole target (default `0.0.0.0`)
- `--sinkhole-ipv6 <addr>` IPv6 sinkhole target (default `::`)
- `--bind-ipv4 <addr|none>` IPv4 bind address (`none` disables IPv4 listener)
- `--bind-ipv6 <addr|none>` IPv6 bind address (`none` disables IPv6 listener)
- `--upstream <host[:port]>` additional upstream resolver (repeatable)
- `--port <number>` listening port (default 53)
- `--timeout-ms <ms>` upstream socket timeout (default 2000)

### Example (Blacklist)

```powershell
# Windows (PowerShell)
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit","-Command","cd `"C:/path/to/DNS server`"; build/dns_proxy.exe --mode blacklist --list-file blacklist.txt"
```

```bash
# Linux
sudo ./build/dns_proxy --mode blacklist --list-file blacklist.txt
```

Create `blacklist.txt` with entries such as:

```
example.com
*.ads.example
```

### Example (Whitelist)

```bash
sudo ./build/dns_proxy --mode whitelist --list-file whitelist.txt --sinkhole-ipv4 127.0.0.1
```

Entries in `whitelist.txt` are the only domains that will resolve; all others will be sinkholed.

## Configuring DNS Clients

### Windows 10/11

1. Open **Settings → Network & Internet**.
2. Choose **Change adapter options**.
3. Right-click your active adapter → **Properties**.
4. Select **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**.
5. Choose **Use the following DNS server addresses** and set:
   - Preferred DNS server: `127.0.0.1`
   - Alternate DNS server: leave blank or set to another resolver.
6. Repeat for **Internet Protocol Version 6 (TCP/IPv6)** if needed (use `::1`).

**PowerShell alternative:**

```powershell
InterfaceAlias="Ethernet"
Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses 127.0.0.1
Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses ::1 -AddressFamily IPv6
```

Restore defaults later with `Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ResetServerAddresses`.

### Linux (systemd-resolved)

```bash
sudo resolvectl dns eth0 127.0.0.1 ::1
sudo resolvectl domain eth0 "~."
```

Replace `eth0` with your interface. For traditional `/etc/resolv.conf`, edit the file as root and set:

```
nameserver 127.0.0.1
nameserver ::1
```

## Verification

After launching the proxy, test DNS resolution:

```powershell
nslookup example.com 127.0.0.1
nslookup example.com ::1
```

On Linux:

```bash
dig example.com @127.0.0.1
dig AAAA example.com @::1
```

Sinkholed domains should return the configured sinkhole address or NXDOMAIN; permitted domains should resolve normally via upstream resolvers.

## Runtime Commands

While the proxy is running in the foreground, you can update the filter lists without restarting. Type commands into the console where the server is running:

```
help
reload
blacklist add example.com
blacklist remove example.com
blacklist list
whitelist add trusted.example
whitelist remove trusted.example
whitelist list
```

Added and removed domains are normalized, persisted to `blacklist.txt` / `whitelist.txt`, and applied to new queries immediately. Sinkholed domains are recorded in `black_logs.txt`, while queries permitted by the whitelist are written to `white_logs.txt`.

## Troubleshooting

- **Permission denied / bind errors**: run with Administrator/root privileges or choose an unprivileged port via `--port`.
- **No IPv6 connectivity**: disable IPv6 binding with `--bind-ipv6 none` or remove IPv6 upstreams.
- **Rules not applied**: ensure the file path is correct and entries are lowercase without trailing dots; wildcard domains should use `*.example.com`.
- **Fallback behavior**: whitelist mode with an empty list blocks everything (warning emitted at startup). Ensure upstream resolvers are reachable.
