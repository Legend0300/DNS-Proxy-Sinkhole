#!/usr/bin/env python3
# dns_proxy.py
# Requirements: dnslib (pip install dnslib)
# Run as Administrator on Windows to bind port 53:
#    python dns_proxy.py

import argparse
import socket
import threading
import struct
import logging
import time
from pathlib import Path
from dnslib import DNSRecord, RCODE, RR, QTYPE, A, AAAA

PORT = 53
BIND_TARGETS = [
    ('0.0.0.0', socket.AF_INET),
    ('::', socket.AF_INET6),
]
UPSTREAMS = [
    ('1.1.1.1', 53),
    ('1.0.0.1', 53),
    ('2606:4700:4700::1111', 53),
    ('2606:4700:4700::1001', 53),
]
SOCKET_TIMEOUT = 2.0
MAX_UDP_SIZE = 4096
MODE = 'blacklist'
RULES = set()
SINKHOLE_IPV4 = '0.0.0.0'
SINKHOLE_IPV6 = '::'
SINKHOLE_TTL = 60

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def normalize_hostname(name):
    return name.strip().lower().rstrip('.')

def load_rules(path):
    if not path:
        return set()
    entries = set()
    try:
        for line in Path(path).read_text(encoding='utf-8').splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            token = line.split()[-1]
            if token.startswith('*.'):
                token = token[2:]
            entries.add(normalize_hostname(token))
    except FileNotFoundError:
        logging.error("Rule file not found: %s", path)
    except OSError as e:
        logging.error("Unable to read rule file %s -> %s", path, e)
    return entries

def hostname_matches(name, rule):
    if name == rule:
        return True
    return name.endswith('.' + rule)

def should_sinkhole_hostname(name):
    if not name:
        return False
    if MODE == 'blacklist':
        return any(hostname_matches(name, rule) for rule in RULES)
    if MODE == 'whitelist':
        if not RULES:
            return True
        return not any(hostname_matches(name, rule) for rule in RULES)
    return False

def build_sinkhole_response(request):
    reply = request.reply()
    q = request.questions[0]
    if q.qtype == QTYPE.A and SINKHOLE_IPV4:
        reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1, ttl=SINKHOLE_TTL, rdata=A(SINKHOLE_IPV4)))
    elif q.qtype == QTYPE.AAAA and SINKHOLE_IPV6:
        reply.add_answer(RR(rname=q.qname, rtype=QTYPE.AAAA, rclass=1, ttl=SINKHOLE_TTL, rdata=AAAA(SINKHOLE_IPV6)))
    else:
        reply.header.rcode = RCODE.NXDOMAIN
    reply.header.aa = 1
    return reply.pack()

def build_bind_targets(ipv4, ipv6):
    targets = []
    if ipv4:
        targets.append((ipv4, socket.AF_INET))
    if ipv6:
        targets.append((ipv6, socket.AF_INET6))
    return targets

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['blacklist', 'whitelist'], default='blacklist')
    parser.add_argument('--list-file')
    parser.add_argument('--sinkhole-ipv4', default='0.0.0.0')
    parser.add_argument('--sinkhole-ipv6', default='::')
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--bind-ipv4', default='0.0.0.0')
    parser.add_argument('--bind-ipv6', default='::')
    return parser.parse_args()

def log_query(client_addr, data):
    """Parse query and log client, qname, qtype."""
    try:
        req = DNSRecord.parse(data)
        q = req.questions[0]
        qname = str(q.get_qname())
        qtype = q.qtype
        # qtype number -> string
        qtype_str = q.qtype
        try:
            qtype_str = q.get_qtype()
        except Exception:
            qtype_str = str(qtype)
        logging.info("Query from %s:%d -> %s (%s)", client_addr[0], client_addr[1], qname, qtype_str)
    except Exception as e:
        logging.info("Query from %s:%d -> (unparseable) len=%d (%s)", client_addr[0], client_addr[1], len(data), e)

def forward_udp_to_upstreams(request_bytes):
    """Try each upstream via UDP, return response bytes or None.
       If upstream returns a response with TC (truncated) bit set, return that response,
       but caller should handle TCP retry when appropriate."""
    for upstream, uport in UPSTREAMS:
        family = socket.AF_INET6 if ':' in upstream else socket.AF_INET
        target = (upstream, uport, 0, 0) if family == socket.AF_INET6 else (upstream, uport)
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(SOCKET_TIMEOUT)
                s.sendto(request_bytes, target)
                resp, _ = s.recvfrom(MAX_UDP_SIZE)
                return resp
        except socket.timeout:
            logging.warning("UDP timeout from upstream %s:%d", upstream, uport)
        except Exception as e:
            logging.warning("UDP error with upstream %s:%d -> %s", upstream, uport, e)
    return None

def forward_tcp_to_upstream_single(upstream_host, upstream_port, request_bytes):
    """Forward a single query to a single upstream using TCP DNS (length-prefixed)."""
    try:
        with socket.create_connection((upstream_host, upstream_port), timeout=SOCKET_TIMEOUT) as s:
            # send length prefix then payload
            s.sendall(struct.pack("!H", len(request_bytes)) + request_bytes)
            # read two-byte length
            hdr = s.recv(2)
            if len(hdr) < 2:
                raise IOError("short read for tcp length")
            resp_len = struct.unpack("!H", hdr)[0]
            chunks = []
            toread = resp_len
            while toread > 0:
                chunk = s.recv(toread)
                if not chunk:
                    raise IOError("incomplete tcp read")
                chunks.append(chunk)
                toread -= len(chunk)
            return b"".join(chunks)
    except Exception as e:
        logging.warning("TCP error with upstream %s:%d -> %s", upstream_host, upstream_port, e)
        return None

def forward_tcp_to_upstreams(request_bytes):
    """Try upstreams via TCP; return first successful response or None."""
    for upstream, uport in UPSTREAMS:
        resp = forward_tcp_to_upstream_single(upstream, uport, request_bytes)
        if resp:
            return resp
    return None

def udp_worker(sock, data, addr):
    """Handle a single UDP client request."""
    log_query(addr, data)
    # Try UDP upstream first
    request = None
    try:
        request = DNSRecord.parse(data)
        if request.questions:
            qname = normalize_hostname(str(request.questions[0].get_qname()))
            if should_sinkhole_hostname(qname):
                logging.info("Sinkhole response for %s (%s mode)", qname, MODE)
                try:
                    sock.sendto(build_sinkhole_response(request), addr)
                except Exception as e:
                    logging.error("Failed to send sinkhole response to %s:%d -> %s", addr[0], addr[1], e)
                return
    except Exception as e:
        logging.error("Failed to parse UDP request from %s:%d -> %s", addr[0], addr[1], e)

    resp = forward_udp_to_upstreams(data)
    if resp:
        # If truncated, perform TCP upstream fetch and use that response instead
        try:
            parsed = DNSRecord.parse(resp)
            if parsed.header.tc == 1:
                logging.info("Upstream sent truncated response (TC). Retrying via TCP")
                tcp_resp = forward_tcp_to_upstreams(data)
                if tcp_resp:
                    resp = tcp_resp
        except Exception:
            # if parse fails, just send what we have
            pass
        try:
            sock.sendto(resp, addr)
            return
        except Exception as e:
            logging.error("Failed to send response to %s:%d -> %s", addr[0], addr[1], e)
            return

    # If UDP upstream failed, try TCP upstream (some servers may only respond via TCP for some queries)
    tcp_resp = forward_tcp_to_upstreams(data)
    if tcp_resp:
        try:
            sock.sendto(tcp_resp, addr)
            return
        except Exception as e:
            logging.error("Failed to send TCP-derived response to %s:%d -> %s", addr[0], addr[1], e)

    # If all upstreams failed, return SERVFAIL
    try:
        req = DNSRecord.parse(data)
        reply = req.reply()
        reply.header.rcode = RCODE.SERVFAIL
        sock.sendto(reply.pack(), addr)
    except Exception:
        # unparseable request: send nothing (or optionally an empty packet)
        logging.error("Unable to parse client request and no upstream response for %s:%d", addr[0], addr[1])

def udp_listener(sock):
    while True:
        try:
            data, addr = sock.recvfrom(MAX_UDP_SIZE)
            t = threading.Thread(target=udp_worker, args=(sock, data, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.exception("UDP server error: %s", e)
            time.sleep(0.5)

def udp_server():
    sockets = []
    for addr, family in BIND_TARGETS:
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6 and hasattr(socket, 'IPPROTO_IPV6') and hasattr(socket, 'IPV6_V6ONLY'):
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            target = (addr, PORT, 0, 0) if family == socket.AF_INET6 else (addr, PORT)
            s.bind(target)
            logging.info("UDP server listening on %s:%d", addr, PORT)
            sockets.append(s)
            threading.Thread(target=udp_listener, args=(s,), daemon=True).start()
        except Exception as e:
            logging.error("Failed to bind UDP socket on %s:%d -> %s", addr, PORT, e)
    if not sockets:
        logging.error("No UDP sockets bound; exiting UDP server thread")
        return
    while True:
        time.sleep(1)

def handle_tcp_client(conn, addr):
    """Handle a single TCP client session (length-prefixed DNS)."""
    try:
        # read 2-byte length
        hdr = conn.recv(2)
        if len(hdr) < 2:
            logging.warning("TCP client disconnected prematurely: %s:%d", addr[0], addr[1])
            conn.close()
            return
        req_len = struct.unpack("!H", hdr)[0]
        # read exactly req_len bytes
        chunks = []
        toread = req_len
        while toread > 0:
            chunk = conn.recv(toread)
            if not chunk:
                break
            chunks.append(chunk)
            toread -= len(chunk)
        data = b"".join(chunks)
        log_query(addr, data)
        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            logging.error("Failed to parse TCP request from %s:%d -> %s", addr[0], addr[1], e)
            request = None
        if request and request.questions:
            qname = normalize_hostname(str(request.questions[0].get_qname()))
            if should_sinkhole_hostname(qname):
                logging.info("Sinkhole response for %s (%s mode)", qname, MODE)
                packet = build_sinkhole_response(request)
                conn.sendall(struct.pack("!H", len(packet)) + packet)
                return

        # Forward via TCP upstreams (prefer TCP for TCP client)
        resp = forward_tcp_to_upstreams(data)
        if not resp:
            # as fallback try UDP upstream
            resp = forward_udp_to_upstreams(data)

        if resp:
            # send length-prefixed response back
            conn.sendall(struct.pack("!H", len(resp)) + resp)
        else:
            # send SERVFAIL reply
            try:
                req = DNSRecord.parse(data)
                reply = req.reply()
                reply.header.rcode = RCODE.SERVFAIL
                packed = reply.pack()
                conn.sendall(struct.pack("!H", len(packed)) + packed)
            except Exception:
                # nothing workable to send
                pass
    except Exception as e:
        logging.exception("Error handling TCP client %s:%d -> %s", addr[0], addr[1], e)
    finally:
        conn.close()

def tcp_listener(sock):
    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            logging.exception("TCP server error: %s", e)
            time.sleep(0.5)

def tcp_server():
    sockets = []
    for addr, family in BIND_TARGETS:
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6 and hasattr(socket, 'IPPROTO_IPV6') and hasattr(socket, 'IPV6_V6ONLY'):
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            target = (addr, PORT, 0, 0) if family == socket.AF_INET6 else (addr, PORT)
            s.bind(target)
            s.listen(50)
            logging.info("TCP server listening on %s:%d", addr, PORT)
            sockets.append(s)
            threading.Thread(target=tcp_listener, args=(s,), daemon=True).start()
        except Exception as e:
            logging.error("Failed to bind TCP socket on %s:%d -> %s", addr, PORT, e)
    if not sockets:
        logging.error("No TCP sockets bound; exiting TCP server thread")
        return
    while True:
        time.sleep(1)

def main():
    args = parse_arguments()
    global MODE, RULES, SINKHOLE_IPV4, SINKHOLE_IPV6, PORT, BIND_TARGETS
    MODE = args.mode
    PORT = args.port
    SINKHOLE_IPV4 = args.sinkhole_ipv4
    SINKHOLE_IPV6 = args.sinkhole_ipv6
    BIND_TARGETS = build_bind_targets(args.bind_ipv4, args.bind_ipv6)
    RULES = load_rules(args.list_file)
    logging.info("Starting DNS proxy. Upstreams: %s", ", ".join([f"{u}:{p}" for u, p in UPSTREAMS]))
    logging.info("Mode: %s (%d rules)", MODE, len(RULES))
    if args.list_file:
        logging.info("Rules file: %s", args.list_file)
    if MODE == 'whitelist' and not RULES:
        logging.warning("Whitelist is empty; all domains will be sinkholed")
    if not BIND_TARGETS:
        logging.error("No bind targets configured")
        return
    logging.info("Binding UDP/TCP on: %s", ", ".join([f"{addr}:{PORT}" for addr, _ in BIND_TARGETS]))
    # Start UDP and TCP servers in threads
    udp_thread = threading.Thread(target=udp_server, daemon=True)
    tcp_thread = threading.Thread(target=tcp_server, daemon=True)
    udp_thread.start()
    tcp_thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down.")

if __name__ == "__main__":
    main()
