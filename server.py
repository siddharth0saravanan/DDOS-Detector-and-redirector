#!/usr/bin/env python3
"""
server.py  –  Enhanced Test HTTP Server
Features: rate limiting, connection stats, real-time dashboard endpoint,
          SSL support, configurable responses.
"""

import http.server
import socketserver
import threading
import argparse
import logging
import time
import socket
import ssl
import os
import json
from collections import defaultdict, deque
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ─── Connection Tracker ───────────────────────────────────────────────────────

class ConnectionStore:
    """Thread-safe store for per-IP connection timestamps."""
    def __init__(self, window: int = 60):
        self.window   = window
        self._data    = defaultdict(lambda: deque(maxlen=5000))
        self._lock    = threading.Lock()
        self.total    = 0
        self.blocked  = set()

    def record(self, ip: str) -> int:
        """Record a connection; return recent count in window."""
        now = time.time()
        with self._lock:
            dq = self._data[ip]
            dq.append(now)
            self.total += 1
            # Clean old entries
            while dq and now - dq[0] > self.window:
                dq.popleft()
            return len(dq)

    def rate(self, ip: str, period: int = 5) -> float:
        now = time.time()
        with self._lock:
            dq = self._data.get(ip, deque())
            recent = sum(1 for ts in dq if now - ts <= period)
        return recent / period

    def top_talkers(self, n=10, period=5):
        now = time.time()
        with self._lock:
            items = []
            for ip, dq in self._data.items():
                cnt = sum(1 for ts in dq if now - ts <= period)
                if cnt:
                    items.append((ip, cnt / period))
        return sorted(items, key=lambda x: -x[1])[:n]

    def stats_json(self) -> str:
        talkers = self.top_talkers()
        return json.dumps({
            "total_connections": self.total,
            "blocked_ips":       list(self.blocked),
            "top_talkers": [{"ip": ip, "rate": round(r, 2)} for ip, r in talkers],
            "timestamp": datetime.now().isoformat(),
        }, indent=2)


STORE = ConnectionStore()
RATE_LIMIT = 0    # 0 = disabled; set via --rate-limit

# ─── Request Handler ──────────────────────────────────────────────────────────

class EnhancedHandler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        ip = self.client_address[0]
        STORE.record(ip)

    def log_message(self, fmt, *args):
        if args and args[1] != "200":
            logging.info(f"{self.client_address[0]} - {fmt % args}")

    def _check_rate_limit(self) -> bool:
        if RATE_LIMIT <= 0:
            return False     # not blocked
        ip = self.client_address[0]
        rate = STORE.rate(ip)
        if rate > RATE_LIMIT:
            STORE.blocked.add(ip)
            return True
        return False

    def _send_json(self, code: int, data: str):
        body = data.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "DDoS-Lab-Server")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code: int, body: str):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self._check_rate_limit():
            self._send_html(429, "<h1>429 Too Many Requests</h1><p>Rate limit exceeded.</p>")
            return

        path = self.path.split("?")[0]

        if path == "/stats":
            self._send_json(200, STORE.stats_json())
        elif path == "/health":
            self._send_json(200, '{"status":"ok"}')
        else:
            ip = self.client_address[0]
            rate = STORE.rate(ip)
            self._send_html(200, HTML_PAGE.format(
                ip=ip, rate=f"{rate:.1f}",
                total=STORE.total,
                time=datetime.now().strftime("%H:%M:%S")
            ))

    def do_POST(self):
        if self._check_rate_limit():
            self._send_html(429, "<h1>429 Too Many Requests</h1>")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        self._send_json(200, '{"status":"received"}')

HTML_PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DDoS Lab — Test Server</title>
  <style>
    body {{ font-family: 'Courier New', monospace; background: #0a0e1a; color: #e8eaf6;
           display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
    .box {{ border: 1px solid #1e3a5f; padding: 40px; border-radius:4px; text-align:center; }}
    h1 {{ color: #00d4ff; margin:0 0 20px; }}
    .stat {{ margin: 8px 0; color: #7986cb; }}
    .val {{ color: #2ed573; font-weight:bold; }}
    a {{ color: #00d4ff; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>⚡ DDoS Lab Server</h1>
    <div class="stat">Your IP: <span class="val">{ip}</span></div>
    <div class="stat">Your rate: <span class="val">{rate} req/s</span></div>
    <div class="stat">Total connections: <span class="val">{total}</span></div>
    <div class="stat">Server time: <span class="val">{time}</span></div>
    <br>
    <div><a href="/stats">/stats</a> — JSON stats endpoint</div>
    <div><a href="/health">/health</a> — Health check</div>
  </div>
</body>
</html>"""

# ─── Threaded Server ──────────────────────────────────────────────────────────

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def print_stats_loop(interval: int):
    while True:
        time.sleep(interval)
        talkers = STORE.top_talkers(5)
        print(f"\n─── Stats @ {datetime.now():%H:%M:%S} ───")
        print(f"  Total connections : {STORE.total}")
        print(f"  Blocked IPs       : {len(STORE.blocked)}")
        if talkers:
            print("  Top talkers (5s)  :")
            for ip, rate in talkers:
                print(f"    {ip:20s}  {rate:.1f} req/s")
        print("──────────────────────────────")

def main():
    global RATE_LIMIT
    parser = argparse.ArgumentParser(description="Enhanced DDoS Lab HTTP Server")
    parser.add_argument("--host",       default="0.0.0.0")
    parser.add_argument("--port",       type=int, default=8080)
    parser.add_argument("--ssl",        action="store_true")
    parser.add_argument("--rate-limit", type=int, default=0,
                        help="Block IPs exceeding N req/s (0=disabled)")
    parser.add_argument("--stats-interval", type=int, default=10,
                        help="Print stats every N seconds (default 10)")
    args = parser.parse_args()
    RATE_LIMIT = args.rate_limit

    try:
        server = ThreadedHTTPServer((args.host, args.port), EnhancedHandler)

        if args.ssl:
            if not (os.path.exists("server.crt") and os.path.exists("server.key")):
                logging.info("Generating self-signed SSL cert...")
                os.system('openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 '
                          '-subj "/CN=localhost" -keyout server.key -out server.crt')
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain("server.crt", "server.key")
            server.socket = ctx.wrap_socket(server.socket, server_side=True)

        proto = "HTTPS" if args.ssl else "HTTP"
        logging.info(f"Starting {proto} server on {args.host}:{args.port}")
        if RATE_LIMIT:
            logging.info(f"Rate limit: {RATE_LIMIT} req/s per IP")
        logging.info(f"Stats endpoint: http://localhost:{args.port}/stats")
        logging.info("Press Ctrl+C to stop")

        t = threading.Thread(target=print_stats_loop,
                             args=(args.stats_interval,), daemon=True)
        t.start()

        server.serve_forever()

    except KeyboardInterrupt:
        logging.info("Server stopped.")
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    finally:
        if "server" in dir():
            server.server_close()

if __name__ == "__main__":
    main()
