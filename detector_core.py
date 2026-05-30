#!/usr/bin/env python3
"""
detector_core.py  –  Cross-platform DDoS Detection Engine
Handles: connection tracking, multi-attack-type detection,
         IP blocking (iptables / Windows firewall), and structured logging.
"""

import time
import threading
import subprocess
import platform
import logging
import json
import os
import csv
import queue
import socket
from collections import defaultdict, deque
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable

# ─── OS Detection ────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"

# ─── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class AttackEvent:
    timestamp: str
    source_ip: str
    target_ip: str
    target_port: int
    attack_type: str          # tcp_flood | udp_flood | http_flood | slowloris | syn_flood | amplification
    rate: float               # connections/sec
    blocked: bool = False
    severity: str = "HIGH"    # LOW | MEDIUM | HIGH | CRITICAL

    def to_dict(self):
        return asdict(self)

@dataclass
class ConnectionRecord:
    timestamps: deque = field(default_factory=lambda: deque(maxlen=2000))
    ports: deque      = field(default_factory=lambda: deque(maxlen=2000))
    half_open: int    = 0     # SYN without ACK counter
    slow_start: float = 0.0   # first seen time (slowloris detection)
    http_reqs: deque  = field(default_factory=lambda: deque(maxlen=500))

# ─── Configuration ───────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "threshold_connections":   100,
    "threshold_period":          5,
    "notification_timeout":     30,
    "monitored_ports":     [80, 443, 8080, 5000],
    "udp_threshold":           200,
    "syn_threshold":            80,
    "http_threshold":          150,
    "slowloris_threshold":      40,
    "amplification_threshold": 100,
    "auto_block":            False,
    "block_duration":          300,   # seconds
    "email_alerts":          False,
    "email_smtp":       "smtp.gmail.com",
    "email_port":              587,
    "email_user":               "",
    "email_password":           "",
    "email_to":                 "",
    "log_file":    "ddos_detector.log",
    "csv_export":  "attack_log.csv",
}

CONFIG_FILE = "detector_config.json"

def load_config() -> dict:
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
    except Exception:
        pass
    save_config(DEFAULT_CONFIG.copy())
    return DEFAULT_CONFIG.copy()

def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)

# ─── Logging Setup ───────────────────────────────────────────────────────────

def setup_logging(log_file: str):
    fmt = "%(asctime)s - %(levelname)s - %(message)s"
    handlers = [
        logging.FileHandler(log_file),
        logging.StreamHandler(),
    ]
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers, force=True)

# ─── IP Blocker ──────────────────────────────────────────────────────────────

class IPBlocker:
    """Cross-platform IP blocking via iptables (Linux), netsh (Windows), pfctl (Mac)."""

    def __init__(self):
        self.blocked: Dict[str, float] = {}   # ip → block_time
        self._lock = threading.Lock()

    def block(self, ip: str, duration: int = 300) -> bool:
        with self._lock:
            if ip in self.blocked:
                return False          # already blocked
            self.blocked[ip] = time.time()
        try:
            if IS_LINUX:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True
                )
            elif IS_WINDOWS:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=BLOCK_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                    check=True, capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            elif IS_MAC:
                subprocess.run(
                    ["sudo", "pfctl", "-t", "bruteforce", "-T", "add", ip],
                    check=True, capture_output=True
                )
            logging.warning(f"[BLOCKER] Blocked IP {ip} for {duration}s")
            # Schedule unblock
            t = threading.Timer(duration, self.unblock, args=(ip,))
            t.daemon = True
            t.start()
            return True
        except Exception as e:
            logging.error(f"[BLOCKER] Failed to block {ip}: {e}")
            with self._lock:
                self.blocked.pop(ip, None)
            return False

    def unblock(self, ip: str):
        with self._lock:
            self.blocked.pop(ip, None)
        try:
            if IS_LINUX:
                subprocess.run(
                    ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
            elif IS_WINDOWS:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name=BLOCK_{ip}"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            elif IS_MAC:
                subprocess.run(
                    ["sudo", "pfctl", "-t", "bruteforce", "-T", "delete", ip],
                    capture_output=True
                )
            logging.info(f"[BLOCKER] Unblocked IP {ip}")
        except Exception as e:
            logging.error(f"[BLOCKER] Failed to unblock {ip}: {e}")

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self.blocked

# ─── Email Alerter ───────────────────────────────────────────────────────────

class EmailAlerter:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._queue: queue.Queue = queue.Queue()
        t = threading.Thread(target=self._worker, daemon=True)
        t.start()

    def send(self, event: AttackEvent):
        if self.cfg.get("email_alerts"):
            self._queue.put(event)

    def _worker(self):
        import smtplib
        from email.mime.text import MIMEText
        while True:
            event: AttackEvent = self._queue.get()
            try:
                body = (
                    f"DDoS Alert — {event.attack_type.upper()}\n\n"
                    f"Time      : {event.timestamp}\n"
                    f"Source IP : {event.source_ip}\n"
                    f"Target    : {event.target_ip}:{event.target_port}\n"
                    f"Rate      : {event.rate:.1f} conn/s\n"
                    f"Severity  : {event.severity}\n"
                    f"Blocked   : {'Yes' if event.blocked else 'No'}\n"
                )
                msg = MIMEText(body)
                msg["Subject"] = f"[DDoS Alert] {event.severity} – {event.attack_type} from {event.source_ip}"
                msg["From"]    = self.cfg["email_user"]
                msg["To"]      = self.cfg["email_to"]

                with smtplib.SMTP(self.cfg["email_smtp"], self.cfg["email_port"]) as s:
                    s.starttls()
                    s.login(self.cfg["email_user"], self.cfg["email_password"])
                    s.send_message(msg)
                logging.info(f"[EMAIL] Alert sent for {event.source_ip}")
            except Exception as e:
                logging.error(f"[EMAIL] Failed to send alert: {e}")

# ─── CSV Logger ──────────────────────────────────────────────────────────────

class CSVLogger:
    _FIELDS = ["timestamp", "source_ip", "target_ip", "target_port",
               "attack_type", "rate", "blocked", "severity"]

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        if not os.path.exists(path):
            with open(path, "w", newline="") as f:
                csv.DictWriter(f, fieldnames=self._FIELDS).writeheader()

    def log(self, event: AttackEvent):
        with self._lock:
            with open(self.path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=self._FIELDS)
                row = event.to_dict()
                w.writerow({k: row[k] for k in self._FIELDS})

# ─── Attack Detector ─────────────────────────────────────────────────────────

class AttackDetector:
    """
    Core detection engine.  Call record_connection() for every observed
    connection; it returns an AttackEvent (or None).
    """

    def __init__(self, cfg: dict, event_cb: Optional[Callable] = None):
        self.cfg      = cfg
        self.event_cb = event_cb        # called with AttackEvent on detection
        self._records: Dict[str, ConnectionRecord] = defaultdict(ConnectionRecord)
        self._lock    = threading.Lock()
        self._recent_alerts: Dict[str, float] = {}  # ip → last alert time

        # Start periodic cleanup
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    # ── Public API ───────────────────────────────────────────────────────────

    def record_connection(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str = "TCP",
        flags: str = "",           # "SYN", "SYN-ACK", etc.
        is_http: bool = False,
        conn_duration: float = 0,  # for slowloris detection
    ) -> Optional[AttackEvent]:

        if dst_port not in self.cfg["monitored_ports"]:
            return None

        now = time.time()
        with self._lock:
            rec = self._records[src_ip]
            rec.timestamps.append(now)
            rec.ports.append(dst_port)
            if is_http:
                rec.http_reqs.append(now)
            if flags == "SYN":
                rec.half_open += 1
            elif flags in ("SYN-ACK", "ACK"):
                rec.half_open = max(0, rec.half_open - 1)
            if rec.slow_start == 0:
                rec.slow_start = now

        attack_type = self._classify(src_ip, dst_ip, dst_port, proto,
                                     conn_duration, now)
        if attack_type is None:
            return None

        # Deduplicate alerts (1 per IP per 60 s)
        with self._lock:
            last = self._recent_alerts.get(src_ip, 0)
            if now - last < 60:
                return None
            self._recent_alerts[src_ip] = now

        rate = self._rate(src_ip, now)
        severity = self._severity(rate, attack_type)
        event = AttackEvent(
            timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source_ip   = src_ip,
            target_ip   = dst_ip,
            target_port = dst_port,
            attack_type = attack_type,
            rate        = round(rate, 2),
            severity    = severity,
        )
        logging.warning(
            f"[DETECT] {attack_type.upper()} from {src_ip} → {dst_ip}:{dst_port} "
            f"@ {rate:.1f} conn/s  [{severity}]"
        )
        if self.event_cb:
            self.event_cb(event)
        return event

    def get_top_talkers(self, n: int = 10) -> List[tuple]:
        now = time.time()
        period = self.cfg["threshold_period"]
        with self._lock:
            rates = []
            for ip, rec in self._records.items():
                recent = sum(1 for ts in rec.timestamps if now - ts <= period)
                if recent:
                    rates.append((ip, round(recent / period, 2)))
        return sorted(rates, key=lambda x: x[1], reverse=True)[:n]

    def get_rate_history(self, ip: str, window: int = 60) -> List[float]:
        """Return per-second rates for the last `window` seconds."""
        now = time.time()
        with self._lock:
            rec = self._records.get(ip)
            if not rec:
                return [0.0] * window
            ts_list = list(rec.timestamps)
        history = []
        for i in range(window, 0, -1):
            t_start = now - i
            t_end   = now - i + 1
            count = sum(1 for ts in ts_list if t_start <= ts < t_end)
            history.append(float(count))
        return history

    # ── Detection Logic ──────────────────────────────────────────────────────

    def _classify(self, src_ip, dst_ip, dst_port, proto, conn_dur, now) -> Optional[str]:
        cfg = self.cfg
        period = cfg["threshold_period"]
        with self._lock:
            rec = self._records[src_ip]
            recent_ts   = [ts for ts in rec.timestamps   if now - ts <= period]
            recent_http = [ts for ts in rec.http_reqs    if now - ts <= period]
            half_open   = rec.half_open
            first_seen  = rec.slow_start

        count = len(recent_ts)

        # TCP / Generic flood
        if proto == "TCP" and count >= cfg["threshold_connections"]:
            return "tcp_flood"

        # UDP flood
        if proto == "UDP" and count >= cfg["udp_threshold"]:
            return "udp_flood"

        # SYN flood (many half-open connections)
        if half_open >= cfg["syn_threshold"]:
            return "syn_flood"

        # HTTP flood
        if len(recent_http) >= cfg["http_threshold"]:
            return "http_flood"

        # Slowloris – many long-lived connections from same IP
        if conn_dur > 10 and count >= cfg["slowloris_threshold"]:
            return "slowloris"

        # Amplification – very small requests generating huge responses
        # Heuristic: many small UDP packets to DNS/NTP ports
        if proto == "UDP" and dst_port in (53, 123, 1900) and count >= cfg["amplification_threshold"]:
            return "amplification"

        return None

    def _rate(self, src_ip: str, now: float) -> float:
        period = self.cfg["threshold_period"]
        with self._lock:
            rec = self._records.get(src_ip)
            if not rec:
                return 0.0
            recent = sum(1 for ts in rec.timestamps if now - ts <= period)
        return recent / period

    def _severity(self, rate: float, attack_type: str) -> str:
        if attack_type in ("syn_flood", "amplification"):
            return "CRITICAL"
        if rate > 500:
            return "CRITICAL"
        if rate > 200:
            return "HIGH"
        if rate > 50:
            return "MEDIUM"
        return "LOW"

    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            now = time.time()
            cutoff = max(self.cfg["threshold_period"], 120)
            with self._lock:
                stale = [ip for ip, rec in self._records.items()
                         if not rec.timestamps or now - rec.timestamps[-1] > cutoff]
                for ip in stale:
                    del self._records[ip]
                old_alerts = [ip for ip, t in self._recent_alerts.items() if now - t > 120]
                for ip in old_alerts:
                    del self._recent_alerts[ip]

# ─── Cross-Platform Network Monitor ──────────────────────────────────────────

class NetworkMonitor:
    """
    Reads active connections via netstat (Windows/Mac) or /proc/net/tcp (Linux).
    Feeds them into AttackDetector.
    """

    def __init__(self, detector: AttackDetector, cfg: dict,
                 blocker: Optional[IPBlocker] = None):
        self.detector  = detector
        self.cfg       = cfg
        self.blocker   = blocker
        self.running   = False
        self._thread: Optional[threading.Thread] = None
        self.check_interval = 1.0

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logging.info(f"[MONITOR] Started on {platform.system()}")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
        logging.info("[MONITOR] Stopped")

    def _loop(self):
        while self.running:
            try:
                conns = self._get_connections()
                for c in conns:
                    src_ip, src_port, dst_ip, dst_port, proto = c
                    if self.blocker and self.blocker.is_blocked(src_ip):
                        continue
                    event = self.detector.record_connection(
                        src_ip, dst_ip, src_port, dst_port, proto
                    )
                    if event and self.blocker and self.cfg.get("auto_block"):
                        blocked = self.blocker.block(src_ip, self.cfg["block_duration"])
                        event.blocked = blocked
            except Exception as e:
                logging.error(f"[MONITOR] Loop error: {e}")
            time.sleep(self.check_interval)

    def _get_connections(self) -> List[tuple]:
        if IS_LINUX:
            return self._linux_proc()
        else:
            return self._netstat()

    # Linux /proc/net/tcp – faster than netstat
    def _linux_proc(self) -> List[tuple]:
        conns = []
        monitored = set(self.cfg["monitored_ports"])
        for proto_file, proto_name in [("/proc/net/tcp", "TCP"), ("/proc/net/udp", "UDP")]:
            try:
                with open(proto_file) as f:
                    lines = f.readlines()[1:]   # skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local_hex, remote_hex = parts[1], parts[2]
                    l_ip, l_port = self._hex_to_ip_port(local_hex)
                    r_ip, r_port = self._hex_to_ip_port(remote_hex)
                    if l_port in monitored:
                        conns.append((r_ip, r_port, l_ip, l_port, proto_name))
            except Exception:
                pass
        return conns

    @staticmethod
    def _hex_to_ip_port(hex_str: str):
        addr, port_hex = hex_str.split(":")
        # Little-endian 4 bytes
        ip_int = int(addr, 16)
        ip = socket.inet_ntoa(ip_int.to_bytes(4, "little"))
        port = int(port_hex, 16)
        return ip, port

    # netstat fallback (Windows / Mac)
    def _netstat(self) -> List[tuple]:
        conns = []
        try:
            if IS_WINDOWS:
                cmd = ["netstat", "-n", "-p", "TCP"]
                kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW}
            else:
                cmd = ["netstat", "-n"]
                kwargs = {}
            output = subprocess.check_output(
                cmd, universal_newlines=True, **kwargs, stderr=subprocess.DEVNULL
            )
            for line in output.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                proto = parts[0].upper() if parts[0].upper() in ("TCP", "UDP") else None
                if not proto:
                    continue
                try:
                    local  = parts[1]
                    remote = parts[2]
                    l_ip, l_port = local.rsplit(":", 1)
                    r_ip, r_port = remote.rsplit(":", 1)
                    conns.append((r_ip, int(r_port), l_ip, int(l_port), proto))
                except (ValueError, IndexError):
                    continue
        except Exception as e:
            logging.debug(f"[MONITOR] netstat error: {e}")
        return conns


# ─── Server Stats Poller ──────────────────────────────────────────────────────

class ServerStatsPoller:
    """
    Polls the test server's /stats endpoint every second and injects
    connection counts directly into the AttackDetector.
    This catches short-lived flood connections that vanish before netstat polls.
    """

    def __init__(self, detector: AttackDetector, cfg: dict,
                 blocker: Optional[IPBlocker] = None,
                 server_url: str = "http://127.0.0.1:8080"):
        self.detector   = detector
        self.cfg        = cfg
        self.blocker    = blocker
        self.server_url = server_url.rstrip("/")
        self.running    = False
        self._thread: Optional[threading.Thread] = None
        # Track last seen count per IP to compute delta
        self._last_counts: Dict[str, int] = {}

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logging.info(f"[POLLER] Started polling {self.server_url}/stats")

    def stop(self):
        self.running = False

    def _loop(self):
        import urllib.request
        import urllib.error
        while self.running:
            try:
                url = f"{self.server_url}/stats"
                with urllib.request.urlopen(url, timeout=1) as resp:
                    data = json.loads(resp.read())

                talkers = data.get("top_talkers", [])
                dst_ip  = "127.0.0.1"
                dst_port = int(self.server_url.split(":")[-1]) if ":" in self.server_url else 8080

                for entry in talkers:
                    src_ip = entry["ip"]
                    rate   = float(entry["rate"])  # conn/s from server
                    if self.blocker and self.blocker.is_blocked(src_ip):
                        continue
                    # Inject synthetic connections proportional to rate
                    count = max(1, int(rate))
                    for _ in range(count):
                        event = self.detector.record_connection(
                            src_ip, dst_ip, 0, dst_port, "TCP", is_http=True
                        )
                        if event and self.blocker and self.cfg.get("auto_block"):
                            blocked = self.blocker.block(src_ip, self.cfg["block_duration"])
                            event.blocked = blocked

            except Exception:
                pass  # server not running or unreachable
            time.sleep(1)
