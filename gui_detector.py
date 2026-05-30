#!/usr/bin/env python3
"""
gui_detector.py  –  Enhanced DDoS Detector GUI
Dark cyberpunk theme | Real-time charts | Full dashboard
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
import json
import os
import csv
import platform
from datetime import datetime
from collections import deque
from typing import Optional

# Matplotlib disabled - causes segfault with NumPy 2.x on Ubuntu 22.04
HAS_MPL = False

from detector_core import (
    AttackDetector, NetworkMonitor, IPBlocker,
    EmailAlerter, CSVLogger, AttackEvent,
    ServerStatsPoller,
    load_config, save_config, setup_logging,
)

# ─── Theme ───────────────────────────────────────────────────────────────────

THEME = {
    "bg":         "#0a0e1a",
    "bg2":        "#111827",
    "bg3":        "#1c2333",
    "accent":     "#00d4ff",
    "accent2":    "#ff4757",
    "accent3":    "#2ed573",
    "warn":       "#ffa502",
    "text":       "#e8eaf6",
    "text_dim":   "#7986cb",
    "border":     "#1e3a5f",
    "critical":   "#ff2d55",
    "high":       "#ff6b35",
    "medium":     "#ffa502",
    "low":        "#2ed573",
    "font_head":  ("Courier New", 11, "bold"),
    "font_body":  ("Courier New", 10),
    "font_small": ("Courier New", 9),
    "font_big":   ("Courier New", 16, "bold"),
    "font_title": ("Courier New", 22, "bold"),
}

SEV_COLOR = {
    "CRITICAL": THEME["critical"],
    "HIGH":     THEME["high"],
    "MEDIUM":   THEME["medium"],
    "LOW":      THEME["low"],
}

ATTACK_ICON = {
    "tcp_flood":     "⚡",
    "udp_flood":     "🌊",
    "syn_flood":     "🔁",
    "http_flood":    "🌐",
    "slowloris":     "🐢",
    "amplification": "📡",
}

# ─── Stat Card Widget ────────────────────────────────────────────────────────

class StatCard(tk.Frame):
    def __init__(self, parent, label: str, value: str = "0",
                 accent=None, **kwargs):
        accent = accent or THEME["accent"]
        super().__init__(parent, bg=THEME["bg3"],
                         highlightbackground=accent,
                         highlightthickness=1, **kwargs)
        tk.Label(self, text=label, bg=THEME["bg3"],
                 fg=THEME["text_dim"], font=THEME["font_small"]).pack(pady=(8, 0))
        self._var = tk.StringVar(value=value)
        self._lbl = tk.Label(self, textvariable=self._var,
                             bg=THEME["bg3"], fg=accent,
                             font=THEME["font_big"])
        self._lbl.pack(pady=(0, 8))

    def set(self, value: str, color: Optional[str] = None):
        self._var.set(value)
        if color:
            self._lbl.config(fg=color)

# ─── Mini Sparkline (no matplotlib) ─────────────────────────────────────────

class Sparkline(tk.Frame):
    """Sparkline replacement using a simple bar of labels — no Canvas width issues."""
    def __init__(self, parent, width=200, height=40, color=None, **kwargs):
        color = color or THEME["accent"]
        super().__init__(parent, bg=THEME["bg3"], **kwargs)
        self._color = color
        self._data: deque = deque([0.0] * 60, maxlen=60)
        self._var = tk.StringVar(value="▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁")
        tk.Label(self, textvariable=self._var, bg=THEME["bg3"],
                 fg=color, font=("Courier New", 8)).pack()
        self._rate_var = tk.StringVar(value="0.0 conn/s")
        tk.Label(self, textvariable=self._rate_var, bg=THEME["bg3"],
                 fg=THEME["text_dim"], font=("Courier New", 8)).pack()

    def push(self, value: float):
        self._data.append(value)
        self._draw(value)

    def _draw(self, latest: float):
        bars = " ▁▂▃▄▅▆▇█"
        data = list(self._data)
        mx = max(data) or 1
        # Show last 20 samples as unicode bar chart
        last20 = data[-20:]
        chars = ""
        for v in last20:
            idx = int((v / mx) * (len(bars) - 1))
            chars += bars[idx]
        self._var.set(chars)
        self._rate_var.set(f"{latest:.1f} conn/s")

# ─── Real-Time Chart (matplotlib) ────────────────────────────────────────────

class LiveChart(tk.Frame):
    def __init__(self, parent, title="Traffic Rate", **kwargs):
        super().__init__(parent, bg=THEME["bg2"], **kwargs)
        if not HAS_MPL:
            tk.Label(self, text="Install matplotlib for charts\npip install matplotlib",
                     bg=THEME["bg2"], fg=THEME["text_dim"],
                     font=THEME["font_body"]).pack(expand=True)
            self._has_mpl = False
            return
        self._has_mpl = True

        fig = Figure(figsize=(6, 2.2), dpi=90, facecolor=THEME["bg2"])
        self._ax = fig.add_subplot(111)
        self._ax.set_facecolor(THEME["bg3"])
        for spine in self._ax.spines.values():
            spine.set_color(THEME["border"])
        self._ax.tick_params(colors=THEME["text_dim"], labelsize=7)
        self._ax.set_title(title, color=THEME["accent"], fontsize=9)
        self._ax.set_xlabel("Seconds ago", color=THEME["text_dim"], fontsize=7)
        self._ax.set_ylabel("conn/s",      color=THEME["text_dim"], fontsize=7)

        self._canvas = FigureCanvasTkAgg(fig, master=self)
        self._canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self._lines = {}
        self._data: dict[str, deque] = {}

    def add_series(self, key: str, color: str):
        if not self._has_mpl:
            return
        self._data[key] = deque([0.0] * 60, maxlen=60)
        (line,) = self._ax.plot(range(60), [0] * 60,
                                color=color, linewidth=1.5, label=key)
        self._lines[key] = line
        self._ax.legend(facecolor=THEME["bg3"], labelcolor=THEME["text"],
                        fontsize=7)

    def push(self, key: str, value: float):
        if not self._has_mpl or key not in self._data:
            return
        self._data[key].append(value)
        data = list(self._data[key])
        self._lines[key].set_ydata(data)
        mx = max(max(d) for d in self._data.values() if d) or 1
        self._ax.set_ylim(0, mx * 1.2)
        self._canvas.draw_idle()

# ─── Main Application ─────────────────────────────────────────────────────────

class DDosDetectorApp:
    def __init__(self):
        self.cfg          = load_config()
        setup_logging(self.cfg["log_file"])

        self.event_queue  = queue.Queue()
        self.attack_log   = deque(maxlen=500)
        self.total_attacks = 0
        self.blocked_ips  = set()

        # Core components
        self.blocker   = IPBlocker()
        self.detector  = AttackDetector(self.cfg, event_cb=self._on_event)
        self.monitor   = NetworkMonitor(self.detector, self.cfg, self.blocker)
        self.poller    = ServerStatsPoller(self.detector, self.cfg, self.blocker,
                             server_url=f"http://127.0.0.1:{self.cfg.get('server_port', 8080)}")
        self.csv_log   = CSVLogger(self.cfg["csv_export"])
        self.emailer   = EmailAlerter(self.cfg)

        # Rate history for charts
        self._rate_history: dict[str, deque] = {
            "total":  deque([0.0]*60, maxlen=60),
            "tcp":    deque([0.0]*60, maxlen=60),
            "udp":    deque([0.0]*60, maxlen=60),
            "http":   deque([0.0]*60, maxlen=60),
        }
        self._attack_type_counts: dict[str, int] = {}

        self._build_ui()
        self.monitor.start()
        self.poller.start()
        self._tick()
        self.root.mainloop()

    # ── Event Callback (from detector thread) ────────────────────────────────

    def _on_event(self, event: AttackEvent):
        self.event_queue.put(event)

    # ── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        self.root = tk.Tk()
        self.root.title("⚡ DDoS Detection System  |  Enhanced Edition")
        self.root.geometry("1100x720")
        self.root.configure(bg=THEME["bg"])
        self.root.minsize(900, 600)

        # Apply ttk style
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=THEME["bg2"], foreground=THEME["text"],
                        fieldbackground=THEME["bg3"], font=THEME["font_body"],
                        borderwidth=0)
        style.configure("TNotebook", background=THEME["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME["bg3"],
                        foreground=THEME["text_dim"],
                        padding=[14, 6], font=THEME["font_head"])
        style.map("TNotebook.Tab",
                  background=[("selected", THEME["bg2"])],
                  foreground=[("selected", THEME["accent"])])
        style.configure("Treeview", background=THEME["bg3"],
                        foreground=THEME["text"],
                        fieldbackground=THEME["bg3"],
                        rowheight=24, font=THEME["font_small"])
        style.configure("Treeview.Heading", background=THEME["bg2"],
                        foreground=THEME["accent"], font=THEME["font_head"])
        style.map("Treeview", background=[("selected", THEME["border"])])
        style.configure("TScrollbar", background=THEME["bg3"],
                        troughcolor=THEME["bg"], arrowcolor=THEME["text_dim"])
        style.configure("TButton", background=THEME["bg3"],
                        foreground=THEME["accent"], font=THEME["font_head"],
                        padding=[8, 4])
        style.map("TButton", background=[("active", THEME["border"])])
        style.configure("TEntry", fieldbackground=THEME["bg3"],
                        foreground=THEME["text"], insertcolor=THEME["accent"])
        style.configure("TLabelframe", background=THEME["bg2"],
                        foreground=THEME["accent"])
        style.configure("TLabelframe.Label", background=THEME["bg2"],
                        foreground=THEME["accent"], font=THEME["font_head"])
        style.configure("TCheckbutton", background=THEME["bg2"],
                        foreground=THEME["text"])

        # Title bar
        title_bar = tk.Frame(self.root, bg=THEME["bg"], pady=6)
        title_bar.pack(fill=tk.X, padx=15, pady=(8, 0))
        tk.Label(title_bar, text="⚡ DDOS DETECTION SYSTEM",
                 bg=THEME["bg"], fg=THEME["accent"],
                 font=THEME["font_title"]).pack(side=tk.LEFT)
        self._status_dot = tk.Label(title_bar, text="● MONITORING",
                                     bg=THEME["bg"], fg=THEME["accent3"],
                                     font=THEME["font_head"])
        self._status_dot.pack(side=tk.RIGHT, padx=10)

        # Tabs
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self._tab_dashboard = ttk.Frame(nb)
        self._tab_alerts    = ttk.Frame(nb)
        self._tab_ips       = ttk.Frame(nb)
        self._tab_charts    = ttk.Frame(nb)
        self._tab_settings  = ttk.Frame(nb)
        self._tab_logs      = ttk.Frame(nb)

        nb.add(self._tab_dashboard, text="  📊 Dashboard  ")
        nb.add(self._tab_alerts,    text="  🚨 Alerts  ")
        nb.add(self._tab_ips,       text="  🌐 IP Monitor  ")
        nb.add(self._tab_charts,    text="  📈 Charts  ")
        nb.add(self._tab_settings,  text="  ⚙️  Settings  ")
        nb.add(self._tab_logs,      text="  📋 Logs  ")

        self._build_dashboard()
        self._build_alerts()
        self._build_ip_monitor()
        self._build_charts()
        self._build_settings()
        self._build_logs()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Dashboard Tab ────────────────────────────────────────────────────────

    def _build_dashboard(self):
        p = ttk.Frame(self._tab_dashboard)
        p.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Stat cards row
        cards_frame = tk.Frame(p, bg=THEME["bg"])
        cards_frame.pack(fill=tk.X, pady=(0, 10))

        self._card_total    = StatCard(cards_frame, "TOTAL ATTACKS",   "0",  THEME["accent2"])
        self._card_rate     = StatCard(cards_frame, "CURRENT RATE",    "0/s", THEME["accent"])
        self._card_blocked  = StatCard(cards_frame, "IPs BLOCKED",     "0",  THEME["warn"])
        self._card_top_type = StatCard(cards_frame, "TOP ATTACK TYPE", "—",  THEME["accent3"])

        for card in [self._card_total, self._card_rate,
                     self._card_blocked, self._card_top_type]:
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

        # Middle row: recent events + sparklines
        mid = tk.Frame(p, bg=THEME["bg"])
        mid.pack(fill=tk.BOTH, expand=True)

        # Recent events list
        evt_frame = tk.LabelFrame(mid, text=" Recent Events ",
                                  bg=THEME["bg2"], fg=THEME["accent"],
                                  font=THEME["font_head"])
        evt_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        self._evt_list = tk.Listbox(
            evt_frame, bg=THEME["bg3"], fg=THEME["text"],
            font=THEME["font_small"], selectbackground=THEME["border"],
            highlightthickness=0, borderwidth=0, relief=tk.FLAT
        )
        self._evt_list.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Right: sparklines
        spark_frame = tk.LabelFrame(mid, text=" Traffic (60s) ",
                                    bg=THEME["bg2"], fg=THEME["accent"],
                                    font=THEME["font_head"])
        spark_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(6, 0))

        for label, color in [("TCP", THEME["accent"]),
                              ("UDP", THEME["accent2"]),
                              ("HTTP", THEME["accent3"])]:
            tk.Label(spark_frame, text=label, bg=THEME["bg2"],
                     fg=color, font=THEME["font_small"]).pack(anchor=tk.W, padx=8)
            spark = Sparkline(spark_frame, color=color)
            spark.pack(anchor=tk.W, padx=8, pady=2)
            setattr(self, f"_spark_{label.lower()}", spark)

    # ── Alerts Tab ───────────────────────────────────────────────────────────

    def _build_alerts(self):
        p = ttk.Frame(self._tab_alerts)
        p.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        toolbar = tk.Frame(p, bg=THEME["bg"])
        toolbar.pack(fill=tk.X, pady=(0, 6))

        ttk.Button(toolbar, text="⬇ Export CSV",
                   command=self._export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="🗑 Clear",
                   command=self._clear_alerts).pack(side=tk.LEFT, padx=4)

        cols = ("time", "src_ip", "type", "rate", "severity", "blocked")
        self._alert_tree = ttk.Treeview(p, columns=cols, show="headings",
                                        selectmode="browse")
        hdrs = {"time": ("Timestamp", 150),
                "src_ip": ("Source IP", 130),
                "type": ("Attack Type", 130),
                "rate": ("Rate (c/s)", 100),
                "severity": ("Severity", 90),
                "blocked": ("Blocked", 80)}
        for col, (txt, w) in hdrs.items():
            self._alert_tree.heading(col, text=txt)
            self._alert_tree.column(col, width=w, anchor=tk.CENTER)

        # Tag colours
        for sev, color in SEV_COLOR.items():
            self._alert_tree.tag_configure(sev, foreground=color)

        sb = ttk.Scrollbar(p, orient=tk.VERTICAL,
                           command=self._alert_tree.yview)
        self._alert_tree.configure(yscrollcommand=sb.set)
        self._alert_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # ── IP Monitor Tab ────────────────────────────────────────────────────────

    def _build_ip_monitor(self):
        p = ttk.Frame(self._tab_ips)
        p.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        toolbar = tk.Frame(p, bg=THEME["bg"])
        toolbar.pack(fill=tk.X, pady=(0, 6))

        self._block_ip_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self._block_ip_var, width=18).pack(
            side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="🚫 Block IP",
                   command=self._manual_block).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="🔄 Refresh",
                   command=self._refresh_ip_table).pack(side=tk.LEFT, padx=4)

        cols = ("ip", "rate", "status")
        self._ip_tree = ttk.Treeview(p, columns=cols, show="headings")
        self._ip_tree.heading("ip",     text="Source IP")
        self._ip_tree.heading("rate",   text="Rate (conn/s)")
        self._ip_tree.heading("status", text="Status")
        self._ip_tree.column("ip",     width=200, anchor=tk.CENTER)
        self._ip_tree.column("rate",   width=160, anchor=tk.CENTER)
        self._ip_tree.column("status", width=120, anchor=tk.CENTER)

        self._ip_tree.tag_configure("blocked",  foreground=THEME["accent2"])
        self._ip_tree.tag_configure("watching", foreground=THEME["warn"])
        self._ip_tree.tag_configure("normal",   foreground=THEME["accent3"])

        sb = ttk.Scrollbar(p, orient=tk.VERTICAL, command=self._ip_tree.yview)
        self._ip_tree.configure(yscrollcommand=sb.set)
        self._ip_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # ── Charts Tab ────────────────────────────────────────────────────────────

    def _build_charts(self):
        p = ttk.Frame(self._tab_charts)
        p.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        self._live_chart = LiveChart(p, title="Connection Rate by Protocol (last 60s)")
        self._live_chart.pack(fill=tk.BOTH, expand=True)
        self._live_chart.add_series("TCP",  THEME["accent"])
        self._live_chart.add_series("UDP",  THEME["accent2"])
        self._live_chart.add_series("HTTP", THEME["accent3"])

        if not HAS_MPL:
            note = tk.Label(
                p,
                text="📦  Install matplotlib for charts:  pip install matplotlib",
                bg=THEME["bg2"], fg=THEME["warn"], font=THEME["font_body"]
            )
            note.pack(pady=4)

        # Attack-type breakdown bar (canvas)
        bar_frame = tk.LabelFrame(p, text=" Attack Type Distribution ",
                                  bg=THEME["bg2"], fg=THEME["accent"],
                                  font=THEME["font_head"])
        bar_frame.pack(fill=tk.X, pady=(8, 0))
        self._bar_canvas = tk.Canvas(bar_frame, height=60, bg=THEME["bg3"],
                                     highlightthickness=0)
        self._bar_canvas.pack(fill=tk.X, padx=8, pady=6)

    def _draw_attack_bars(self):
        c = self._bar_canvas
        c.delete("all")
        counts = self._attack_type_counts
        if not counts:
            c.create_text(10, 30, text="No attacks detected yet.",
                          fill=THEME["text_dim"], anchor=tk.W,
                          font=THEME["font_small"])
            return
        total = sum(counts.values()) or 1
        w = c.winfo_width() or 400
        colors = [THEME["accent"], THEME["accent2"], THEME["accent3"],
                  THEME["warn"], THEME["critical"], THEME["text_dim"]]
        x = 5
        for i, (atype, cnt) in enumerate(sorted(counts.items(),
                                                  key=lambda x: -x[1])):
            bar_w = max(2, int((cnt / total) * (w - 10)))
            col = colors[i % len(colors)]
            c.create_rectangle(x, 10, x + bar_w, 40, fill=col, outline="")
            icon = ATTACK_ICON.get(atype, "•")
            label = f"{icon} {atype} ({cnt})"
            c.create_text(x + 4, 50, text=label, fill=col, anchor=tk.W,
                          font=THEME["font_small"])
            x += bar_w + 4

    # ── Settings Tab ─────────────────────────────────────────────────────────

    def _build_settings(self):
        p = ttk.Frame(self._tab_settings)
        p.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        canvas = tk.Canvas(p, bg=THEME["bg2"], highlightthickness=0)
        sb = ttk.Scrollbar(p, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        inner = tk.Frame(canvas, bg=THEME["bg2"])
        canvas.create_window((0, 0), window=inner, anchor=tk.NW)
        inner.bind("<Configure>", lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))

        self._sv = {}  # string vars keyed by config key

        def section(title):
            tk.Label(inner, text=title, bg=THEME["bg2"], fg=THEME["accent"],
                     font=THEME["font_head"]).grid(
                row=section.row, column=0, columnspan=3,
                sticky=tk.W, padx=8, pady=(12, 4))
            ttk.Separator(inner, orient=tk.HORIZONTAL).grid(
                row=section.row+1, column=0, columnspan=3,
                sticky=tk.EW, padx=8, pady=2)
            section.row += 2
        section.row = 0

        def field(key, label, is_bool=False, is_int=False):
            r = section.row; section.row += 1
            tk.Label(inner, text=label, bg=THEME["bg2"], fg=THEME["text"],
                     font=THEME["font_body"]).grid(
                row=r, column=0, sticky=tk.W, padx=12, pady=3)
            if is_bool:
                var = tk.BooleanVar(value=bool(self.cfg.get(key, False)))
                self._sv[key] = var
                ttk.Checkbutton(inner, variable=var).grid(
                    row=r, column=1, sticky=tk.W, padx=8)
            else:
                var = tk.StringVar(value=str(self.cfg.get(key, "")))
                self._sv[key] = var
                ttk.Entry(inner, textvariable=var, width=28).grid(
                    row=r, column=1, sticky=tk.W, padx=8)

        section("🔍 Detection Thresholds")
        field("threshold_connections",   "TCP Connections threshold")
        field("threshold_period",        "Time window (seconds)")
        field("udp_threshold",           "UDP Flood threshold")
        field("syn_threshold",           "SYN Flood threshold")
        field("http_threshold",          "HTTP Flood threshold")
        field("slowloris_threshold",     "Slowloris threshold")
        field("amplification_threshold", "Amplification threshold")
        field("monitored_ports",         "Monitored ports (comma-sep)")

        section("🚫 Auto-Blocking")
        field("auto_block",    "Enable auto-blocking",   is_bool=True)
        field("block_duration","Block duration (seconds)")

        section("📧 Email Alerts")
        field("email_alerts",   "Enable email alerts",    is_bool=True)
        field("email_smtp",     "SMTP server")
        field("email_port",     "SMTP port")
        field("email_user",     "Sender email")
        field("email_password", "Password")
        field("email_to",       "Alert recipient")

        section("📁 Files")
        field("log_file",   "Log file path")
        field("csv_export", "CSV export path")

        ttk.Button(inner, text="💾 Save Settings",
                   command=self._save_settings).grid(
            row=section.row, column=0, columnspan=2,
            padx=12, pady=16, sticky=tk.W)

    # ── Logs Tab ─────────────────────────────────────────────────────────────

    def _build_logs(self):
        p = ttk.Frame(self._tab_logs)
        p.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        toolbar = tk.Frame(p, bg=THEME["bg"])
        toolbar.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(toolbar, text="🔄 Refresh",
                   command=self._refresh_logs).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="🗑 Clear Log",
                   command=self._clear_log).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="📂 Open Log File",
                   command=self._open_log_file).pack(side=tk.LEFT, padx=4)

        self._log_text = scrolledtext.ScrolledText(
            p, bg=THEME["bg3"], fg=THEME["text"],
            font=("Courier New", 9),
            insertbackground=THEME["accent"],
            highlightthickness=0
        )
        self._log_text.pack(fill=tk.BOTH, expand=True)
        # Tag colours for log levels
        self._log_text.tag_configure("WARNING",  foreground=THEME["warn"])
        self._log_text.tag_configure("ERROR",    foreground=THEME["accent2"])
        self._log_text.tag_configure("CRITICAL", foreground=THEME["critical"])
        self._log_text.tag_configure("INFO",     foreground=THEME["text_dim"])

        self._refresh_logs()

    # ── Periodic Tick ─────────────────────────────────────────────────────────

    def _tick(self):
        # Drain event queue
        while not self.event_queue.empty():
            try:
                event: AttackEvent = self.event_queue.get_nowait()
                self._process_event(event)
            except queue.Empty:
                break

        # Update cards
        top_talkers = self.detector.get_top_talkers(1)
        rate_str = f"{top_talkers[0][1]:.0f}/s" if top_talkers else "0/s"
        self._card_rate.set(rate_str)
        self._card_blocked.set(str(len(self.blocker.blocked)))
        if self._attack_type_counts:
            top = max(self._attack_type_counts, key=self._attack_type_counts.get)
            self._card_top_type.set(
                f"{ATTACK_ICON.get(top,'•')} {top.replace('_',' ').title()}"
            )

        # Push sparklines (total traffic proxy from top talkers)
        total_rate = sum(r for _, r in self.detector.get_top_talkers(50))
        self._spark_tcp.push(total_rate)
        self._spark_udp.push(total_rate * 0.1)   # placeholder split
        self._spark_http.push(total_rate * 0.3)

        # Push live chart
        self._live_chart.push("TCP",  total_rate)
        self._live_chart.push("UDP",  total_rate * 0.1)
        self._live_chart.push("HTTP", total_rate * 0.3)

        # Redraw attack bars
        self._draw_attack_bars()

        # Refresh IP table every 3 ticks (3s)
        if not hasattr(self, "_tick_n"):
            self._tick_n = 0
        self._tick_n += 1
        if self._tick_n % 3 == 0:
            self._refresh_ip_table()

        self.root.after(1000, self._tick)

    def _process_event(self, event: AttackEvent):
        self.total_attacks += 1
        self.attack_log.appendleft(event)
        self._attack_type_counts[event.attack_type] = \
            self._attack_type_counts.get(event.attack_type, 0) + 1

        # Update card
        self._card_total.set(str(self.total_attacks), THEME["accent2"])

        # Dashboard event list
        icon = ATTACK_ICON.get(event.attack_type, "•")
        line = (f"[{event.timestamp[-8:]}] {icon} {event.attack_type.upper()} "
                f"from {event.source_ip}  [{event.severity}]")
        self._evt_list.insert(0, line)
        clr = SEV_COLOR.get(event.severity, THEME["text"])
        self._evt_list.itemconfig(0, {"fg": clr})
        if self._evt_list.size() > 50:
            self._evt_list.delete(50, tk.END)

        # Alerts treeview
        self._alert_tree.insert(
            "", 0,
            values=(event.timestamp, event.source_ip,
                    f"{ATTACK_ICON.get(event.attack_type,'')} {event.attack_type}",
                    f"{event.rate:.1f}", event.severity,
                    "✅" if event.blocked else "—"),
            tags=(event.severity,)
        )

        # CSV + email
        self.csv_log.log(event)
        self.emailer.send(event)

    # ── Button Handlers ───────────────────────────────────────────────────────

    def _refresh_ip_table(self):
        for row in self._ip_tree.get_children():
            self._ip_tree.delete(row)
        for ip, rate in self.detector.get_top_talkers(30):
            if self.blocker.is_blocked(ip):
                status, tag = "🚫 BLOCKED", "blocked"
            elif rate > self.cfg["threshold_connections"] / self.cfg["threshold_period"]:
                status, tag = "⚠ WATCHING", "watching"
            else:
                status, tag = "✓ OK", "normal"
            self._ip_tree.insert("", tk.END,
                                 values=(ip, f"{rate:.1f}", status),
                                 tags=(tag,))

    def _manual_block(self):
        ip = self._block_ip_var.get().strip()
        if not ip:
            return
        if self.blocker.block(ip, self.cfg["block_duration"]):
            messagebox.showinfo("Blocked", f"IP {ip} blocked for "
                                f"{self.cfg['block_duration']}s")
        else:
            messagebox.showwarning("Already Blocked",
                                   f"{ip} is already blocked or could not be blocked.")

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"ddos_export_{datetime.now():%Y%m%d_%H%M%S}.csv"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Timestamp","Source IP","Target IP","Port",
                             "Attack Type","Rate","Severity","Blocked"])
                for ev in self.attack_log:
                    w.writerow([ev.timestamp, ev.source_ip, ev.target_ip,
                                 ev.target_port, ev.attack_type,
                                 ev.rate, ev.severity, ev.blocked])
            messagebox.showinfo("Exported", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _clear_alerts(self):
        for row in self._alert_tree.get_children():
            self._alert_tree.delete(row)
        self.attack_log.clear()
        self.total_attacks = 0
        self._card_total.set("0")

    def _save_settings(self):
        try:
            for key, var in self._sv.items():
                raw = var.get()
                if isinstance(raw, bool):
                    self.cfg[key] = raw
                elif key == "monitored_ports":
                    self.cfg[key] = [int(x.strip())
                                     for x in str(raw).split(",") if x.strip()]
                else:
                    # Try int, then float, then str
                    try:
                        self.cfg[key] = int(raw)
                    except ValueError:
                        try:
                            self.cfg[key] = float(raw)
                        except ValueError:
                            self.cfg[key] = str(raw)
            save_config(self.cfg)
            # Propagate live thresholds
            self.detector.cfg = self.cfg
            self.monitor.cfg  = self.cfg
            messagebox.showinfo("Saved", "Settings saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _refresh_logs(self):
        self._log_text.delete("1.0", tk.END)
        try:
            with open(self.cfg["log_file"]) as f:
                lines = f.readlines()
        except Exception:
            lines = ["(log file not found)\n"]

        for line in lines:
            level = "INFO"
            for lvl in ("CRITICAL", "ERROR", "WARNING", "INFO"):
                if lvl in line:
                    level = lvl
                    break
            self._log_text.insert(tk.END, line, level)
        self._log_text.see(tk.END)

    def _clear_log(self):
        try:
            with open(self.cfg["log_file"], "w"):
                pass
            self._log_text.delete("1.0", tk.END)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _open_log_file(self):
        import subprocess, sys
        path = self.cfg["log_file"]
        try:
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _on_close(self):
        if messagebox.askokcancel("Quit", "Stop detection and exit?"):
            self.monitor.stop()
            self.poller.stop()
            self.root.destroy()


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    DDosDetectorApp()
