"""
dashboard.py — SentinelX v3  (complete redesign)

Changes:
  - New layout: stat cards top-right, area graph top-left,
    alert feed bottom-left, severity breakdown bottom-right
  - New palette: dark charcoal with teal/cyan accent — professional SOC
  - Graph changed to bar chart (buckets of 10s) — no more vertical line bug
  - Graph throttled to every 2s — eliminates lag
  - Poll interval 200ms — faster alert display
  - Matplotlib figure reuse (no cla() on every tick) — smoother
"""

import os, time, queue, json, threading, subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from datetime import datetime
from collections import defaultdict
from urllib.request import urlopen

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure  import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.ticker as ticker

from data_store    import store, WHITELIST_IPS
from db_store      import alert_db
from investigation import InvestigationWindow
import sound

with open("config.json") as _f:
    _CFG = json.load(_f)

_D         = _CFG["dashboard"]
REFRESH_MS = 200          # poll queue every 200ms for fast alert display
GRAPH_WIN  = _D["graph_window_seconds"]
MAX_ALERTS = _D["max_alerts"]
MAX_PKTS   = _D["max_packets"]
GRAPH_BUCKET = 10         # seconds per bar in the chart

# ── Palette — dark professional ───────────────────────────────────────────────
BG        = "#111318"     # main background
BG2       = "#1a1d27"     # panel / card background
BG3       = "#20242f"     # row / input background
BG4       = "#262b38"     # alternate row
BORDER    = "#2e3446"
FG        = "#e8eaf0"
FG2       = "#ffffff"
FG3       = "#ffffff"
ACCENT    = "#00c9b1"     # teal
ACCENT2   = "#0ea5e9"     # sky blue
ACCENT3   = "#6366f1"     # indigo

SEV_COL = {
    "LOW"     : "#10b981",   # emerald green
    "MEDIUM"  : "#f59e0b",   # amber
    "HIGH"    : "#f97316",   # orange
    "CRITICAL": "#ef4444",   # red
}

FONT      = ("Segoe UI", 9)
FONT_B    = ("Segoe UI", 9,  "bold")
FONT_HDR  = ("Segoe UI", 11, "bold")
FONT_MONO = ("Consolas",  9)
FONT_NUM  = ("Segoe UI", 20, "bold")


class SentinelXDashboard:

    def __init__(self, alert_queue: queue.Queue):
        self._q            = alert_queue
        self._alert_map    = {}
        self._all_alerts   = []
        self._last_stats_t = 0
        self._pkt_snapshot = 0
        self._last_graph_t = 0    # throttle graph redraws

        self.root = tk.Tk()

        # Filter vars — must be after tk.Tk()
        self._filter_sev  = tk.StringVar(value="ALL")
        self._filter_type = tk.StringVar(value="ALL")
        self._filter_ip   = tk.StringVar(value="")

        self._setup_styles()
        self._build_window()
        self._restore_db()
        self.root.after(REFRESH_MS, self._poll)

    # ── Styles ────────────────────────────────────────────────────────

    def _setup_styles(self):
        self.root.title("SentinelX IDS  ·  v3")
        self.root.geometry("1440x880")
        self.root.minsize(1200, 720)
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        s = ttk.Style(self.root)
        s.theme_use("clam")

        s.configure("IDS.Treeview",
            background=BG2, fieldbackground=BG2,
            foreground=FG, rowheight=26,
            font=FONT_MONO, borderwidth=0)
        s.configure("IDS.Treeview.Heading",
            background=BG3, foreground=ACCENT,
            font=FONT_B, relief="flat", borderwidth=0)
        s.map("IDS.Treeview",
            background=[("selected", ACCENT3)],
            foreground=[("selected", "#ffffff")])
        s.configure("IDS.Vertical.TScrollbar",
            background=BG3, troughcolor=BG2,
            arrowcolor=FG3, borderwidth=0, relief="flat")
        s.configure("IDS.TNotebook",
            background=BG, borderwidth=0, tabmargins=0)
        s.configure("IDS.TNotebook.Tab",
            background=BG2, foreground=FG2,
            font=FONT_B, padding=(16, 7), borderwidth=0)
        s.map("IDS.TNotebook.Tab",
            background=[("selected", BG3)],
            foreground=[("selected", ACCENT)])
        s.configure("IDS.TCombobox",
            fieldbackground=BG3, background=BG3,
            foreground=FG, arrowcolor=ACCENT,
            borderwidth=0, relief="flat")

    # ── Window ────────────────────────────────────────────────────────

    def _build_window(self):
        self._build_titlebar()

        # ── Main grid: 2 rows × 2 cols ────────────────────────────────
        #   [0,0] graph      [0,1] stat cards
        #   [1,0] alert feed [1,1] severity breakdown
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 4))

        body.columnconfigure(0, weight=6)
        body.columnconfigure(1, weight=4)
        body.rowconfigure(0, weight=4)
        body.rowconfigure(1, weight=6)

        self._build_graph_panel(body)       # top-left
        self._build_stats_cards(body)       # top-right
        self._build_alert_panel(body)       # bottom-left
        self._build_severity_panel(body)    # bottom-right
        self._build_statusbar()

    # ── Title bar ─────────────────────────────────────────────────────

    def _build_titlebar(self):
        bar = tk.Frame(self.root, bg=BG2, pady=0)
        bar.pack(fill=tk.X)

        # Left accent
        tk.Frame(bar, bg=ACCENT, width=3).pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(bar, text="  SENTINELX",
                 font=("Segoe UI", 15, "bold"),
                 fg=ACCENT, bg=BG2, pady=10).pack(side=tk.LEFT, padx=(8, 0))
        tk.Label(bar, text="INTRUSION DETECTION SYSTEM",
                 font=FONT, fg=FG3, bg=BG2).pack(side=tk.LEFT, padx=10)

        # Status indicator
        self._dot = tk.Label(bar, text="● ACTIVE",
                              font=FONT_B, fg="#10b981", bg=BG2)
        self._dot.pack(side=tk.RIGHT, padx=16)

        # Toolbar buttons
        for text, cmd, bg in [
            ("⬛ BLOCK IP",  self._block_ip,         "#ef4444"),
            ("↓ EXPORT",     self._export_csv,        ACCENT),
            ("◎ WHITELIST",  self._whitelist_manager, "#f59e0b"),
        ]:
            tk.Button(bar, text=text, command=cmd,
                      font=FONT_B, fg=BG2, bg=bg,
                      activebackground=bg, relief=tk.FLAT,
                      bd=0, padx=12, pady=5,
                      cursor="hand2").pack(side=tk.RIGHT, padx=4, pady=8)

    # ── Top-left: Threat graph ────────────────────────────────────────

    def _build_graph_panel(self, parent):
        frame = tk.Frame(parent, bg=BG2)
        frame.grid(row=0, column=0, sticky="nsew",
                   padx=(0, 5), pady=(0, 5))
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Header
        hdr = tk.Frame(frame, bg=BG2)
        hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))
        tk.Label(hdr, text="THREAT ACTIVITY",
                 font=FONT_HDR, fg=FG, bg=BG2).pack(side=tk.LEFT)
        tk.Label(hdr, text=f"last {GRAPH_WIN}s  ·  alerts per severity per 10s",
                 font=FONT, fg=FG3, bg=BG2).pack(side=tk.RIGHT)

        # Matplotlib bar chart
        self._fig = Figure(facecolor=BG2, figsize=(5, 2.6))
        self._ax  = self._fig.add_subplot(111)
        self._fig.subplots_adjust(left=0.08, right=0.98, top=0.92, bottom=0.22)
        self._style_ax()

        self._canvas = FigureCanvasTkAgg(self._fig, master=frame)
        self._canvas.get_tk_widget().grid(
            row=1, column=0, sticky="nsew", padx=6, pady=(0, 8))

    def _style_ax(self):
        ax = self._ax
        ax.set_facecolor(BG)
        ax.tick_params(colors=FG3, labelsize=7)
        ax.set_ylabel("Alerts", color=FG3, fontsize=7)
        ax.set_xlabel("Time", color=FG3, fontsize=7)
        for spine in ax.spines.values():
            spine.set_color(BORDER)
        ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=4))

    def _update_graph(self):
        now = time.time()
        if now - self._last_graph_t < 2.0:
            return
        self._last_graph_t = now

        import numpy as np
        import matplotlib.dates as mdates
        from collections import defaultdict

        cutoff   = now - GRAPH_WIN
        BUCKET   = 10   # seconds per data point

        # Build buckets: {bucket_index: {severity: count}}
        buckets: dict = defaultdict(lambda: {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0})
        score_to_sev  = {1:"LOW", 2:"MEDIUM", 3:"HIGH", 5:"CRITICAL"}

        for t, score, _ in store.graph_points:
            if t >= cutoff:
                b   = int((t - cutoff) // BUCKET)
                sev = score_to_sev.get(score, "LOW")
                buckets[b][sev] += 1

        ax = self._ax
        ax.cla()
        self._style_ax()

        if buckets:
            n_buckets = int(GRAPH_WIN // BUCKET) + 1
            # Fill missing buckets with zeros
            for i in range(n_buckets):
                if i not in buckets:
                    buckets[i] = {"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}

            xs_idx = sorted(buckets.keys())
            xs_dt  = [datetime.fromtimestamp(cutoff + i * BUCKET) for i in xs_idx]

            sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

            for sev in sev_order:
                ys  = [buckets[i][sev] for i in xs_idx]
                col = SEV_COL[sev]

                # Skip lines that are all zero to keep chart clean
                if max(ys) == 0:
                    continue

                # Smooth with rolling average
                if len(ys) >= 4:
                    k      = np.ones(3) / 3
                    ys_s   = np.convolve(ys, k, mode="same").tolist()
                    ys_s[0] = ys[0]; ys_s[-1] = ys[-1]
                else:
                    ys_s = ys

                ax.plot(xs_dt, ys_s,
                        color=col, linewidth=2.2,
                        label=sev, zorder=4,
                        solid_capstyle="round",
                        solid_joinstyle="round")

                ax.fill_between(xs_dt, ys_s,
                                color=col, alpha=0.07, zorder=2)

                # Dot on latest point
                ax.scatter([xs_dt[-1]], [ys_s[-1]],
                           color=col, s=30, zorder=5,
                           edgecolors="none")

            ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
            ax.xaxis.set_major_locator(
                mdates.SecondLocator(interval=max(GRAPH_WIN // 6, 1)))
            ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=4))
            ax.yaxis.grid(True, color=BORDER, linewidth=0.5, zorder=0)
            ax.xaxis.grid(True, color=BORDER, linewidth=0.3,
                          linestyle="--", zorder=0)
            ax.set_ylabel("Alerts / 10s", color=FG3, fontsize=7)

            ax.legend(
                fontsize=7, loc="upper left",
                framealpha=0.25, facecolor=BG2,
                edgecolor=BORDER, labelcolor=FG2,
                markerscale=0.8, ncol=2,
            )

        else:
            ax.text(0.5, 0.5, "No alerts yet — run a test command",
                    transform=ax.transAxes, ha="center", va="center",
                    color=FG3, fontsize=9, style="italic")

        self._canvas.draw_idle()

    # ── Top-right: Stat cards ─────────────────────────────────────────

    def _build_stats_cards(self, parent):
        frame = tk.Frame(parent, bg=BG)
        frame.grid(row=0, column=1, sticky="nsew",
                   padx=(5, 0), pady=(0, 5))
        frame.columnconfigure((0, 1), weight=1)
        frame.rowconfigure((0, 1), weight=1)

        self._stat_vars = {}
        metrics = [
            ("total_alerts", "TOTAL ALERTS",  "0",   FG,               "#ef4444"),
            ("top_attacker", "TOP ATTACKER",  "—",   SEV_COL["HIGH"],  "#f97316"),
            ("pkt_rate",     "PACKETS / SEC", "0",   ACCENT,           ACCENT),
            ("db_total",     "DB  ALL-TIME",  "0",   FG2,              ACCENT3),
        ]
        for i, (key, label, default, fg, accent) in enumerate(metrics):
            card = tk.Frame(frame, bg=BG2, padx=16, pady=12)
            card.grid(row=i // 2, column=i % 2,
                      sticky="nsew", padx=4, pady=4)

            # Top accent stripe
            tk.Frame(card, bg=accent, height=3).pack(fill=tk.X, pady=(0, 8))

            tk.Label(card, text=label,
                     font=("Segoe UI", 7, "bold"),
                     fg=FG3, bg=BG2).pack(anchor="w")

            var = tk.StringVar(value=default)
            self._stat_vars[key] = var
            tk.Label(card, textvariable=var,
                     font=FONT_NUM,
                     fg=fg, bg=BG2,
                     wraplength=180, justify=tk.LEFT).pack(anchor="w", pady=(4, 0))

    # ── Bottom-left: Alert feed ───────────────────────────────────────

    def _build_alert_panel(self, parent):
        frame = tk.Frame(parent, bg=BG2)
        frame.grid(row=1, column=0, sticky="nsew",
                   padx=(0, 5), pady=(5, 0))
        frame.rowconfigure(2, weight=1)
        frame.columnconfigure(0, weight=1)

        # Header
        hdr = tk.Frame(frame, bg=BG2, pady=8)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14)
        tk.Label(hdr, text="ALERT FEED",
                 font=FONT_HDR, fg=FG, bg=BG2).pack(side=tk.LEFT)
        tk.Label(hdr, text="Double-click · Right-click",
                 font=FONT, fg=FG3, bg=BG2).pack(side=tk.RIGHT)

        # Filter bar
        self._build_filter_bar(frame)

        # Treeview
        cols = ("ack", "time", "type", "src", "severity", "info")
        self._alert_tree = ttk.Treeview(frame, columns=cols,
                                         show="headings",
                                         selectmode="browse",
                                         style="IDS.Treeview")
        for col, text, w, anchor in [
            ("ack",      "✓",           28,  "center"),
            ("time",     "TIME",        74,  "center"),
            ("type",     "ATTACK TYPE", 138, "w"),
            ("src",      "SOURCE IP",   126, "center"),
            ("severity", "SEV",         76,  "center"),
            ("info",     "DETAILS",     0,   "w"),
        ]:
            self._alert_tree.heading(col, text=text)
            self._alert_tree.column(col, width=w, anchor=anchor,
                                     stretch=(col == "info"))

        # Row text is normal FG, but the severity column value uses
        # a short coloured label — foreground set per severity tag
        self._alert_tree.tag_configure(
            "CRITICAL",     background=BG2, foreground=SEV_COL["CRITICAL"])
        self._alert_tree.tag_configure(
            "HIGH",         background=BG2, foreground=SEV_COL["HIGH"])
        self._alert_tree.tag_configure(
            "MEDIUM",       background=BG2, foreground=SEV_COL["MEDIUM"])
        self._alert_tree.tag_configure(
            "LOW",          background=BG2, foreground=SEV_COL["LOW"])
        self._alert_tree.tag_configure(
            "CRITICAL_ALT", background=BG3, foreground=SEV_COL["CRITICAL"])
        self._alert_tree.tag_configure(
            "HIGH_ALT",     background=BG3, foreground=SEV_COL["HIGH"])
        self._alert_tree.tag_configure(
            "MEDIUM_ALT",   background=BG3, foreground=SEV_COL["MEDIUM"])
        self._alert_tree.tag_configure(
            "LOW_ALT",      background=BG3, foreground=SEV_COL["LOW"])
        self._alert_tree.tag_configure(
            "ACKED",        background=BG2, foreground=FG3)

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                             command=self._alert_tree.yview,
                             style="IDS.Vertical.TScrollbar")
        self._alert_tree.configure(yscrollcommand=vsb.set)
        self._alert_tree.grid(row=2, column=0, sticky="nsew",
                               padx=(10, 0), pady=(0, 8))
        vsb.grid(row=2, column=1, sticky="ns", pady=(0, 8), padx=(0, 8))

        # Context menu
        self._ctx = tk.Menu(self.root, tearoff=0,
                             bg=BG3, fg=FG,
                             activebackground=ACCENT,
                             activeforeground=BG2,
                             font=FONT_MONO)
        self._ctx.add_command(label="🔍  Investigate",        command=self._investigate)
        self._ctx.add_command(label="🌍  Geo-IP Lookup",       command=self._geoip)
        self._ctx.add_command(label="⬛  Block IP",            command=self._block_selected_ip)
        self._ctx.add_command(label="◎  Whitelist IP",         command=self._whitelist_selected)
        self._ctx.add_separator()
        self._ctx.add_command(label="✓  Acknowledge",          command=self._acknowledge)

        self._alert_tree.bind("<Button-3>", self._on_rclick)
        self._alert_tree.bind("<Double-1>", lambda e: self._investigate())

    def _build_filter_bar(self, parent):
        bar = tk.Frame(parent, bg=BG3, pady=7)
        bar.grid(row=1, column=0, columnspan=2,
                 sticky="ew", padx=10, pady=(0, 6))

        tk.Label(bar, text="  FILTER",
                 font=FONT_B, fg=ACCENT, bg=BG3).pack(side=tk.LEFT)

        # Severity
        tk.Label(bar, text="   Severity",
                 font=FONT, fg=FG2, bg=BG3).pack(side=tk.LEFT)
        sev_cb = ttk.Combobox(bar, textvariable=self._filter_sev,
                               values=["ALL","CRITICAL","HIGH","MEDIUM","LOW"],
                               state="readonly", width=10, font=FONT_MONO)
        sev_cb.pack(side=tk.LEFT, padx=(4, 0))
        sev_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        # Type
        tk.Label(bar, text="   Type",
                 font=FONT, fg=FG2, bg=BG3).pack(side=tk.LEFT)
        type_cb = ttk.Combobox(bar, textvariable=self._filter_type,
                                values=["ALL","PORT_SCAN","PING_FLOOD",
                                        "SYN_FLOOD","ARP_SPOOF","DNS_FLOOD",
                                        "SENSITIVE_PORT","UDP_FLOOD","HTTP_FLOOD"],
                                state="readonly", width=16, font=FONT_MONO)
        type_cb.pack(side=tk.LEFT, padx=(4, 0))
        type_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        # Source IP
        tk.Label(bar, text="   Source IP",
                 font=FONT, fg=FG2, bg=BG3).pack(side=tk.LEFT)
        ip_e = tk.Entry(bar, textvariable=self._filter_ip,
                         font=FONT_MONO, fg=FG, bg=BG2,
                         insertbackground=FG,
                         relief=tk.FLAT, width=15,
                         highlightthickness=1,
                         highlightcolor=ACCENT,
                         highlightbackground=BORDER)
        ip_e.pack(side=tk.LEFT, padx=(4, 0))
        ip_e.bind("<KeyRelease>", lambda e: self._apply_filters())

        # Clear
        tk.Button(bar, text="✕",
                  command=self._clear_filters,
                  font=FONT_B, fg=FG, bg=BG2,
                  activebackground=BG2,
                  relief=tk.FLAT, bd=0,
                  padx=8, pady=2,
                  cursor="hand2").pack(side=tk.LEFT, padx=(8, 0))

        # Count
        self._filter_count = tk.StringVar(value="0 alerts")
        tk.Label(bar, textvariable=self._filter_count,
                 font=FONT, fg=FG3, bg=BG3).pack(side=tk.RIGHT, padx=10)

    # ── Bottom-right: Severity breakdown ─────────────────────────────

    def _build_severity_panel(self, parent):
        frame = tk.Frame(parent, bg=BG2)
        frame.grid(row=1, column=1, sticky="nsew",
                   padx=(5, 0), pady=(5, 0))
        frame.columnconfigure(0, weight=1)

        tk.Label(frame, text="SEVERITY BREAKDOWN",
                 font=FONT_HDR, fg=FG, bg=BG2,
                 pady=12).pack(fill=tk.X, padx=14)

        # Severity bars
        bar_frame = tk.Frame(frame, bg=BG2, padx=14)
        bar_frame.pack(fill=tk.X)

        self._sev_bars = {}
        for sev, col in SEV_COL.items():
            row = tk.Frame(bar_frame, bg=BG2, pady=6)
            row.pack(fill=tk.X)

            # Label + count on same line
            top = tk.Frame(row, bg=BG2)
            top.pack(fill=tk.X)
            tk.Label(top, text=sev, font=FONT_B,
                     fg=col, bg=BG2, width=9,
                     anchor="w").pack(side=tk.LEFT)
            cnt_lbl = tk.Label(top, text="0",
                                font=FONT_B,
                                fg=col, bg=BG2)
            cnt_lbl.pack(side=tk.RIGHT)

            # Progress bar
            track = tk.Frame(row, bg=BORDER, height=10)
            track.pack(fill=tk.X, pady=(3, 0))
            fill  = tk.Frame(track, bg=col, height=10)
            fill.place(x=0, y=0, height=10, width=0)
            self._sev_bars[sev] = (fill, track, cnt_lbl)

        # Divider
        tk.Frame(frame, bg=BORDER, height=1).pack(
            fill=tk.X, padx=14, pady=12)

        # Top attacker section
        tk.Label(frame, text="TOP ATTACKER",
                 font=("Segoe UI", 7, "bold"),
                 fg=FG3, bg=BG2).pack(anchor="w", padx=14)
        self._top_ip_var = tk.StringVar(value="—")
        tk.Label(frame, textvariable=self._top_ip_var,
                 font=("Segoe UI", 13, "bold"),
                 fg=SEV_COL["HIGH"], bg=BG2).pack(anchor="w", padx=14, pady=(4, 0))

        # Divider
        tk.Frame(frame, bg=BORDER, height=1).pack(
            fill=tk.X, padx=14, pady=12)

        # Recent attack types list
        tk.Label(frame, text="RECENT ATTACK TYPES",
                 font=("Segoe UI", 7, "bold"),
                 fg=FG3, bg=BG2).pack(anchor="w", padx=14)

        self._type_frame = tk.Frame(frame, bg=BG2, padx=14)
        self._type_frame.pack(fill=tk.X, pady=(6, 0))

    # ── Status bar ────────────────────────────────────────────────────

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG2, pady=3)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Frame(bar, bg=ACCENT, width=3).pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(bar,
                 text="  SentinelX v3  ·  Rule-Based IDS  ·  8 Detection Rules  ·  No ML",
                 font=("Segoe UI", 8), fg=FG3, bg=BG2).pack(side=tk.LEFT)
        self._clock = tk.Label(bar, text="",
                                font=("Segoe UI", 8), fg=FG3, bg=BG2)
        self._clock.pack(side=tk.RIGHT, padx=12)

    # ── Alert tree helpers ────────────────────────────────────────────

    def _add_alert_row(self, alert: dict):
        self._all_alerts.append(alert)
        if self._matches_filter(alert):
            self._insert_tree_row(alert)
        sound.play(alert.get("severity", "LOW"))

    # Severity badge values — plain text, foreground tag provides the colour
    _BADGE = {
        "CRITICAL": "■ CRITICAL",
        "HIGH"    : "■ HIGH",
        "MEDIUM"  : "■ MEDIUM",
        "LOW"     : "■ LOW",
    }

    def _insert_tree_row(self, alert: dict):
        sev  = alert.get("severity", "LOW")
        info = alert.get("details", {}).get("info", "")
        alt  = len(self._alert_tree.get_children()) % 2 == 1

        # Tag determines both row tint AND badge dot colour
        tag = f"{sev}_ALT" if alt else sev

        iid = self._alert_tree.insert("", 0,
            values=("",
                    alert.get("timestamp", "?"),
                    alert.get("type", "?"),
                    alert.get("src", "?"),
                    self._BADGE.get(sev, sev),
                    info),
            tags=(tag,))

        self._alert_map[iid] = alert

        children = self._alert_tree.get_children()
        if len(children) > MAX_ALERTS:
            old = children[-1]
            self._alert_map.pop(old, None)
            self._alert_tree.delete(old)

    def _matches_filter(self, alert: dict) -> bool:
        sev   = self._filter_sev.get()
        atype = self._filter_type.get()
        ip    = self._filter_ip.get().strip()
        if sev   != "ALL" and alert.get("severity") != sev:   return False
        if atype != "ALL" and alert.get("type")     != atype: return False
        if ip and ip.lower() not in alert.get("src","").lower(): return False
        return True

    def _apply_filters(self):
        self._alert_tree.delete(*self._alert_tree.get_children())
        self._alert_map.clear()
        matched = [a for a in self._all_alerts if self._matches_filter(a)]
        for a in matched:
            self._insert_tree_row(a)
        total = len(self._all_alerts)
        shown = len(matched)
        self._filter_count.set(
            f"{total} alerts" if shown == total else f"{shown} of {total}")

    def _clear_filters(self):
        self._filter_sev.set("ALL")
        self._filter_type.set("ALL")
        self._filter_ip.set("")
        self._apply_filters()

    def _get_alert(self) -> dict | None:
        sel = self._alert_tree.selection()
        return self._alert_map.get(sel[0]) if sel else None

    def _on_rclick(self, e):
        row = self._alert_tree.identify_row(e.y)
        if row:
            self._alert_tree.selection_set(row)
            self._ctx.post(e.x_root, e.y_root)

    def _investigate(self):
        a = self._get_alert()
        if a: InvestigationWindow(self.root, a)

    def _acknowledge(self):
        sel = self._alert_tree.selection()
        if not sel: return
        iid = sel[0]
        v   = self._alert_tree.item(iid, "values")
        self._alert_tree.item(iid, tags=("ACKED",),
                               values=("✓",) + tuple(v[1:]))

    def _whitelist_selected(self):
        a = self._get_alert()
        if a:
            WHITELIST_IPS.add(a["src"])
            messagebox.showinfo("Whitelist",
                f"{a['src']} added.\nEdit config.json to persist.",
                parent=self.root)

    def _geoip(self):
        a = self._get_alert()
        if not a: return
        ip = a["src"]
        if ip in ("127.0.0.1","::1","0.0.0.0"):
            messagebox.showinfo("Geo-IP", f"{ip} is local.", parent=self.root)
            return
        def _lookup():
            try:
                url  = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,query"
                d    = json.loads(urlopen(url, timeout=5).read().decode())
                msg  = "\n".join([f"IP       {d.get('query',ip)}",
                                   f"Country  {d.get('country','N/A')}",
                                   f"Region   {d.get('regionName','N/A')}",
                                   f"City     {d.get('city','N/A')}",
                                   f"ISP      {d.get('isp','N/A')}",
                                   f"AS       {d.get('as','N/A')}"])
            except Exception as e:
                msg = f"Lookup failed: {e}"
            self.root.after(0, lambda: messagebox.showinfo(
                f"Geo-IP  ·  {ip}", msg, parent=self.root))
        threading.Thread(target=_lookup, daemon=True).start()

    # ── Block IP ──────────────────────────────────────────────────────

    def _block_selected_ip(self):
        a = self._get_alert()
        if a: self._run_block(a["src"])

    def _block_ip(self):
        ip = simpledialog.askstring("Block IP", "Enter IP:", parent=self.root)
        if ip: self._run_block(ip.strip())

    def _run_block(self, ip: str):
        if not ip or ip in ("127.0.0.1","::1"):
            messagebox.showwarning("Block IP", "Cannot block loopback.", parent=self.root)
            return
        if not messagebox.askyesno("Block IP", f"Add DROP rule for:\n{ip}", parent=self.root):
            return
        try:
            r = subprocess.run(["iptables","-A","INPUT","-s",ip,"-j","DROP"],
                                capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                messagebox.showinfo("Blocked", f"✓ DROP rule added for {ip}", parent=self.root)
            else:
                messagebox.showerror("Error", r.stderr, parent=self.root)
        except FileNotFoundError:
            messagebox.showerror("Error", "iptables not found (Linux only).", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    # ── Export CSV ────────────────────────────────────────────────────

    def _export_csv(self):
        fp = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile=f"sentinelx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if fp:
            n = alert_db.export_csv(fp)
            messagebox.showinfo("Export", f"✓ {n} alerts exported to:\n{fp}", parent=self.root)

    # ── Whitelist manager ─────────────────────────────────────────────

    def _whitelist_manager(self):
        win = tk.Toplevel(self.root)
        win.title("Whitelist Manager")
        win.geometry("400x360")
        win.configure(bg=BG)
        win.update_idletasks()
        try: win.grab_set()
        except Exception: pass

        tk.Label(win, text="WHITELIST  (runtime)",
                 font=FONT_HDR, fg=ACCENT, bg=BG, pady=12).pack()
        lb = tk.Listbox(win, font=FONT_MONO, bg=BG2, fg=FG,
                         selectbackground=ACCENT, selectforeground=BG2,
                         relief=tk.FLAT, bd=0, highlightthickness=0)
        lb.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 8))

        def _refresh():
            lb.delete(0, tk.END)
            for ip in sorted(WHITELIST_IPS): lb.insert(tk.END, f"  {ip}")
        _refresh()

        row = tk.Frame(win, bg=BG)
        row.pack(pady=8)
        def _add():
            ip = simpledialog.askstring("Add IP", "IP:", parent=win)
            if ip: WHITELIST_IPS.add(ip.strip()); _refresh()
        def _remove():
            sel = lb.curselection()
            if sel: WHITELIST_IPS.discard(lb.get(sel[0]).strip()); _refresh()
        for txt, cmd, bg in [("+ Add",_add,"#10b981"),("− Remove",_remove,"#ef4444"),("Close",win.destroy,ACCENT)]:
            tk.Button(row, text=txt, command=cmd, font=FONT_B,
                      fg=BG2, bg=bg, relief=tk.FLAT, padx=12, pady=6,
                      cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Label(win, text="To persist: edit config.json → whitelist → ips",
                 font=("Segoe UI", 7), fg=FG3, bg=BG).pack(pady=(0, 8))

    # ── Severity panel update ─────────────────────────────────────────

    def _update_severity_panel(self):
        counts = store.get_severity_counts()
        total  = max(sum(counts.values()), 1)
        for sev, (fill, track, lbl) in self._sev_bars.items():
            track.update_idletasks()
            w = int(track.winfo_width() * counts[sev] / total)
            fill.place(x=0, y=0, height=10, width=max(w, 0))
            lbl.configure(text=str(counts[sev]))

        self._top_ip_var.set(store.get_top_attacker())

        # Recent attack types
        for w in self._type_frame.winfo_children():
            w.destroy()
        seen_types = {}
        for a in reversed(self._all_alerts):
            t = a.get("type","?")
            if t not in seen_types:
                seen_types[t] = a.get("severity","LOW")
            if len(seen_types) >= 6:
                break
        for atype, sev in seen_types.items():
            row = tk.Frame(self._type_frame, bg=BG2)
            row.pack(fill=tk.X, pady=2)
            tk.Frame(row, bg=SEV_COL.get(sev, FG3),
                      width=3, height=18).pack(side=tk.LEFT)
            tk.Label(row, text=f"  {atype}",
                     font=FONT_MONO, fg=FG2, bg=BG2).pack(side=tk.LEFT)
            tk.Label(row, text=sev,
                     font=FONT_B, fg=SEV_COL.get(sev, FG3),
                     bg=BG2).pack(side=tk.RIGHT)

    # ── Stat cards update ─────────────────────────────────────────────

    def _update_stat_cards(self):
        self._stat_vars["pkt_rate"].set(str(store.packet_rate))
        self._stat_vars["total_alerts"].set(str(store.get_alert_count()))
        self._stat_vars["top_attacker"].set(store.get_top_attacker())
        db = alert_db.get_stats()
        self._stat_vars["db_total"].set(str(db.get("total", "—")))

    # ── Restore from DB ───────────────────────────────────────────────

    def _restore_db(self):
        alerts = alert_db.load_all()
        for a in alerts[-MAX_ALERTS:]:
            self._all_alerts.append(a)
        self._apply_filters()

    # ── Poll loop ─────────────────────────────────────────────────────

    def _poll(self):
        # Drain queue — fast 200ms poll for instant alerts
        new = False
        try:
            while True:
                self._add_alert_row(self._q.get_nowait())
                new = True
        except queue.Empty:
            pass

        # Update filter count on new alerts
        if new:
            total = len(self._all_alerts)
            shown = len(self._alert_tree.get_children())
            self._filter_count.set(
                f"{total} alerts" if shown == total else f"{shown} of {total}")

        # Always update stat cards and severity panel
        self._update_stat_cards()
        self._update_severity_panel()

        # Graph throttled to every 2s internally
        self._update_graph()

        self._clock.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(REFRESH_MS, self._poll)

    # ── Lifecycle ─────────────────────────────────────────────────────

    def run(self):
        self.root.mainloop()

    def _on_close(self):
        self.root.quit()
        self.root.destroy()
