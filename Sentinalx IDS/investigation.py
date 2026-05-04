"""
investigation.py — Alert Investigation Window  (SentinelX v3)

Opens as a Toplevel when user double-clicks or right-clicks an alert.
Shows full alert details + per-IP history from DataStore.
"""

import tkinter as tk
from data_store import store

# ── Palette (matches dashboard) ───────────────────────────────────────────────
BG       = "#0b1120"
BG_CARD  = "#111827"
BG_ROW   = "#1a2236"
FG       = "#e2e8f0"
FG_DIM   = "#64748b"
ACCENT   = "#06b6d4"   # cyan

SEV_COL = {
    "LOW"     : "#22c55e",
    "MEDIUM"  : "#f59e0b",
    "HIGH"    : "#f97316",
    "CRITICAL": "#ef4444",
}

BEHAVIOR = {
    "PORT_SCAN"     : "This host rapidly probed multiple destination ports using TCP SYN or UDP packets — classic automated reconnaissance. Tools like Nmap or Masscan are commonly used. This is typically the first phase of an attack, used to identify open services before exploitation.",
    "PING_FLOOD"    : "This host sent ICMP Echo Requests at a rate far above normal usage. This is consistent with a ping flood — used to saturate bandwidth, test host availability, or act as part of a coordinated DDoS attack.",
    "SYN_FLOOD"     : "This host sent a high volume of TCP SYN packets without completing the three-way handshake. This exhausts the server's half-open connection queue, a classic denial-of-service vector that can render TCP services completely unreachable.",
    "ARP_SPOOF"     : "An IP-to-MAC address mapping inconsistency was detected multiple times. This is consistent with ARP cache poisoning — an attacker associates their MAC with a legitimate IP to intercept traffic, enabling Man-in-the-Middle attacks, credential theft, or session hijacking.",
    "DNS_FLOOD"     : "This host issued DNS queries at a rate far above baseline. This may indicate DNS amplification attack preparation, recursive resolver abuse, or C2 beacon activity using DNS as a covert communication channel.",
    "SENSITIVE_PORT": "A connection was made to a monitored administrative port. This may indicate SSH brute-force, RDP exploitation, legacy protocol abuse (FTP/Telnet), or lateral movement through an exposed management interface.",
    "UDP_FLOOD"     : "High-volume UDP packets were detected on non-standard ports. This is consistent with a UDP amplification attack — sending spoofed requests to services that return large responses, amplifying the attacker's bandwidth impact on the target.",
    "HTTP_FLOOD"    : "Excessive TCP SYN connections to HTTP/HTTPS ports were detected. This is a Layer 7 denial-of-service indicator — potentially using a botnet or stress tool to exhaust web server thread pools or connection limits.",
}


class InvestigationWindow:
    def __init__(self, parent: tk.Widget, alert: dict):
        self.alert  = alert
        self.win    = tk.Toplevel(parent)
        self._build()

    def _build(self):
        win   = self.win
        alert = self.alert
        sev   = alert.get("severity", "LOW")
        color = SEV_COL.get(sev, "#ffffff")
        ip    = alert.get("src", "?")

        win.title(f"Investigation  ·  {alert.get('type','?')}  ·  {ip}")
        win.geometry("720x620")
        win.configure(bg=BG)
        win.resizable(True, True)

        # Render window before grab_set
        win.update_idletasks()
        try:
            win.grab_set()
        except Exception:
            pass
        win.focus_force()

        # ── Top accent bar ────────────────────────────────────────────
        tk.Frame(win, bg=color, height=4).pack(fill=tk.X)

        # ── Header ────────────────────────────────────────────────────
        hdr = tk.Frame(win, bg=BG, pady=14)
        hdr.pack(fill=tk.X, padx=24)

        tk.Label(hdr, text="INCIDENT INVESTIGATION",
                 font=("JetBrains Mono", 13, "bold"),
                 fg=color, bg=BG).pack(side=tk.LEFT)

        tk.Label(hdr, text=sev,
                 font=("JetBrains Mono", 10, "bold"),
                 fg=BG, bg=color,
                 padx=10, pady=3).pack(side=tk.RIGHT)

        # ── Scrollable body ───────────────────────────────────────────
        body_frame = tk.Frame(win, bg=BG)
        body_frame.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 8))

        canvas = tk.Canvas(body_frame, bg=BG, highlightthickness=0)
        vsb    = tk.Scrollbar(body_frame, orient="vertical",
                               command=canvas.yview)
        inner  = tk.Frame(canvas, bg=BG)

        inner.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # ── Section 1: Alert Details ──────────────────────────────────
        self._heading(inner, "ALERT DETAILS", color)

        self._row(inner, "Source IP",   ip)
        self._row(inner, "Attack Type", alert.get("type", "?"))
        self._row(inner, "Severity",    sev, val_color=color)
        self._row(inner, "Timestamp",   alert.get("timestamp", "?"))
        self._row(inner, "Info",
                  alert.get("details", {}).get("info", "No details available"))

        self._divider(inner)

        # ── Section 2: IP History ─────────────────────────────────────
        self._heading(inner, "IP ACTIVITY HISTORY", color)
        d = store.get_ip_details(ip)

        self._row(inner, "Total Alerts",
                  str(d["alert_count"]) if d["alert_count"] > 0 else "1")
        self._row(inner, "Attack Types",
                  ", ".join(d["types"]) if d["types"] else alert.get("type","?"))
        self._row(inner, "Ports Seen",
                  ", ".join(str(p) for p in d["ports"]) if d["ports"] else "N/A")
        self._row(inner, "First Seen",  d["first_seen"])
        self._row(inner, "Last Seen",   d["last_seen"])

        self._divider(inner)

        # ── Section 3: Behaviour Analysis ────────────────────────────
        self._heading(inner, "BEHAVIOUR ANALYSIS", color)

        summary = BEHAVIOR.get(alert.get("type", ""),
                                "Unusual activity detected. Manual review recommended.")

        txt = tk.Text(inner, height=6, wrap=tk.WORD,
                      font=("JetBrains Mono", 9),
                      fg="#94a3b8", bg=BG_CARD,
                      bd=0, padx=12, pady=10,
                      relief=tk.FLAT, cursor="arrow")
        txt.insert("1.0", summary)
        txt.configure(state=tk.DISABLED)
        txt.pack(fill=tk.X, pady=(4, 0))

        # ── Close button ──────────────────────────────────────────────
        tk.Button(win, text="Close",
                  command=win.destroy,
                  font=("JetBrains Mono", 10, "bold"),
                  fg=BG, bg=color,
                  activebackground=color,
                  relief=tk.FLAT, bd=0,
                  padx=28, pady=10,
                  cursor="hand2").pack(pady=12)

    def _heading(self, parent, text, color):
        tk.Label(parent, text=text,
                 font=("JetBrains Mono", 9, "bold"),
                 fg=color, bg=BG,
                 anchor="w").pack(fill=tk.X, pady=(10, 4))

    def _divider(self, parent):
        tk.Frame(parent, bg="#1e293b", height=1).pack(fill=tk.X, pady=10)

    def _row(self, parent, label, value, val_color=FG):
        row = tk.Frame(parent, bg=BG_ROW)
        row.pack(fill=tk.X, pady=2)
        tk.Label(row, text=label, width=16, anchor="w",
                 font=("JetBrains Mono", 9, "bold"),
                 fg=FG_DIM, bg=BG_ROW,
                 padx=10, pady=7).pack(side=tk.LEFT)
        tk.Label(row, text=str(value), anchor="w",
                 font=("JetBrains Mono", 9),
                 fg=val_color, bg=BG_ROW,
                 wraplength=460, justify=tk.LEFT,
                 padx=6).pack(side=tk.LEFT, fill=tk.X, expand=True)
