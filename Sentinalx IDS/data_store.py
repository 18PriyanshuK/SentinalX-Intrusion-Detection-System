"""
data_store.py — Centralized In-Memory State  (SentinelX v3)

Single shared DataStore instance used by all modules.
All public methods are thread-safe via a reentrant lock.
"""

import time
import json
import threading
from collections import defaultdict, deque

# ── Load config ───────────────────────────────────────────────────────────────
with open("config.json") as _f:
    _CFG = json.load(_f)

_WL  = _CFG.get("whitelist",     {})
_DD  = _CFG.get("deduplication", {})
_TH  = _CFG["thresholds"]

WHITELIST_ENABLED  = _WL.get("enabled", True)
WHITELIST_IPS: set = set(_WL.get("ips", []))

DEDUP_ENABLED  = _DD.get("enabled", True)
DEDUP_WINDOW   = _DD.get("window_seconds", 8)

SENSITIVE_COOLDOWN = _TH.get("sensitive_port_cooldown", 30)


class DataStore:
    def __init__(self):
        self._lock = threading.RLock()

        # ── Alerts ────────────────────────────────────────────────────
        self.alerts: list[dict] = []

        # ── Raw packet log ────────────────────────────────────────────
        self.packet_log: deque = deque(maxlen=_CFG["dashboard"]["max_packets"])

        # ── Counters ──────────────────────────────────────────────────
        self.total_packets: int   = 0
        self.packet_rate:   float = 0.0

        # ── Sliding-window deques (detector uses these) ───────────────
        self.ip_ports: dict = defaultdict(deque)
        self.ip_icmp:  dict = defaultdict(deque)
        self.ip_syn:   dict = defaultdict(deque)
        self.ip_udp:   dict = defaultdict(deque)
        self.ip_http:  dict = defaultdict(deque)
        self.ip_dns:   dict = defaultdict(deque)

        # ── ARP table  ip → mac ───────────────────────────────────────
        self.arp_table: dict = {}

        # ── Dedup cache  (type, src) → last_epoch ────────────────────
        self._dedup:    dict = {}

        # ── Sensitive port cooldown  (src, port) → last_epoch ────────
        self._sp_cool:  dict = {}

        # ── Per-IP investigation data ─────────────────────────────────
        self.ip_details: dict = defaultdict(lambda: {
            "alert_count": 0,
            "ports":       set(),
            "types":       set(),
            "first_seen":  None,
            "last_seen":   None,
        })

        # ── Graph points  (epoch, score) ─────────────────────────────
        self.graph_points: deque = deque(maxlen=600)

    # ── Checks ───────────────────────────────────────────────────────

    def is_whitelisted(self, ip: str) -> bool:
        return WHITELIST_ENABLED and ip in WHITELIST_IPS

    def is_duplicate(self, atype: str, src: str) -> bool:
        if not DEDUP_ENABLED:
            return False
        key  = (atype, src)
        last = self._dedup.get(key, 0)
        now  = time.time()
        if now - last < DEDUP_WINDOW:
            return True
        self._dedup[key] = now
        return False

    def sensitive_port_allowed(self, src: str, port: int) -> bool:
        key  = (src, port)
        last = self._sp_cool.get(key, 0)
        now  = time.time()
        if now - last < SENSITIVE_COOLDOWN:
            return False
        self._sp_cool[key] = now
        return True

    # ── Writers ───────────────────────────────────────────────────────

    def add_alert(self, alert: dict):
        with self._lock:
            self.alerts.append(alert)
            src  = alert.get("src", "?")
            d    = self.ip_details[src]
            d["alert_count"] += 1
            d["types"].add(alert["type"])
            now_str = alert.get("timestamp", "")
            if d["first_seen"] is None:
                d["first_seen"] = now_str
            d["last_seen"] = now_str
            for p in alert.get("details", {}).get("ports", []):
                d["ports"].add(p)
            score = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 5}.get(
                alert.get("severity", "LOW"), 1)
            self.graph_points.append((time.time(), score, alert["type"]))

    def add_packet(self, pkt_summary: dict):
        """Add a raw packet summary to the packet log."""
        with self._lock:
            self.packet_log.append(pkt_summary)

    def load_historical(self, alerts: list[dict]):
        for a in alerts:
            self.add_alert(a)

    # ── Readers ───────────────────────────────────────────────────────

    def get_alerts(self) -> list[dict]:
        with self._lock:
            return list(self.alerts)

    def get_alert_count(self) -> int:
        with self._lock:
            return len(self.alerts)

    def get_top_attacker(self) -> str:
        with self._lock:
            if not self.ip_details:
                return "N/A"
            return max(self.ip_details,
                       key=lambda ip: self.ip_details[ip]["alert_count"],
                       default="N/A")

    def get_severity_counts(self) -> dict:
        with self._lock:
            counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for a in self.alerts:
                counts[a.get("severity", "LOW")] += 1
            return counts

    def get_ip_details(self, ip: str) -> dict:
        with self._lock:
            d = self.ip_details[ip]
            return {
                "alert_count": d["alert_count"],
                "ports":       sorted(d["ports"]),
                "types":       sorted(d["types"]),
                "first_seen":  d["first_seen"] or "—",
                "last_seen":   d["last_seen"]  or "—",
            }

    def get_packets(self) -> list[dict]:
        with self._lock:
            return list(self.packet_log)


# Singleton
store = DataStore()
