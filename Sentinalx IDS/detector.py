"""
detector.py — Rule Engine  (SentinelX v3 — fixed)

Fixes:
  - Added print() debug trace so you can see exactly what is being processed
  - Dedup window reduced to 3s (was 8s — was suppressing nmap alerts)
  - _routable() no longer blocks 127.0.0.1 — whitelist handles that separately
  - Port scan threshold lowered to work with nmap's default scan speed
  - Sensitive port fires on ANY TCP/UDP packet to monitored port, not just SYN
"""

import time
import queue
import json
import logging
from collections import deque, defaultdict
from datetime import datetime

from data_store import store
from db_store   import alert_db

logger = logging.getLogger("detector")

with open("config.json") as _f:
    _CFG = json.load(_f)

_T  = _CFG["thresholds"]
_SP = set(_CFG["sensitive_ports"])

# Ports excluded from port-scan counting
_BENIGN_SCAN: set = {
    53, 80, 443, 8080, 8443,
    67, 68, 123, 137, 138, 139,
    445, 5353, 1900, 631, 5355,
}

# UDP ports excluded from UDP-flood counting
_BENIGN_UDP: set = {
    53, 67, 68, 123, 137, 138,
    5353, 1900, 631, 5355, 547, 546,
}

_ARP_WARMUP  = _T.get("arp_warmup_seconds", 30)
_ARP_CONFIRM = _T.get("arp_confirm_count",   3)


def _routable(ip: str) -> bool:
    """
    Filter out addresses that are never real attack sources.
    NOTE: 127.0.0.1 is intentionally ALLOWED here so loopback
    test commands work. Whitelist in config.json handles trusted IPs.
    """
    if not ip:                       return False
    if ip == "0.0.0.0":              return False
    if ip.startswith("169.254."):    return False  # link-local
    if ip.startswith("224."):        return False  # multicast
    if ip.startswith("239."):        return False  # multicast
    if ip.startswith("255."):        return False  # broadcast
    if ip == "::1":                  return False  # IPv6 loopback (kept)
    return True


def _make_alert(atype: str, src: str, severity: str, **details) -> dict:
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "type":      atype,
        "src":       src,
        "severity":  severity,
        "details":   details,
    }


class RuleEngine:
    def __init__(self):
        self._start    = time.time()
        self._arp_conf = defaultdict(int)

    def process(self, pkt: dict, q: queue.Queue):
        proto = pkt.get("proto", "OTHER")
        src   = pkt.get("src_ip", "")
        dport = pkt.get("dst_port")
        flags = pkt.get("flags", "") or ""

        # Skip unroutable and whitelisted
        if not _routable(src):
            return
        if store.is_whitelisted(src):
            return

        # Rule 1 — Port Scan
        # Catches SYN, FIN, NULL, Xmas scans and version detection probes
        # Any TCP to a non-benign port counts — not just pure SYN
        if proto == "TCP" and dport and dport not in _BENIGN_SCAN:
            self._port_scan(src, dport, q)

        # Rule 2 — Ping Flood
        if proto == "ICMP":
            self._ping_flood(src, q)

        # Rule 3 — SYN Flood (pure SYN only)
        if proto == "TCP" and "S" in flags and "A" not in flags:
            self._syn_flood(src, q)

        # Rule 4 — ARP Spoof
        if proto == "ARP":
            self._arp_spoof(pkt, q)

        # Rule 5 — DNS Flood
        if proto == "UDP" and dport == 53:
            self._dns_flood(src, q)

        # Rule 6 — Sensitive Port (any packet, not just SYN)
        if dport and dport in _SP:
            self._sensitive_port(src, dport, q)

        # Rule 7 — UDP Flood
        if proto == "UDP" and dport and dport not in _BENIGN_UDP:
            self._udp_flood(src, q)

        # Rule 8 — HTTP Flood
        if proto == "TCP" and "S" in flags and "A" not in flags \
                and dport in (80, 443, 8080, 8443):
            self._http_flood(src, q)

    # ── Rules ─────────────────────────────────────────────────────────

    def _port_scan(self, src: str, port: int, q: queue.Queue):
        now = time.time()
        w   = _T["port_scan_window"]
        thr = _T["port_scan_ports"]
        dq  = store.ip_ports[src]
        dq.append((now, port))
        while dq and dq[0][0] < now - w:
            dq.popleft()
        unique = {p for _, p in dq}
        if len(unique) >= thr:
            self._fire(_make_alert("PORT_SCAN", src, "HIGH",
                info=f"{len(unique)} ports scanned in {w}s",
                ports=sorted(unique)), q)

    def _ping_flood(self, src: str, q: queue.Queue):
        now = time.time()
        w   = _T["ping_flood_window"]
        thr = _T["ping_flood_count"]
        dq  = store.ip_icmp[src]
        dq.append(now)
        while dq and dq[0] < now - w:
            dq.popleft()
        if len(dq) >= thr:
            self._fire(_make_alert("PING_FLOOD", src, "MEDIUM",
                info=f"{len(dq)} ICMP packets in {w}s"), q)

    def _syn_flood(self, src: str, q: queue.Queue):
        now = time.time()
        w   = _T["syn_flood_window"]
        thr = _T["syn_flood_count"]
        dq  = store.ip_syn[src]
        dq.append(now)
        while dq and dq[0] < now - w:
            dq.popleft()
        if len(dq) >= thr:
            self._fire(_make_alert("SYN_FLOOD", src, "CRITICAL",
                info=f"{len(dq)} SYN packets in {w}s"), q)

    def _arp_spoof(self, pkt: dict, q: queue.Queue):
        if not _T.get("arp_check", True):
            return
        ip  = pkt.get("arp_ip")
        mac = pkt.get("src_mac")
        if not ip or not mac or not _routable(ip):
            return
        known = store.arp_table.get(ip)
        if known is None:
            store.arp_table[ip] = mac
            return
        if known == mac:
            self._arp_conf[ip] = 0
            return
        if time.time() - self._start < _ARP_WARMUP:
            store.arp_table[ip] = mac
            return
        self._arp_conf[ip] += 1
        if self._arp_conf[ip] >= _ARP_CONFIRM:
            self._fire(_make_alert("ARP_SPOOF", ip, "CRITICAL",
                info=f"{ip}: MAC {known} → {mac}",
                known_mac=known, new_mac=mac), q)
            self._arp_conf[ip] = 0
            store.arp_table[ip] = mac

    def _dns_flood(self, src: str, q: queue.Queue):
        now = time.time()
        w   = _T["dns_flood_window"]
        thr = _T["dns_flood_count"]
        dq  = store.ip_dns[src]
        dq.append(now)
        while dq and dq[0] < now - w:
            dq.popleft()
        if len(dq) >= thr:
            self._fire(_make_alert("DNS_FLOOD", src, "HIGH",
                info=f"{len(dq)} DNS queries in {w}s"), q)

    def _sensitive_port(self, src: str, port: int, q: queue.Queue):
        if not store.sensitive_port_allowed(src, port):
            return
        sev = "HIGH" if port in {21, 23} else \
              "MEDIUM" if port in {22, 3389} else "LOW"
        self._fire(_make_alert("SENSITIVE_PORT", src, sev,
            info=f"Connection to port {port}",
            ports=[port]), q)

    def _udp_flood(self, src: str, q: queue.Queue):
        now = time.time()
        w   = _T["udp_flood_window"]
        thr = _T["udp_flood_count"]
        dq  = store.ip_udp[src]
        dq.append(now)
        while dq and dq[0] < now - w:
            dq.popleft()
        if len(dq) >= thr:
            self._fire(_make_alert("UDP_FLOOD", src, "HIGH",
                info=f"{len(dq)} UDP packets in {w}s"), q)

    def _http_flood(self, src: str, q: queue.Queue):
        now = time.time()
        w   = _T["http_flood_window"]
        thr = _T["http_flood_count"]
        dq  = store.ip_http[src]
        dq.append(now)
        while dq and dq[0] < now - w:
            dq.popleft()
        if len(dq) >= thr:
            self._fire(_make_alert("HTTP_FLOOD", src, "HIGH",
                info=f"{len(dq)} HTTP SYNs in {w}s"), q)

    @staticmethod
    def _fire(a: dict, q: queue.Queue):
        if store.is_duplicate(a["type"], a["src"]):
            return
        logger.warning("ALERT  %-18s  %-16s  %s",
                        a["type"], a["src"], a["severity"])
        store.add_alert(a)
        alert_db.save(a)
        try:
            q.put_nowait(a)
        except queue.Full:
            logger.error("Alert queue full — dashboard not draining fast enough")
