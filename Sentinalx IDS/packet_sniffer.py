"""
packet_sniffer.py — Live Packet Capture  (SentinelX)

- Sniffs ALL interfaces by default (including lo) so loopback test
  commands like hping3 127.0.0.1 are captured
- Named packet_sniffer to avoid collision with Scapy's internal sniffer module
- Logs a compact summary of every packet to the raw packet log
"""

import time
import queue
import logging
import threading

from data_store import store
from detector   import RuleEngine

logger = logging.getLogger("sniffer")


def _parse(pkt) -> dict | None:
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2   import ARP, Ether
    except ImportError:
        return None

    info = {
        "proto"   : "OTHER",
        "src_ip"  : None,
        "dst_ip"  : None,
        "src_port": None,
        "dst_port": None,
        "flags"   : "",
        "src_mac" : None,
        "arp_ip"  : None,
        "length"  : len(pkt),
    }

    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src

    if pkt.haslayer(ARP):
        info["proto"]   = "ARP"
        info["src_mac"] = pkt[ARP].hwsrc
        info["arp_ip"]  = pkt[ARP].psrc
        info["src_ip"]  = pkt[ARP].psrc
        info["dst_ip"]  = pkt[ARP].pdst
        return info

    if not pkt.haslayer(IP):
        return None

    info["src_ip"] = pkt[IP].src
    info["dst_ip"] = pkt[IP].dst

    if pkt.haslayer(TCP):
        info["proto"]    = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        f = int(pkt[TCP].flags)
        fs = ""
        if f & 0x02: fs += "S"
        if f & 0x10: fs += "A"
        if f & 0x04: fs += "R"
        if f & 0x01: fs += "F"
        if f & 0x08: fs += "P"
        info["flags"] = fs or "?"

    elif pkt.haslayer(UDP):
        info["proto"]    = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport

    elif pkt.haslayer(ICMP):
        info["proto"] = "ICMP"

    else:
        return None

    return info


class PacketSniffer:
    def __init__(self, alert_queue: queue.Queue, iface=None):
        self._q          = alert_queue
        self._iface      = iface
        self._stop       = threading.Event()
        self._engine     = RuleEngine()
        self._thread     = threading.Thread(
            target=self._run, daemon=True, name="sniffer")
        self._count      = 0
        self._rate_ts    = time.time()

    def start(self):
        self._thread.start()
        logger.info("Sniffer started.")

    def stop(self):
        self._stop.set()

    def _run(self):
        try:
            from scapy.all import sniff, get_if_list
        except ModuleNotFoundError:
            logger.critical("Scapy not found. Install: pip install scapy")
            return

        # Sniff ALL interfaces when none specified — captures loopback too
        ifaces = self._iface if self._iface else get_if_list()
        logger.info("Sniffing on: %s", ifaces)

        try:
            sniff(
                iface=ifaces,
                prn=self._handle,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except PermissionError:
            logger.critical("Permission denied — run with sudo.")
        except Exception as e:
            logger.exception("Sniffer error: %s", e)

    def _handle(self, pkt):
        store.total_packets += 1
        self._count         += 1

        now     = time.time()
        elapsed = now - self._rate_ts
        if elapsed >= 1.0:
            store.packet_rate = round(self._count / elapsed, 1)
            self._count       = 0
            self._rate_ts     = now

        parsed = _parse(pkt)
        if not parsed:
            return

        # Add to raw packet log for the Packet Log tab
        from datetime import datetime
        summary = {
            "time"    : datetime.now().strftime("%H:%M:%S"),
            "proto"   : parsed["proto"],
            "src"     : f"{parsed['src_ip']}:{parsed['src_port']}"
                        if parsed["src_port"] else parsed["src_ip"] or "?",
            "dst"     : f"{parsed['dst_ip']}:{parsed['dst_port']}"
                        if parsed["dst_port"] else parsed["dst_ip"] or "?",
            "flags"   : parsed["flags"] or "—",
            "length"  : parsed["length"],
        }
        store.add_packet(summary)

        # Run detection rules
        self._engine.process(parsed, self._q)
