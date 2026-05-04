"""
test_pipeline.py — Pipeline Verification Tool

Run this FIRST before main.py to verify the full pipeline works:
  detector → data_store → queue → dashboard display

Usage:
    python3 test_pipeline.py

Does NOT need Scapy or root. If alerts appear in the dashboard,
the pipeline is working and the issue is only in packet capture.
"""

import os, sys, time, queue, threading, json
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)

from data_store import store
from db_store   import alert_db
from detector   import RuleEngine
from dashboard  import SentinelXDashboard

def _inject(alert_queue, stop):
    """Inject one of each attack type every 2 seconds."""
    engine = RuleEngine()
    attacks = [
        # (proto, src_ip, dst_port, flags)
        ("TCP",  "10.0.0.1",  22,    "S"),      # SENSITIVE_PORT
        ("TCP",  "10.0.0.2",  9001,  "S"),      # PORT_SCAN seed
        ("TCP",  "10.0.0.2",  9002,  "S"),
        ("TCP",  "10.0.0.2",  9003,  "S"),
        ("TCP",  "10.0.0.2",  9004,  "S"),
        ("TCP",  "10.0.0.2",  9005,  "S"),      # 5 unique → PORT_SCAN
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),
        ("ICMP", "10.0.0.3",  None,  ""),       # 10 → PING_FLOOD
    ]
    i = 0
    while not stop.is_set():
        proto, src, dport, flags = attacks[i % len(attacks)]
        pkt = {
            "proto":    proto,
            "src_ip":   src,
            "dst_ip":   "192.168.1.1",
            "src_port": 54321,
            "dst_port": dport,
            "flags":    flags,
            "src_mac":  None,
            "arp_ip":   None,
            "length":   64,
        }
        store.total_packets += 1
        store.packet_rate    = float(i % 100)
        engine.process(pkt, alert_queue)
        i += 1
        time.sleep(0.1)

def main():
    print("\n" + "═"*52)
    print("  SentinelX Pipeline Test")
    print("  Injecting synthetic attacks every 0.1s")
    print("  Alerts should appear in the dashboard immediately")
    print("═"*52 + "\n")

    alert_queue = queue.Queue(maxsize=2000)
    stop        = threading.Event()

    t = threading.Thread(target=_inject, args=(alert_queue, stop),
                          daemon=True, name="injector")
    t.start()

    dash = SentinelXDashboard(alert_queue=alert_queue)
    try:
        dash.run()
    finally:
        stop.set()

if __name__ == "__main__":
    main()
