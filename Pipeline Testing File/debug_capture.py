"""
debug_capture.py — Live Capture Debugger

Run this INSTEAD of main.py to see exactly what Scapy is capturing.
No dashboard needed. Just prints every packet to the terminal.

Usage (Windows CMD as Administrator):
    python debug_capture.py

Watch the output when you run nmap or ping commands.
"""

import os, sys
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2   import ARP, Ether

print("\n" + "="*60)
print("  SentinelX — Capture Debugger")
print("="*60)

# Print all available interfaces
ifaces = get_if_list()
print(f"\nAvailable interfaces ({len(ifaces)} total):")
for i, iface in enumerate(ifaces):
    print(f"  [{i}]  {iface}")

print("\nSniffing on ALL interfaces...")
print("Run your nmap/ping commands now and watch below.")
print("Press Ctrl+C to stop.\n")
print("-"*60)

pkt_count = 0

def handle(pkt):
    global pkt_count
    pkt_count += 1

    src = dst = proto = info = "?"

    if pkt.haslayer(ARP):
        proto = "ARP"
        src   = pkt[ARP].psrc
        dst   = pkt[ARP].pdst
        info  = f"hwsrc={pkt[ARP].hwsrc}"

    elif pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst

        if pkt.haslayer(TCP):
            proto = "TCP"
            flags = int(pkt[TCP].flags)
            fs    = ""
            if flags & 0x02: fs += "S"
            if flags & 0x10: fs += "A"
            if flags & 0x04: fs += "R"
            if flags & 0x01: fs += "F"
            info  = f":{pkt[TCP].sport} → :{pkt[TCP].dport}  flags={fs or '?'}"

        elif pkt.haslayer(UDP):
            proto = "UDP"
            info  = f":{pkt[UDP].sport} → :{pkt[UDP].dport}"

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            info  = f"type={pkt[ICMP].type}"
    else:
        return   # skip non-IP non-ARP

    print(f"  #{pkt_count:<5}  {proto:<5}  {src:<16} → {dst:<16}  {info}")

try:
    sniff(prn=handle, store=False)
except KeyboardInterrupt:
    print(f"\n\nStopped. Captured {pkt_count} packets total.")
except PermissionError:
    print("\nERROR: Permission denied.")
    print("Run CMD as Administrator.")
except Exception as e:
    print(f"\nERROR: {e}")
