"""
main.py — SentinelX Entry Point

Usage:
    sudo python3 main.py              # sniff all interfaces (recommended)
    sudo python3 main.py --iface eth0 # specific interface only
"""

import os
import sys
import queue
import logging
import argparse
import json

# ── Always resolve imports from this file's directory ────────────────────────
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

# ── Args ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="SentinelX v3 — Real-Time IDS")
parser.add_argument("--iface", default=None,
                    help="Network interface to sniff (default: all)")
args = parser.parse_args()

# ── Logging ───────────────────────────────────────────────────────────────────
with open("config.json") as _f:
    _CFG = json.load(_f)

def _sep(char: str, count: int) -> str:
    """
    Create a repeated separator that won't crash logging on Windows consoles
    with limited encodings (e.g. cp1252).
    """
    try:
        # sys.stdout.encoding is often cp1252 on Windows terminals.
        enc = getattr(sys.stdout, "encoding", None) or ""
        if enc:
            char.encode(enc)
            return char * count
    except Exception:
        pass
    # ASCII fallback (safe everywhere).
    return "-" * count

# Try to make console stderr/stdout UTF-8 so Unicode separators render.
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    # If reconfigure isn't supported (or fails), we'll still be safe via _sep().
    pass

_LOG = _CFG.get("logging", {})
_handlers = [logging.StreamHandler(sys.stdout)]
if _LOG.get("enabled", True):
    _handlers.append(
        logging.FileHandler(
            _LOG.get("log_file", "sentinelx.log"),
            encoding="utf-8",
        )
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=_handlers,
)
logger = logging.getLogger("main")

# ── Late imports ──────────────────────────────────────────────────────────────
from data_store    import store
from db_store      import alert_db
from packet_sniffer import PacketSniffer
from dashboard     import SentinelXDashboard


def main():
    logger.info(_sep("━", 52))
    logger.info("  SentinelX v2  —  starting up")
    logger.info("  Interface : %s", args.iface or "ALL (including loopback)")
    logger.info(_sep("━", 52))

    # Restore previous session from SQLite
    historical = alert_db.load_all()
    if historical:
        store.load_historical(historical)
        logger.info("Restored %d alerts from previous session.", len(historical))

    alert_queue: queue.Queue = queue.Queue(maxsize=2000)

    sniffer = PacketSniffer(alert_queue=alert_queue, iface=args.iface)
    sniffer.start()

    dash = SentinelXDashboard(alert_queue=alert_queue)
    try:
        dash.run()
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        logger.info("SentinelX shut down.")


if __name__ == "__main__":
    main()
