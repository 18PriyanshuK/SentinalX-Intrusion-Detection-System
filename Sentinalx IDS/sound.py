"""
sound.py — Alert Sound Notifications  (SentinelX v3)

Uses the terminal bell (\a) for sound — no pygame, no numpy,
no native library conflicts. Works reliably under sudo on Kali.

Severity mapping:
  CRITICAL → 3 rapid beeps
  HIGH     → 2 beeps
  MEDIUM   → 1 beep
  LOW      → silent
"""

import json
import logging
import threading
import sys

logger = logging.getLogger("sound")

with open("config.json") as _f:
    _CFG = json.load(_f)

SOUND_ENABLED = _CFG.get("sound", {}).get("enabled", True)

# Number of beeps per severity
_BEEPS = {
    "CRITICAL": 3,
    "HIGH"    : 2,
    "MEDIUM"  : 1,
    "LOW"     : 0,
}


def _beep(n: int):
    """Write n terminal bell characters to stdout."""
    for _ in range(n):
        sys.stdout.write("\a")
        sys.stdout.flush()


def play(severity: str):
    """Play alert beep for given severity. Non-blocking."""
    if not SOUND_ENABLED:
        return
    n = _BEEPS.get(severity, 0)
    if n > 0:
        threading.Thread(target=_beep, args=(n,), daemon=True).start()


logger.info("Sound ready (terminal bell). CRITICAL=3 beeps, HIGH=2, MEDIUM=1.")
