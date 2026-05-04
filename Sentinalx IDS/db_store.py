"""
db_store.py — SQLite Persistence  (SentinelX)
"""

import json
import sqlite3
import logging
import threading
from datetime import datetime

logger = logging.getLogger("db")

with open("config.json") as _f:
    _CFG = json.load(_f)

_DB_CFG    = _CFG.get("database", {})
DB_ENABLED = _DB_CFG.get("enabled", True)
DB_FILE    = _DB_CFG.get("db_file", "sentinelx.db")

_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    date      TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    type      TEXT NOT NULL,
    src       TEXT NOT NULL,
    severity  TEXT NOT NULL,
    info      TEXT,
    raw_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_src  ON alerts(src);
CREATE INDEX IF NOT EXISTS idx_type ON alerts(type);
CREATE INDEX IF NOT EXISTS idx_sev  ON alerts(severity);
"""


class AlertDB:
    def __init__(self):
        self._lock = threading.Lock()
        self._conn = None
        if DB_ENABLED:
            self._connect()

    def _connect(self):
        try:
            self._conn = sqlite3.connect(DB_FILE, check_same_thread=False)
            self._conn.executescript(_DDL)
            self._conn.commit()
            logger.info("DB ready: %s", DB_FILE)
        except Exception as e:
            logger.error("DB init failed: %s", e)
            self._conn = None

    def save(self, alert: dict):
        if not self._conn:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO alerts (date,timestamp,type,src,severity,info,raw_json) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (
                        datetime.now().strftime("%Y-%m-%d"),
                        alert.get("timestamp", ""),
                        alert.get("type", ""),
                        alert.get("src", ""),
                        alert.get("severity", ""),
                        alert.get("details", {}).get("info", ""),
                        json.dumps(alert),
                    )
                )
                self._conn.commit()
        except Exception as e:
            logger.error("DB save: %s", e)

    def load_all(self) -> list[dict]:
        if not self._conn:
            return []
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT raw_json FROM alerts ORDER BY id ASC"
                ).fetchall()
            result = []
            for (raw,) in rows:
                try:
                    result.append(json.loads(raw))
                except Exception:
                    pass
            logger.info("Loaded %d historical alerts.", len(result))
            return result
        except Exception as e:
            logger.error("DB load: %s", e)
            return []

    def get_stats(self) -> dict:
        if not self._conn:
            return {"total": 0, "by_severity": {}, "top_types": {}}
        try:
            with self._lock:
                total  = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                by_sev = dict(self._conn.execute(
                    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
                ).fetchall())
                top    = dict(self._conn.execute(
                    "SELECT type, COUNT(*) FROM alerts GROUP BY type "
                    "ORDER BY COUNT(*) DESC LIMIT 5"
                ).fetchall())
            return {"total": total, "by_severity": by_sev, "top_types": top}
        except Exception as e:
            logger.error("DB stats: %s", e)
            return {"total": 0, "by_severity": {}, "top_types": {}}

    def export_csv(self, filepath: str) -> int:
        if not self._conn:
            return 0
        import csv
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT date,timestamp,type,src,severity,info FROM alerts ORDER BY id"
                ).fetchall()
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Date", "Time", "Attack Type", "Source IP", "Severity", "Details"])
                w.writerows(rows)
            return len(rows)
        except Exception as e:
            logger.error("CSV export: %s", e)
            return 0


alert_db = AlertDB()
