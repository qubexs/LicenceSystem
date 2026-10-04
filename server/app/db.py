"""SQLite (WAL) for Phase 1. Postgres-ready: keep SQL portable, swap get_conn() later."""
from __future__ import annotations
import sqlite3
import time
from pathlib import Path
from . import config

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS devices(
  device_id TEXT PRIMARY KEY,
  request_id TEXT UNIQUE NOT NULL,
  label TEXT DEFAULT '',
  platform TEXT DEFAULT '',
  app_version TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',   -- pending|active|suspended|revoked
  license_version INTEGER NOT NULL DEFAULT 1,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS licenses(
  jti TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  issued_at INTEGER NOT NULL,
  license_version INTEGER NOT NULL,
  perpetual INTEGER NOT NULL DEFAULT 1,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recovery_codes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  code_hash TEXT UNIQUE NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  used_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target_device TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  ts INTEGER NOT NULL,
  detail TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS admin_lockout(
  ip TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);
"""


def get_conn(db_path: Path | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else config.DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path | None = None) -> None:
    conn = get_conn(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def now_ts() -> int:
    return int(time.time())


def audit(conn: sqlite3.Connection, actor: str, action: str, target: str = "", ip: str = "", detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit(actor, action, target_device, ip, ts, detail) VALUES(?,?,?,?,?,?)",
        (actor, action, target, ip, now_ts(), detail),
    )
