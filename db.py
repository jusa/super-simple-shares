# Copyright (c) 2026 Enni Hämäläinen
#
# SPDX-License-Identifier: MIT

import logging
import secrets
import sqlite3
from datetime import datetime

logger = logging.getLogger(__name__)


def init_db(db_path: str) -> None:
    with sqlite3.connect(db_path, timeout=5.0) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                path TEXT NOT NULL,
                username TEXT,
                range_request INTEGER
            )
            """
        )
        conn.commit()


def get_or_create_secret(db_path: str) -> str:
    with sqlite3.connect(db_path, timeout=5.0) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        row = conn.execute("SELECT value FROM app_meta WHERE key = 'secret'").fetchone()
        if row and row[0]:
            return row[0]
        secret = secrets.token_hex(32)
        cur = conn.execute(
            "INSERT OR IGNORE INTO app_meta (key, value) VALUES ('secret', ?)",
            (secret,),
        )
        row = conn.execute("SELECT value FROM app_meta WHERE key = 'secret'").fetchone()
        conn.commit()
        if cur.rowcount == 1:
            logger.info("Created session secret in %s", db_path)
        if not row or not row[0]:
            raise RuntimeError("Could not store session secret")
        return row[0]


def log_download(
    db_path: str | None,
    path: str,
    ip: str | None,
    user_agent: str | None,
    username: str | None = None,
    range_request: bool = False,
) -> None:
    if not db_path:
        return
    try:
        with sqlite3.connect(db_path, timeout=5.0) as conn:
            conn.execute(
                """
                INSERT INTO downloads (at, ip, user_agent, path, username, range_request)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat() + "Z",
                    ip or "",
                    user_agent or "",
                    path,
                    username or "",
                    1 if range_request else 0,
                ),
            )
            conn.commit()
    except Exception as e:
        logger.warning("Failed to log download: %s", e)
