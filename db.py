# Copyright (c) 2026 Enni Hämäläinen
#
# SPDX-License-Identifier: MIT

import sqlite3
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def init_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
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


def log_download(
    db_path: str,
    path: str,
    ip: str | None,
    user_agent: str | None,
    username: str | None = None,
    range_request: bool = False,
) -> None:
    try:
        with sqlite3.connect(db_path) as conn:
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
