#!/usr/bin/env python3
# Copyright (c) 2026 Enni Hämäläinen
#
# SPDX-License-Identifier: MIT

"""Query and summarize the file-share download SQLite database."""

import argparse
import os
import sqlite3
import sys

# Add parent so config can be imported when run as script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import get_server_config

CONFIG_PATH = os.environ.get("FILE_SHARE_CONFIG", "config.ini")


def run(db_path: str, limit: int, by_path: int, by_ip: int) -> None:
    if not os.path.isfile(db_path):
        print("Database not found:", db_path, file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM downloads")
    total = cur.fetchone()[0]
    print("Total downloads:", total)
    if total == 0:
        conn.close()
        return

    cur.execute("SELECT COUNT(DISTINCT ip) FROM downloads WHERE ip != ''")
    print("Unique IPs:", cur.fetchone()[0])

    print()
    print("Recent downloads (limit %d):" % limit)
    print("-" * 80)
    cur.execute(
        "SELECT at, ip, path, username, range_request FROM downloads ORDER BY at DESC LIMIT ?",
        (limit,),
    )
    for row in cur.fetchall():
        r = " (resumed)" if row["range_request"] else ""
        user = " [%s]" % row["username"] if row["username"] else ""
        print("  %s  %s  %s%s%s" % (row["at"], row["ip"] or "-", row["path"], user, r))
    print()

    if by_path > 0:
        print("By path (top %d):" % by_path)
        print("-" * 80)
        cur.execute(
            "SELECT path, COUNT(*) AS n FROM downloads GROUP BY path ORDER BY n DESC LIMIT ?",
            (by_path,),
        )
        for row in cur.fetchall():
            print("  %d  %s" % (row["n"], row["path"]))
        print()

    if by_ip > 0:
        print("By IP (top %d):" % by_ip)
        print("-" * 80)
        cur.execute(
            "SELECT ip, COUNT(*) AS n FROM downloads WHERE ip != '' GROUP BY ip ORDER BY n DESC LIMIT ?",
            (by_ip,),
        )
        for row in cur.fetchall():
            print("  %d  %s" % (row["n"], row["ip"]))
        print()

    cur.execute(
        "SELECT DATE(at) AS d, COUNT(*) AS n FROM downloads GROUP BY d ORDER BY d DESC LIMIT 14"
    )
    rows = cur.fetchall()
    if rows:
        print("By date (last 14 days):")
        print("-" * 80)
        for row in rows:
            print("  %s  %d" % (row["d"], row["n"]))

    conn.close()


def main() -> None:
    default_db = get_server_config(CONFIG_PATH).get("db", "file_share.db")
    p = argparse.ArgumentParser(description="Analyze file-share download database")
    p.add_argument("--db", default=default_db, help="SQLite database path (default: from config [server] db)")
    p.add_argument("--limit", type=int, default=20, help="Recent downloads to show (default: 20)")
    p.add_argument("--by-path", type=int, default=10, help="Top N paths to show (0 to skip, default: 10)")
    p.add_argument("--by-ip", type=int, default=10, help="Top N IPs to show (0 to skip, default: 10)")
    args = p.parse_args()
    run(args.db, args.limit, args.by_path, args.by_ip)


if __name__ == "__main__":
    main()
