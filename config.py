# Copyright (c) 2026 Enni Hämäläinen
#
# SPDX-License-Identifier: MIT

import configparser
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Share:
    root: Path
    public: bool
    credentials: list[tuple[str, str]]
    name: str
    slug: str
    hidden: bool


def _slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-") or "share"


DEFAULT_FOOTER = '<a href="https://github.com/jusa/super-simple-shares">super-simple-shares</a> (c) 2026 Enni Hämäläinen'


def get_server_config(path: str) -> dict:
    cp = configparser.ConfigParser()
    cp.read(path)
    out = {"port": 5000, "host": "0.0.0.0", "db": "file_share.db", "name": "Shares", "footer": DEFAULT_FOOTER}
    if cp.has_section("server"):
        out["port"] = cp.getint("server", "port", fallback=5000)
        host = cp.get("server", "host", fallback="0.0.0.0").strip()
        if host:
            out["host"] = host
        db_path = cp.get("server", "db", fallback="file_share.db").strip()
        if db_path:
            out["db"] = db_path
        out["name"] = cp.get("server", "name", fallback="Shares").strip() or "Shares"
        footer = cp.get("server", "footer", fallback=DEFAULT_FOOTER).strip()
        if footer:
            out["footer"] = footer
    return out


def load_config(path: str) -> list[Share]:
    cp = configparser.ConfigParser()
    cp.read(path)
    shares = []
    seen_slugs = set()
    for section in cp.sections():
        if section.strip().lower() == "server":
            continue
        root = Path(section.strip())
        if not root.is_absolute():
            root = root.resolve()
        public = cp.getboolean(section, "public", fallback=False)
        hidden = cp.getboolean(section, "hidden", fallback=False)
        name = cp.get(section, "name", fallback="").strip() or root.name or str(root)
        slug = _slugify(name)
        if slug in seen_slugs:
            logger.warning("Duplicate share slug '%s' for section %s, skipping", slug, section)
            continue
        seen_slugs.add(slug)
        creds = []
        for key, value in cp.items(section):
            if key.startswith("credentials."):
                part = value.strip()
                if ":" in part:
                    u, _, p = part.partition(":")
                    creds.append((u.strip(), p.strip()))
        shares.append(Share(root=root, public=public, credentials=creds, name=name, slug=slug, hidden=hidden))
    return shares
