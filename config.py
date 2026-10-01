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
    credentials: list[tuple[str, str, str | None]]
    name: str
    slug: str
    visibility: str


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
        visibility = cp.get(section, "visibility", fallback="visible").strip().lower() or "visible"
        if cp.has_option(section, "hidden") and not cp.has_option(section, "visibility"):
            visibility = "hidden" if cp.getboolean(section, "hidden", fallback=False) else "visible"
        if visibility not in ("visible", "hidden", "all-hidden"):
            visibility = "visible"
        name = cp.get(section, "name", fallback="").strip() or root.name or str(root)
        slug = _slugify(root.name if root.name else str(root))
        if slug in seen_slugs:
            logger.warning("Duplicate share slug '%s' for section %s, skipping", slug, section)
            continue
        seen_slugs.add(slug)
        creds = []
        for key, value in cp.items(section):
            if key.startswith("credentials."):
                part = value.strip()
                if ":" in part:
                    segs = part.split(":")
                    vis_override = None
                    if len(segs) >= 3 and segs[-1].startswith("visibility="):
                        v = segs[-1].split("=", 1)[1].strip().lower()
                        if v in ("visible", "hidden", "all-hidden") or v == "hidden-all":
                            vis_override = "all-hidden" if v == "hidden-all" else v
                        segs = segs[:-1]
                    u = segs[0].strip()
                    p = ":".join(segs[1:]).strip() if len(segs) > 1 else ""
                    if u:
                        creds.append((u, p, vis_override))
        shares.append(Share(root=root, public=public, credentials=creds, name=name, slug=slug, visibility=visibility))
    return shares
