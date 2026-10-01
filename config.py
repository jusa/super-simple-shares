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
DEFAULT_COOKIE_LIFETIME = 7 * 24 * 3600
_COOKIE_LIFETIME = re.compile(r"^(\d+)([hd])$", re.IGNORECASE)


_SERVER_SETTINGS = {"port", "host", "db", "name", "footer", "secret", "cookie_lifetime"}


def _server_variables(cp: configparser.ConfigParser) -> dict[str, str]:
    if not cp.has_section("server"):
        return {}
    variables = {}
    for key, value in cp.items("server"):
        if key.lower() not in _SERVER_SETTINGS:
            variables[key.lower()] = value
    for _ in range(len(variables) + 1):
        changed = False
        for name, value in list(variables.items()):
            others = {key: item for key, item in variables.items() if key != name}
            expanded = _substitute(value, others)
            if expanded != value:
                variables[name] = expanded
                changed = True
        if not changed:
            break
    return variables


def _substitute(text: str, variables: dict[str, str]) -> str:
    if not variables or "$" not in text:
        return text
    for name in sorted(variables, key=len, reverse=True):
        text = re.sub(
            rf"\${re.escape(name)}(?![A-Za-z0-9_])",
            lambda _match, replacement=variables[name]: replacement,
            text,
            flags=re.IGNORECASE,
        )
    return text


def parse_cookie_lifetime(value: str) -> int | None:
    match = _COOKIE_LIFETIME.match(value.strip())
    if not match:
        return None
    count = int(match.group(1))
    if count <= 0:
        return None
    if match.group(2).lower() == "h":
        return count * 3600
    return count * 86400


def get_server_config(path: str) -> dict:
    cp = configparser.ConfigParser()
    cp.read(path)
    out = {
        "port": 5000,
        "host": "0.0.0.0",
        "db": "",
        "name": "Shares",
        "footer": DEFAULT_FOOTER,
        "secret": "",
        "cookie_lifetime": DEFAULT_COOKIE_LIFETIME,
    }
    variables = _server_variables(cp)
    if cp.has_section("server"):
        out["port"] = cp.getint("server", "port", fallback=5000)
        host = cp.get("server", "host", fallback="0.0.0.0").strip()
        if host:
            out["host"] = host
        if cp.has_option("server", "db"):
            db_path = _substitute(cp.get("server", "db").strip(), variables)
            if db_path:
                out["db"] = db_path
        out["name"] = cp.get("server", "name", fallback="Shares").strip() or "Shares"
        if cp.has_option("server", "secret"):
            out["secret"] = cp.get("server", "secret").strip()
        if cp.has_option("server", "cookie_lifetime"):
            raw = cp.get("server", "cookie_lifetime")
            parsed = parse_cookie_lifetime(raw)
            if parsed is None:
                logger.warning("Invalid cookie_lifetime %r, using 7d", raw.strip())
            else:
                out["cookie_lifetime"] = parsed
        footer = cp.get("server", "footer", fallback=DEFAULT_FOOTER).strip()
        if footer:
            out["footer"] = footer
    return out


def load_config(path: str) -> list[Share]:
    cp = configparser.ConfigParser()
    cp.read(path)
    variables = _server_variables(cp)
    shares = []
    seen_slugs = set()
    for section in cp.sections():
        if section.strip().lower() == "server":
            continue
        root = Path(_substitute(section.strip(), variables))
        if not root.is_absolute():
            root = root.resolve()
        public = cp.getboolean(section, "public", fallback=False)
        visibility = cp.get(section, "visibility", fallback="visible").strip().lower() or "visible"
        if cp.has_option(section, "hidden") and not cp.has_option(section, "visibility"):
            visibility = "hidden" if cp.getboolean(section, "hidden", fallback=False) else "visible"
        if visibility not in ("visible", "hidden", "all-hidden"):
            visibility = "visible"
        name = _substitute(cp.get(section, "name", fallback="").strip(), variables) or root.name or str(root)
        slug = _slugify(root.name if root.name else str(root))
        if slug in seen_slugs:
            logger.warning("Duplicate share slug '%s' for section %s, skipping", slug, section)
            continue
        seen_slugs.add(slug)
        creds = []
        for key, value in cp.items(section):
            if key.startswith("credentials."):
                part = _substitute(value.strip(), variables)
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
