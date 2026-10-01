# Copyright (c) 2026 Enni Hämäläinen
#
# SPDX-License-Identifier: MIT

import hmac
import logging
import mimetypes
import os
import re
from datetime import datetime
from pathlib import Path

from flask import Flask, abort, make_response, request, send_file

from config import get_server_config, load_config, Share
import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

CONFIG_PATH = os.environ.get("FILE_SHARE_CONFIG", "config.ini")

_server_config = get_server_config(CONFIG_PATH)
app.config["FILE_SHARE_DB"] = _server_config["db"]
db.init_db(app.config["FILE_SHARE_DB"])

_shares: list[Share] = []
_config_mtime: float | None = None


def get_shares() -> list[Share]:
    global _shares, _config_mtime
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        mtime = 0.0
    if _config_mtime is None or mtime > _config_mtime:
        _config_mtime = mtime
        _shares = load_config(CONFIG_PATH)
        if not _shares:
            logger.warning("No shares configured in %s", CONFIG_PATH)
        else:
            logger.info("Reloaded config from %s (%d shares)", CONFIG_PATH, len(_shares))
    return _shares


def format_size(n: int) -> str:
    if n < 0:
        return "-"
    for u, suffix in [(1024**3, "GB"), (1024**2, "MB"), (1024, "KB")]:
        if n >= u:
            return "%.1f %s" % (n / u, suffix)
    return "%d B" % n


def format_mtime(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
    except OSError:
        return "-"


def get_share_by_slug(slug: str) -> tuple[Share | None, int]:
    shares = get_shares()
    for i, s in enumerate(shares):
        if s.slug == slug:
            return (s, i)
    return (None, -1)


def resolve_path(share: Share, subpath: str) -> Path | None:
    root = share.root
    if not subpath or subpath.strip() in ("", "."):
        return root
    parts = [p for p in subpath.strip().split("/") if p and p not in (".", "..")]
    resolved = root.joinpath(*parts)
    try:
        resolved = resolved.resolve()
    except OSError:
        return None
    if not str(resolved).startswith(str(root.resolve())):
        return None
    return resolved


def check_auth(share: Share) -> bool:
    if share.public:
        return True
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return False
    for user, raw_pass, _ in share.credentials:
        if hmac.compare_digest(auth.username, user) and hmac.compare_digest(auth.password, raw_pass):
            return True
    return False


def get_effective_visibility(share: Share) -> str:
    auth = request.authorization
    if auth:
        for user, raw_pass, vis_override in share.credentials:
            if hmac.compare_digest(auth.username, user) and hmac.compare_digest(auth.password, raw_pass):
                return vis_override if vis_override else share.visibility
    return share.visibility


def has_listing_credentials(share: Share) -> bool:
    return any(vis in ("hidden", "visible") for _, _, vis in share.credentials if vis)

LISTABLE_COOKIE = "sss_listable"
LISTABLE_COOKIE_MAX_AGE = 604800


def _listable_slugs_from_cookie() -> set[str]:
    raw = request.cookies.get(LISTABLE_COOKIE) or ""
    return {s.strip() for s in raw.split(",") if s.strip()}


def _maybe_set_listable_cookie(response, share: Share) -> None:
    if share.visibility not in ("hidden", "all-hidden"):
        return
    if get_effective_visibility(share) not in ("visible", "hidden"):
        return
    if not request.authorization:
        return
    slugs = _listable_slugs_from_cookie() | {share.slug}
    response.set_cookie(
        LISTABLE_COOKIE,
        ",".join(sorted(slugs)),
        max_age=LISTABLE_COOKIE_MAX_AGE,
        path="/",
        httponly=True,
        samesite="Lax",
    )


def _remove_slug_from_listable_cookie(response, slug: str) -> None:
    slugs = _listable_slugs_from_cookie()
    slugs.discard(slug)
    if not slugs:
        response.delete_cookie(LISTABLE_COOKIE, path="/")
    else:
        response.set_cookie(
            LISTABLE_COOKIE,
            ",".join(sorted(slugs)),
            max_age=LISTABLE_COOKIE_MAX_AGE,
            path="/",
            httponly=True,
            samesite="Lax",
        )


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def require_auth(share: Share):
    if not check_auth(share):
        return (
            (
                "<!DOCTYPE html><html><head><title>Auth required</title></head>"
                "<body><p>Authentication required.</p></body></html>"
            ),
            401,
            {"WWW-Authenticate": 'Basic realm="File share"'},
        )
    return None


def send_file_with_range(
    filepath: Path,
    as_attachment: bool = True,
    download_name: str | None = None,
    mimetype: str | None = None,
):
    size = filepath.stat().st_size
    range_header = request.headers.get("Range")
    name = download_name or filepath.name
    if mimetype is None:
        mimetype = mimetypes.guess_type(str(filepath), strict=False)[0]

    if not range_header or not range_header.strip().lower().startswith("bytes="):
        db.log_download(
            app.config["FILE_SHARE_DB"],
            str(filepath),
            client_ip(),
            request.user_agent.string if request.user_agent else None,
            request.authorization.username if request.authorization else None,
            range_request=False,
        )
        chunk_size = 262144

        def stream_full():
            with open(filepath, "rb") as f:
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    yield data

        from flask import Response
        from urllib.parse import quote
        r = Response(stream_full(), status=200, mimetype=mimetype or "application/octet-stream")
        r.headers["Content-Length"] = size
        r.headers["Accept-Ranges"] = "bytes"
        if as_attachment:
            r.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(name)}"
        else:
            r.headers["Content-Disposition"] = f"inline; filename*=UTF-8''{quote(name)}"
        return r

    match = re.match(r"bytes=(\d*)-(\d*)", range_header.strip())
    if not match:
        return send_file(filepath, as_attachment=as_attachment, download_name=name, mimetype=mimetype)

    start_s, end_s = match.group(1), match.group(2)
    start = int(start_s) if start_s else 0
    end = int(end_s) if end_s else size - 1
    if start >= size:
        return "", 416, {"Content-Range": f"bytes */{size}"}
    end = min(end, size - 1)
    if start > end:
        return "", 416, {"Content-Range": f"bytes */{size}"}

    length = end - start + 1
    db.log_download(
        app.config["FILE_SHARE_DB"],
        str(filepath),
        client_ip(),
        request.user_agent.string if request.user_agent else None,
        request.authorization.username if request.authorization else None,
        range_request=True,
    )

    def stream():
        with open(filepath, "rb") as f:
            f.seek(start)
            remaining = length
            chunk_size = 262144
            while remaining > 0:
                read = min(chunk_size, remaining)
                data = f.read(read)
                if not data:
                    break
                remaining -= len(data)
                yield data

    from flask import Response
    from urllib.parse import quote
    r = Response(stream(), status=206, mimetype=mimetype or "application/octet-stream")
    r.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    r.headers["Content-Length"] = length
    r.headers["Accept-Ranges"] = "bytes"
    if as_attachment:
        r.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{quote(name)}"
    else:
        r.headers["Content-Disposition"] = f"inline; filename*=UTF-8''{quote(name)}"
    return r


@app.route("/")
def index():
    shares = get_shares()
    server = get_server_config(CONFIG_PATH)
    title = server["name"].replace("<", "&lt;").replace(">", "&gt;")
    if not shares:
        return "<!DOCTYPE html><html><head><title>%s</title></head><body><p>No shares configured.</p></body></html>" % title
    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>%s</title>" % title,
        "<style>",
        "body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; flex-direction: column; }",
        ".app-main { flex: 1; margin: 2rem; }",
        "a { color: #2563eb; text-decoration: none; }",
        "a:hover { text-decoration: underline; }",
        "h1 { font-size: 1.5rem; margin-bottom: 1rem; }",
        ".breadcrumb { margin-bottom: 1rem; }",
        "ul { list-style: none; padding-left: 0; }",
        "li { margin: 0.25rem 0; }",
        ".app-footer { margin: 2rem; font-size: 0.875rem; color: #6b7280; }",
        "@media (max-width: 768px) { .app-main { margin: 1rem; } li { padding: 0.5rem 0; min-height: 2.5rem; } }",
        "</style></head><body>",
        "<main class='app-main'><h1>%s</h1><ul>" % title,
    ]
    listable_slugs = _listable_slugs_from_cookie()
    for s in shares:
        if s.visibility != "visible" and s.slug not in listable_slugs:
            continue
        safe_label = s.name.replace("<", "&lt;").replace(">", "&gt;")
        lines.append("<li><a href='/%s/'>%s</a></li>" % (s.slug, safe_label))
    lines.append("</ul></main><footer class='app-footer'>%s</footer></body></html>" % server["footer"])
    return "\n".join(lines)


@app.route("/<slug>/")
@app.route("/<slug>/<path:subpath>")
def share_path(slug: str, subpath: str = ""):
    share, _ = get_share_by_slug(slug)
    if share is None:
        abort(404)
    err = require_auth(share)
    if err is not None:
        resp = make_response(err[0], err[1])
        if len(err) > 2:
            resp.headers.update(err[2])
        _remove_slug_from_listable_cookie(resp, share.slug)
        return resp

    resolved = resolve_path(share, subpath)
    if resolved is None or not resolved.exists():
        abort(404)

    effective_visibility = get_effective_visibility(share)
    if resolved.is_dir() and effective_visibility == "all-hidden":
        if share.public and has_listing_credentials(share):
            if request.args.get("login"):
                resp = make_response(
                    "<!DOCTYPE html><html><head><title>Log in</title></head><body><p>Authentication required.</p></body></html>",
                    401,
                )
                resp.headers["WWW-Authenticate"] = 'Basic realm="File share"'
                _remove_slug_from_listable_cookie(resp, share.slug)
                return resp
            login_path = request.path + ("&" if "?" in request.path else "?") + "login=1"
            resp = make_response(
                "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Log in</title>"
                "<body><p>This share requires authentication to browse.</p>"
                "<p><a href='%s'>Log in</a></p></body></html>" % login_path,
                200,
            )
            _remove_slug_from_listable_cookie(resp, share.slug)
            return resp
        abort(404)

    if resolved.is_file():
        if resolved.name == "index.info":
            abort(404)
        guessed = mimetypes.guess_type(str(resolved), strict=False)[0] or ""
        as_attachment = not guessed.startswith("image/")
        r = send_file_with_range(
            resolved,
            as_attachment=as_attachment,
            download_name=resolved.name,
            mimetype=guessed if guessed else None,
        )
        _maybe_set_listable_cookie(r, share)
        return r

    INDEX_INFO = "index.info"
    entries = []
    try:
        for e in sorted(resolved.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            if e.name == INDEX_INFO:
                continue
            rel = e.relative_to(share.root)
            name = e.name
            if e.is_dir():
                name += "/"
                url = "/%s/%s/" % (share.slug, rel.as_posix())
                size_str = "-"
            else:
                url = "/%s/%s" % (share.slug, rel.as_posix())
                try:
                    size_str = format_size(e.stat().st_size)
                except OSError:
                    size_str = "-"
            mtime_str = format_mtime(e)
            entries.append((name, url, e.is_dir(), mtime_str, size_str))
    except OSError:
        abort(404)

    path_parts = [p for p in subpath.strip().split("/") if p]
    server = get_server_config(CONFIG_PATH)
    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    breadcrumb_segments = []
    breadcrumb_segments.append((_esc(server["name"]), "/"))
    breadcrumb_segments.append((_esc(share.name), "/%s/" % share.slug))
    for i, part in enumerate(path_parts):
        escaped = _esc(part)
        url = "/%s/%s/" % (share.slug, "/".join(path_parts[: i + 1]))
        breadcrumb_segments.append((escaped, url))
    bits = []
    for i, (label, url) in enumerate(breadcrumb_segments):
        if i < len(breadcrumb_segments) - 1:
            bits.append('<a href="%s">%s</a>' % (url, label))
        else:
            bits.append("<span class='breadcrumb-current'>%s</span>" % label)
    breadcrumb_html = " / ".join(bits)

    if not path_parts:
        title = share.name
    else:
        title = resolved.name or "/"
    title_escaped = _esc(title)
    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>%s</title>" % (title_escaped,),
        "<style>",
        "body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; flex-direction: column; }",
        ".app-main { flex: 1; margin: 2rem; max-width: 56rem; }",
        "a { color: #2563eb; text-decoration: none; }",
        "a:hover { text-decoration: underline; }",
        "h1 { font-size: 1.5rem; margin-bottom: 1rem; }",
        ".breadcrumb { margin-bottom: 1rem; color: #6b7280; font-size: 0.9375rem; }",
        ".breadcrumb a { color: #2563eb; }",
        ".breadcrumb-current { font-weight: 500; color: #111827; }",
        "table { width: 100%%; border-collapse: collapse; }",
        "th { text-align: left; padding: 0.5rem 1rem; font-weight: 600; color: #374151; border-bottom: 1px solid #e5e7eb; }",
        "td { padding: 0.5rem 1rem; border-bottom: 1px solid #f3f4f6; }",
        "tr:hover td { background: #f9fafb; }",
        "td.name { font-weight: 500; }",
        "td.mtime, td.size { color: #6b7280; font-variant-numeric: tabular-nums; }",
        "td.size { text-align: right; }",
        ".dir .name { font-weight: 600; }",
        ".app-footer { margin: 2rem; font-size: 0.875rem; color: #6b7280; }",
        ".dir-description { margin: 1rem 0; padding: 1rem; background: #f8fafc; border-radius: 0.25rem; color: #374151; white-space: pre-wrap; font-size: 0.9375rem; }",
        "@media (max-width: 768px) { .app-main { margin: 1rem; } thead { display: none; } tbody tr { display: block; padding: 0.75rem 0; border-bottom: 1px solid #e5e7eb; } tbody td { border: none; padding: 0.25rem 0; display: block; } tbody td.name { padding-bottom: 0.25rem; } tbody td.name a { display: block; line-height: 1.4; padding: 0.25rem 0; } tbody td.mtime, tbody td.size { display: inline; font-size: 0.8125rem; color: #6b7280; } tbody td.mtime { margin-right: 1rem; } tbody td.mtime::before { content: 'Modified: '; font-weight: 600; color: #374151; } tbody td.size::before { content: 'Size: '; font-weight: 600; color: #374151; } .app-footer { margin: 1rem; } }",
        "</style></head><body>",
        "<main class='app-main'><h1>%s</h1>" % (title_escaped,),
    ]
    lines.append("<p class='breadcrumb'>%s</p>" % breadcrumb_html)
    root_resolved = share.root.resolve()
    current = resolved
    info_file = None
    while True:
        try:
            if not str(current.resolve()).startswith(str(root_resolved)):
                break
        except OSError:
            break
        candidate = current / INDEX_INFO
        if candidate.is_file():
            info_file = candidate
            break
        if current == share.root:
            break
        current = current.parent
    if info_file is not None:
        try:
            desc = info_file.read_text(encoding="utf-8", errors="replace").strip()
            if desc:
                desc_escaped = desc.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                lines.append("<div class='dir-description'>%s</div>" % desc_escaped)
        except OSError:
            pass
    lines.append("<table><thead><tr><th>Name</th><th>Modified</th><th class='size'>Size</th></tr></thead><tbody>")
    for name, url, is_dir, mtime_str, size_str in entries:
        row_cls = " class='dir'" if is_dir else ""
        safe_name = name.replace("<", "&lt;").replace(">", "&gt;")
        lines.append("<tr%s><td class='name'><a href='%s'>%s</a></td><td class='mtime'>%s</td><td class='size'>%s</td></tr>" % (row_cls, url, safe_name, mtime_str, size_str))
    lines.append("</tbody></table></main><footer class='app-footer'>%s</footer></body></html>" % server["footer"])
    resp = make_response("\n".join(lines))
    _maybe_set_listable_cookie(resp, share)
    return resp


if __name__ == "__main__":
    logger.info("Listening on %s:%s", _server_config["host"], _server_config["port"])
    app.run(host=_server_config["host"], port=_server_config["port"])
