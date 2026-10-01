# Copyright (c) 2026 Enni Hämäläinen
#
# SPDX-License-Identifier: MIT

import hashlib
import hmac
import html
import logging
import mimetypes
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, abort, g, make_response, redirect, request, send_file, session

from config import get_server_config, load_config, Share
import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

CONFIG_PATH = os.environ.get("FILE_SHARE_CONFIG", "config.ini")

_server_config = get_server_config(CONFIG_PATH)
app.config["FILE_SHARE_DB"] = _server_config["db"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.permanent_session_lifetime = timedelta(seconds=_server_config["cookie_lifetime"])
db.init_db(app.config["FILE_SHARE_DB"])
app.secret_key = _server_config["secret"] or db.get_or_create_secret(app.config["FILE_SHARE_DB"])

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


AUTH_SESSION_KEY = "auth"
_VIS_ORDER = {"visible": 0, "hidden": 1, "all-hidden": 2}


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _credential_token(user: str, password: str) -> str:
    key = app.secret_key
    if isinstance(key, str):
        key = key.encode()
    msg = user.encode() + b"\0" + password.encode()
    return hmac.new(key, msg, "sha256").hexdigest()


def _auth_map() -> dict[str, list[str]]:
    raw = session.get(AUTH_SESSION_KEY)
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for slug, tokens in raw.items():
        if not isinstance(slug, str) or not isinstance(tokens, list):
            continue
        kept = [t for t in tokens if isinstance(t, str)]
        if kept:
            out[slug] = kept
    return out


def _share_tokens(slug: str) -> set[str]:
    return set(_auth_map().get(slug, []))


def remember_login(share: Share, user: str, password: str) -> None:
    token = _credential_token(user, password)
    auth = _auth_map()
    tokens = set(auth.get(share.slug, []))
    if token in tokens:
        return
    tokens.add(token)
    auth[share.slug] = sorted(tokens)
    session[AUTH_SESSION_KEY] = auth
    session.permanent = True


def forget_share(slug: str) -> None:
    auth = _auth_map()
    if slug not in auth:
        return
    auth.pop(slug, None)
    if auth:
        session[AUTH_SESSION_KEY] = auth
    else:
        session.pop(AUTH_SESSION_KEY, None)


def _posted_login() -> tuple[str, str] | None:
    if request.method != "POST":
        return None
    if "username" not in request.form and "password" not in request.form:
        return None
    return ((request.form.get("username") or "").strip(), request.form.get("password") or "")


_SHA256_UNSALTED = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
_SHA256_SALTED = re.compile(r"^sha256:([0-9a-fA-F]+):([0-9a-fA-F]{64})$")


def _equals(given: str, expected: str) -> bool:
    return hmac.compare_digest(given.encode(), expected.encode())


def _password_matches(given: str, expected: str) -> bool:
    salted = _SHA256_SALTED.match(expected)
    if salted:
        salt_hex, digest_hex = salted.group(1), salted.group(2)
        if len(salt_hex) < 16 or len(salt_hex) % 2:
            return False
        digest = hashlib.sha256(bytes.fromhex(salt_hex) + given.encode()).hexdigest()
        return hmac.compare_digest(digest, digest_hex.lower())
    unsalted = _SHA256_UNSALTED.match(expected)
    if unsalted:
        digest = hashlib.sha256(given.encode()).hexdigest()
        return hmac.compare_digest(digest, unsalted.group(1).lower())
    return _equals(given, expected)


def matching_credentials(share: Share) -> list[tuple[str, str, str | None]]:
    cache = getattr(g, "_match_cache", None)
    if cache is None:
        cache = {}
        g._match_cache = cache
    if share.slug in cache:
        return cache[share.slug]

    tokens = _share_tokens(share.slug)
    found: list[tuple[str, str, str | None]] = []
    seen: set[str] = set()
    for cred in share.credentials:
        user, password, _vis = cred
        token = _credential_token(user, password)
        if token in tokens and token not in seen:
            found.append(cred)
            seen.add(token)

    posted = _posted_login()
    if posted and posted[0]:
        user, password = posted
        for cred in share.credentials:
            cu, cp, _vis = cred
            if _equals(user, cu) and _password_matches(password, cp):
                remember_login(share, cu, cp)
                token = _credential_token(cu, cp)
                if token not in seen:
                    found.append(cred)
                    seen.add(token)
                break

    cache[share.slug] = found
    return found


def check_auth(share: Share) -> bool:
    if share.public:
        return True
    return bool(matching_credentials(share))


def get_effective_visibility(share: Share) -> str:
    best = share.visibility
    best_rank = _VIS_ORDER.get(best, 1)
    for _user, _password, vis in matching_credentials(share):
        candidate = vis or share.visibility
        rank = _VIS_ORDER.get(candidate, 1)
        if rank < best_rank:
            best = candidate
            best_rank = rank
    return best


def authenticated_username(share: Share) -> str | None:
    matches = matching_credentials(share)
    if not matches:
        return None
    best_user = matches[0][0]
    best_rank = 99
    for user, _password, vis in matches:
        rank = _VIS_ORDER.get(vis or share.visibility, 1)
        if rank < best_rank:
            best_rank = rank
            best_user = user
    return best_user


def has_listing_credentials(share: Share) -> bool:
    return any(vis in ("hidden", "visible") for _, _, vis in share.credentials if vis)

LISTABLE_COOKIE = "sss_listable"


@app.before_request
def _apply_cookie_lifetime() -> None:
    seconds = get_server_config(CONFIG_PATH)["cookie_lifetime"]
    app.permanent_session_lifetime = timedelta(seconds=seconds)


def _cookie_max_age() -> int:
    return int(app.permanent_session_lifetime.total_seconds())


def _listable_slugs_from_cookie() -> set[str]:
    raw = request.cookies.get(LISTABLE_COOKIE) or ""
    return {s.strip() for s in raw.split(",") if s.strip()}


def _maybe_set_listable_cookie(response, share: Share) -> None:
    if share.visibility not in ("hidden", "all-hidden"):
        return
    if get_effective_visibility(share) not in ("visible", "hidden"):
        return
    if not matching_credentials(share):
        return
    slugs = _listable_slugs_from_cookie() | {share.slug}
    response.set_cookie(
        LISTABLE_COOKIE,
        ",".join(sorted(slugs)),
        max_age=_cookie_max_age(),
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
            max_age=_cookie_max_age(),
            path="/",
            httponly=True,
            samesite="Lax",
        )


def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _has_any_login() -> bool:
    if _auth_map():
        return True
    return bool(_listable_slugs_from_cookie())


def _logout_all_link() -> str:
    if not _has_any_login():
        return ""
    return "<p class='logout'><a href='/logout'>Log out from all shares</a></p>"


def _share_logout_link(share: Share) -> str:
    if not _share_tokens(share.slug):
        return ""
    return "<p class='logout'><a href='/logout/%s'>Log out</a></p>" % share.slug


def login_page(
    share: Share,
    *,
    error: str | None = None,
    status: int = 401,
    message: str | None = None,
):
    server = get_server_config(CONFIG_PATH)
    username_value = ""
    if error and request.method == "POST":
        username_value = _esc((request.form.get("username") or "").strip())
    err_html = "<p class='error'>%s</p>" % _esc(error) if error else ""
    msg = message or "Authentication required."
    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Log in</title>",
        "<style>",
        "body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: flex; flex-direction: column; }",
        ".app-main { flex: 1; margin: 2rem; max-width: 24rem; }",
        "a { color: #2563eb; text-decoration: none; }",
        "a:hover { text-decoration: underline; }",
        "h1 { font-size: 1.5rem; margin-bottom: 1rem; }",
        ".breadcrumb { margin-bottom: 1rem; color: #6b7280; font-size: 0.9375rem; }",
        ".breadcrumb a { color: #2563eb; }",
        "label { display: block; margin: 0.75rem 0; font-weight: 500; }",
        "input { display: block; width: 100%; margin-top: 0.25rem; padding: 0.45rem 0.5rem; font: inherit; box-sizing: border-box; }",
        "button { font: inherit; margin-top: 0.5rem; padding: 0.45rem 0.9rem; cursor: pointer; }",
        ".error { color: #b91c1c; }",
        ".app-footer { margin: 2rem; font-size: 0.875rem; color: #6b7280; }",
        "@media (max-width: 768px) { .app-main { margin: 1rem; } }",
        "</style></head><body>",
        "<main class='app-main'>",
        "<p class='breadcrumb'><a href='/'>{}</a> / {}</p>".format(_esc(server["name"]), _esc(share.name)),
        "<h1>Log in</h1>",
        "<p>%s</p>" % _esc(msg),
        err_html,
        "<form class='login' method='post' action='%s'>" % _esc(request.path),
        "<label>Username <input name='username' value='%s' autocomplete='username' required></label>" % username_value,
        "<label>Password <input type='password' name='password' autocomplete='current-password' required></label>",
        "<button type='submit'>Log in</button>",
        "</form></main>",
        "<footer class='app-footer'>%s</footer></body></html>" % server["footer"],
    ]
    resp = make_response("\n".join(lines), status)
    resp.headers["Cache-Control"] = "no-store"
    _remove_slug_from_listable_cookie(resp, share.slug)
    return resp


def send_file_with_range(
    filepath: Path,
    as_attachment: bool = True,
    download_name: str | None = None,
    mimetype: str | None = None,
    username: str | None = None,
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
            username,
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
        username,
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
    lines.append("</ul>%s</main><footer class='app-footer'>%s</footer></body></html>" % (_logout_all_link(), server["footer"]))
    return "\n".join(lines)


@app.route("/logout")
def logout():
    session.pop(AUTH_SESSION_KEY, None)
    resp = redirect("/")
    resp.delete_cookie(LISTABLE_COOKIE, path="/")
    return resp


@app.route("/logout/<slug>")
def logout_share(slug: str):
    share, _ = get_share_by_slug(slug)
    if share is None:
        abort(404)
    forget_share(slug)
    resp = redirect("/%s/" % slug)
    _remove_slug_from_listable_cookie(resp, slug)
    return resp


@app.route("/<slug>/", methods=["GET", "POST"])
@app.route("/<slug>/<path:subpath>", methods=["GET", "POST"])
def share_path(slug: str, subpath: str = ""):
    share, _ = get_share_by_slug(slug)
    if share is None:
        abort(404)
    matches = matching_credentials(share)
    posted = _posted_login()
    login_error = None
    if posted is not None and posted[0] and not matches:
        login_error = "Invalid username or password."
    if not check_auth(share):
        return login_page(share, error=login_error)

    resolved = resolve_path(share, subpath)
    if resolved is None or not resolved.exists():
        abort(404)

    effective_visibility = get_effective_visibility(share)
    if resolved.is_dir() and effective_visibility == "all-hidden":
        if share.public and has_listing_credentials(share):
            notice = login_error
            if matches and not notice:
                notice = "These credentials do not allow browsing this share."
            return login_page(
                share,
                error=notice,
                status=200,
                message="This share requires authentication to browse.",
            )
        abort(404)

    if resolved.is_dir() and request.method == "POST":
        resp = redirect(request.path, code=303)
        _maybe_set_listable_cookie(resp, share)
        return resp

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
            username=authenticated_username(share),
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
    lines.append("</tbody></table>%s</main><footer class='app-footer'>%s</footer></body></html>" % (_share_logout_link(share), server["footer"]))
    resp = make_response("\n".join(lines))
    _maybe_set_listable_cookie(resp, share)
    return resp


if __name__ == "__main__":
    logger.info("Listening on %s:%s", _server_config["host"], _server_config["port"])
    app.run(host=_server_config["host"], port=_server_config["port"])
