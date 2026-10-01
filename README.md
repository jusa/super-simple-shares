# Super Simple Shares

Python file sharing app: directory listing and downloads with per-directory auth and download logging.

- **Config**: `config.ini` (see `config.ini.example`). Path to config: env `FILE_SHARE_CONFIG` or `config.ini`. Under `[server]`: `port`, `host`, `db`, `name`, `footer`, optional `secret`, optional `cookie_lifetime` (`12h` or `7d`, default `7d`). Any other `[server]` key is a string you can insert as `$KEY` in `db` and in share sections (`ROOT = /home/foo/bar`, then `[$ROOT/share-1]` and `db = $ROOT/my_db.db`). Share sections are filesystem paths; `public`, `credentials.N`, etc.
- **Auth**: protected shares show an HTML login form. A successful login is kept in a signed cookie, and that cookie can hold logins for more than one share. A credential password may be plain text or a `sha256:` hash (see `config.ini.example`). Omit `[server]` `secret` to store a generated secret in the database when `db` is set, or to use a new random secret on each start when it is not. From the command line, POST `username` and `password` (the response sets the same cookie):

  ```bash
  curl -c cookies.txt -b cookies.txt -d "username=user&password=secret" -L -O http://127.0.0.1:5000/slug/file
  ```

  A POST straight to a file URL returns the file. A POST to a directory responds with a redirect, so add `-L` when you want the listing.
- **DB**: Optional. Set `[server]` `db` to a SQLite path to log each download (time, IP, user-agent, path, optional username). If `db` is omitted, nothing is logged and no database file is created.
- **Run**: `python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python app.py`. Use nginx (or similar) in front for SSL and proxy to this app.

Resumable downloads: server sends `Accept-Ranges: bytes` and handles `Range` requests (206 Partial Content).
