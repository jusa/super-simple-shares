# Super Simple Shares

Python file sharing app: directory listing and downloads with per-directory auth and download logging.

- **Config**: `config.ini` (see `config.ini.example`). Path to config: env `FILE_SHARE_CONFIG` or `config.ini`. Under `[server]`: `port`, `host`, `db`, `name`, `footer`. Share sections are filesystem paths; `public`, `credentials.N`, etc.
- **DB**: SQLite path is set in config `[server]` `db`; stores each download (time, IP, user-agent, path, optional username).
- **Run**: `python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python app.py`. Use nginx (or similar) in front for SSL and proxy to this app.

Resumable downloads: server sends `Accept-Ranges: bytes` and handles `Range` requests (206 Partial Content).
