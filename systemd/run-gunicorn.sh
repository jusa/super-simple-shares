#!/bin/sh
# Reads host and port from config.ini [server] and execs gunicorn.
# Expects WorkingDirectory to be the app root; use FILE_SHARE_CONFIG for config path.

set -e
CONFIG="${FILE_SHARE_CONFIG:-config.ini}"
if [ ! -f "$CONFIG" ]; then
    echo "Config not found: $CONFIG" >&2
    exit 1
fi

# Default timeout for unicorn worker is 2 days. 0 for no timeout.
USE_TIMEOUT=172800
if [ -n "$TIMEOUT" ]; then
    USE_TIMEOUT=$TIMEOUT
fi

port=$(awk '/^\[server\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*port[[:space:]]*=/ {gsub(/^[^=]*=[[:space:]]*|[[:space:]]*$/,""); print; exit}' "$CONFIG")
host=$(awk '/^\[server\]/{f=1;next} /^\[/{f=0} f&&/^[[:space:]]*host[[:space:]]*=/ {gsub(/^[^=]*=[[:space:]]*|[[:space:]]*$/,""); print; exit}' "$CONFIG")
port=${port:-5000}
host=${host:-127.0.0.1}

GUNICORN="${GUNICORN:-.venv/bin/gunicorn}"
exec "$GUNICORN" -w 1 --timeout $USE_TIMEOUT -b "${host}:${port}" app:app
