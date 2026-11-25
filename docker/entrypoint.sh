#!/bin/sh
# Container start: fix data-folder ownership, provide a SECRET_KEY, prepare the
# database, print a first invite key, then run the server without root rights.
set -eu

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"   # /app in the image
cd "$APP_DIR"
export PYTHONPATH="$APP_DIR"
DATA_DIR="${DATA_DIR:-/data}"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
export DATA_DIR PUID PGID

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR/uploads"
    # Only walk the whole tree if something near the top has another owner (first
    # start, changed PUID, or folders created by root such as uploads/ above).
    # Checking only $DATA_DIR is not enough: Unraid creates the appdata folder
    # already owned by 99:100, which left the root-made uploads/ unwritable.
    if [ -n "$(find "$DATA_DIR" -maxdepth 2 \( ! -user "$PUID" -o ! -group "$PGID" \) -print -quit)" ]; then
        echo "Setting owner of $DATA_DIR to $PUID:$PGID"
        chown -R "$PUID:$PGID" "$DATA_DIR"
    fi
fi
run_as() { python "$APP_DIR/docker/run_as.py" "$@"; }

# SECRET_KEY: use the configured one, otherwise generate one once and keep it
# in the data folder (so sessions survive restarts and image updates).
if [ -z "${SECRET_KEY:-}" ]; then
    KEY_FILE="$DATA_DIR/.secret_key"
    export KEY_FILE
    if [ ! -s "$KEY_FILE" ]; then
        run_as python -c \
            "import os, secrets; os.umask(0o077); open(os.environ['KEY_FILE'], 'w').write(secrets.token_hex(32))"
        echo "Generated a SECRET_KEY in $KEY_FILE"
    fi
    SECRET_KEY="$(cat "$KEY_FILE")"
    export SECRET_KEY
fi

run_as python -c "from src.app import initialize_app_storage; initialize_app_storage()"
run_as python "$APP_DIR/src/manage.py" ensure-invite

exec python "$APP_DIR/docker/run_as.py" "$@"
