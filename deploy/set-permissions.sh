#!/bin/bash
# Fix ownership and modes for /opt/livecam after deploy or git pull.
# Run as root once, or as livecam when livecam already owns the tree.
set -euo pipefail

ROOT="/opt/livecam"
OWNER="livecam"
GROUP="www-data"

if [[ ! -d "$ROOT" ]]; then
	echo "missing $ROOT" >&2
	exit 1
fi

if [[ "$(id -un)" != "root" && "$(id -un)" != "$OWNER" ]]; then
	echo "run as root or $OWNER" >&2
	exit 1
fi

chown -R "$OWNER:$GROUP" "$ROOT"

install -d -o "$OWNER" -g "$GROUP" -m 2770 "$ROOT/archive"
install -d -o "$OWNER" -g "$GROUP" -m 2770 "$ROOT/hls"
install -d -o "$OWNER" -g "$GROUP" -m 2770 "$ROOT/data"
install -d -o "$OWNER" -g "$GROUP" -m 2770 "$ROOT/data/offline_banners"
install -d -o "$OWNER" -g "$GROUP" -m 2750 "$ROOT/deploy"

if [[ -f "$ROOT/deploy/.env" ]]; then
	chown "$OWNER:$GROUP" "$ROOT/deploy/.env"
	chmod 640 "$ROOT/deploy/.env"
fi

if [[ -f "$ROOT/deploy/.env.example" ]]; then
	chmod 644 "$ROOT/deploy/.env.example"
fi

find "$ROOT" -type d ! -path "$ROOT/deploy" -exec chmod 775 {} +
chmod 750 "$ROOT/deploy"

find "$ROOT" -type f ! -path "$ROOT/deploy/.env" -exec chmod 664 {} +
find "$ROOT" -type f \( -name 'api-server' -o -name 'rust-core' \) -exec chmod 775 {} +
find "$ROOT/deploy" -type f -name '*.sh' -exec chmod 775 {} +

echo "permissions applied: $OWNER:$GROUP under $ROOT"
