#!/bin/bash
# H12: source tree is not group-writable by the runtime user.
# Writable only: data/, hls/, archive/, and deploy/.env (640).
set -euo pipefail

ROOT="/opt/livecam"
OWNER="${LIVECAM_OWNER:-livecam}"
RUNTIME_GROUP="${LIVECAM_RUNTIME_GROUP:-www-data}"

if [[ ! -d "$ROOT" ]]; then
	echo "missing $ROOT" >&2
	exit 1
fi

if [[ "$(id -un)" != "root" && "$(id -un)" != "$OWNER" ]]; then
	echo "run as root or $OWNER" >&2
	exit 1
fi

# Tree owned by deploy user; runtime group may read but not rewrite source/binaries.
chown -R "$OWNER:$RUNTIME_GROUP" "$ROOT"

# Default: dirs 755, files 644 (not 775/664).
find "$ROOT" -type d -exec chmod 755 {} +
find "$ROOT" -type f -exec chmod 644 {} +

# Runtime-writable areas only.
install -d -o "$OWNER" -g "$RUNTIME_GROUP" -m 2770 "$ROOT/archive"
install -d -o "$OWNER" -g "$RUNTIME_GROUP" -m 2770 "$ROOT/hls"
install -d -o "$OWNER" -g "$RUNTIME_GROUP" -m 2770 "$ROOT/data"
install -d -o "$OWNER" -g "$RUNTIME_GROUP" -m 2770 "$ROOT/data/offline_banners"
install -d -o "$OWNER" -g "$RUNTIME_GROUP" -m 2750 "$ROOT/deploy"

if [[ -f "$ROOT/deploy/.env" ]]; then
	chown "$OWNER:$RUNTIME_GROUP" "$ROOT/deploy/.env"
	chmod 640 "$ROOT/deploy/.env"
fi

if [[ -f "$ROOT/deploy/.env.example" ]]; then
	chmod 644 "$ROOT/deploy/.env.example"
fi

# Binaries and install scripts executable, not group-writable.
find "$ROOT" -type f \( -name 'api-server' -o -name 'rust-core' \) -exec chmod 755 {} +
find "$ROOT/deploy" -type f -name '*.sh' -exec chmod 755 {} +

echo "permissions applied (H12): $OWNER:$RUNTIME_GROUP under $ROOT (source not group-writable)"
