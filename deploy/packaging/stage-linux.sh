#!/usr/bin/env bash
# Shared staging for .deb / .rpm / tarball. Expects built binaries.
# Usage: STAGE=/tmp/x . deploy/packaging/stage-linux.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STAGE="${STAGE:?STAGE is required}"
RUST_BIN="${RUST_BIN:-$REPO_ROOT/rust-core/target/release/rust-core}"
GO_BIN="${GO_BIN:-$REPO_ROOT/go-features/api/api-server}"
[[ -x "$RUST_BIN" ]] || { echo "missing $RUST_BIN" >&2; exit 1; }
[[ -x "$GO_BIN" ]] || { echo "missing $GO_BIN" >&2; exit 1; }

ROOT="$STAGE/opt/livecam"
mkdir -p "$ROOT/rust-core/target/release" \
	"$ROOT/go-features/api" \
	"$ROOT/client" \
	"$ROOT/deploy/templates" \
	"$STAGE/usr/bin"
install -m 755 "$RUST_BIN" "$ROOT/rust-core/target/release/rust-core"
install -m 755 "$GO_BIN" "$ROOT/go-features/api/api-server"
if [[ -d "$REPO_ROOT/client" ]]; then
	cp -a "$REPO_ROOT/client/." "$ROOT/client/"
	find "$ROOT/client" -name '._*' -delete || true
fi
install -m 755 "$REPO_ROOT/deploy/install.sh" "$ROOT/deploy/install.sh"
cp -a "$REPO_ROOT/deploy/templates/." "$ROOT/deploy/templates/"
install -m 755 "$SCRIPT_DIR/livecam-setup" "$STAGE/usr/bin/livecam-setup"
rm -f "$ROOT/deploy/.env"
