#!/usr/bin/env bash
# Distro-agnostic linux-amd64 tarball. Output: deploy/out/livecam-linux-amd64.tar.gz
# Unpack: sudo tar -C /opt -xzf livecam-linux-amd64.tar.gz
# (layout is opt/livecam + usr/bin/livecam-setup; tar -C /opt would nest wrong)
# Correct unpack from repo root of the archive:
#   sudo tar -C / -xzf livecam-linux-amd64.tar.gz
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
	echo "build-tarball.sh: Linux amd64 only" >&2
	exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PATH="${HOME}/.cargo/bin:${HOME}/sdk/go/bin:${PATH}"
if [[ "${LIVE_SKIP_BUILD:-}" != 1 ]]; then
	(cd "$REPO_ROOT/rust-core" && cargo build --release --offline 2>/dev/null || cargo build --release)
	(cd "$REPO_ROOT/go-features" && go build -mod=vendor -o api/api-server ./api)
fi
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/livecam-tar.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
STAGE="$STAGE" . "$SCRIPT_DIR/stage-linux.sh"
mkdir -p "$REPO_ROOT/deploy/out"
OUT="$REPO_ROOT/deploy/out/livecam-linux-amd64.tar.gz"
tar -C "$STAGE" -czf "$OUT" opt usr
echo "wrote $OUT"
tar tzf "$OUT" | head
