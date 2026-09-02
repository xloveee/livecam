#!/usr/bin/env bash
# Build livecam.deb on Linux amd64. Output: deploy/out/livecam.deb
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
	echo "build-deb.sh: Linux amd64 only (this host is $(uname -s)/$(uname -m))" >&2
	exit 1
fi
if [[ "$(uname -m)" != x86_64 && "$(uname -m)" != amd64 ]]; then
	echo "build-deb.sh: amd64 binaries only (got $(uname -m))" >&2
	exit 1
fi
command -v dpkg-deb >/dev/null || { echo "need dpkg-deb" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${LIVE_DEB_VERSION:-0.1.0}"
# Prefer rustup/user go over distro 1.85 / 1.24.
export PATH="${HOME}/.cargo/bin:${HOME}/sdk/go/bin:${PATH}"

if [[ "${LIVE_SKIP_BUILD:-}" != 1 ]]; then
	command -v cargo >/dev/null || { echo "need cargo" >&2; exit 1; }
	command -v go >/dev/null || { echo "need go" >&2; exit 1; }
	echo "building rust-core --release"
	(cd "$REPO_ROOT/rust-core" && cargo build --release --offline 2>/dev/null || cargo build --release)
	echo "building go-proxy"
	(cd "$REPO_ROOT/go-features" && go build -mod=vendor -o api/api-server ./api)
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/livecam-deb.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
STAGE="$STAGE" . "$SCRIPT_DIR/stage-linux.sh"

mkdir -p "$STAGE/DEBIAN"
sed "s/__VERSION__/$VERSION/" "$SCRIPT_DIR/control.in" > "$STAGE/DEBIAN/control"
install -m 755 "$SCRIPT_DIR/postinst" "$STAGE/DEBIAN/postinst"
install -m 755 "$SCRIPT_DIR/prerm" "$STAGE/DEBIAN/prerm"

mkdir -p "$REPO_ROOT/deploy/out"
DEB="$REPO_ROOT/deploy/out/livecam.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$DEB"
echo "wrote $DEB"
dpkg-deb -I "$DEB"
