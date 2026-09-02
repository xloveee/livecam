#!/usr/bin/env bash
# Build livecam.rpm (RPM-family). Output: deploy/out/livecam.rpm
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then
	echo "build-rpm.sh: Linux x86_64 only" >&2
	exit 1
fi
if ! command -v rpmbuild >/dev/null 2>&1; then
	echo "rpmbuild not on PATH; install rpm-build, or use the tarball:" >&2
	echo "  sudo tar -C / -xzf deploy/out/livecam-linux-amd64.tar.gz" >&2
	echo "  sudo /usr/bin/livecam-setup DOMAIN EMAIL" >&2
	exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERSION="${LIVE_DEB_VERSION:-0.1.0}"
export PATH="${HOME}/.cargo/bin:${HOME}/sdk/go/bin:${PATH}"
if [[ "${LIVE_SKIP_BUILD:-}" != 1 ]]; then
	(cd "$REPO_ROOT/rust-core" && cargo build --release --offline 2>/dev/null || cargo build --release)
	(cd "$REPO_ROOT/go-features" && go build -mod=vendor -o api/api-server ./api)
fi
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/livecam-rpm.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
STAGE="$STAGE/root" . "$SCRIPT_DIR/stage-linux.sh"
TOP="$STAGE/rpmbuild"
mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp -a "$STAGE/root/." "$TOP/SOURCES/"
sed "s/^Version:.*/Version:        $VERSION/" "$SCRIPT_DIR/livecam.spec" > "$TOP/SPECS/livecam.spec"
rpmbuild --define "_topdir $TOP" --define "_sourcedir $TOP/SOURCES" -bb "$TOP/SPECS/livecam.spec"
mkdir -p "$REPO_ROOT/deploy/out"
find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$REPO_ROOT/deploy/out/livecam.rpm" \;
echo "wrote $REPO_ROOT/deploy/out/livecam.rpm"
rpm -qpi "$REPO_ROOT/deploy/out/livecam.rpm"
