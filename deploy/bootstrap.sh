#!/usr/bin/env bash
# Ubuntu/Debian droplet installer for livecam.
# Preferred: sudo apt install ./livecam.deb && sudo livecam-setup DOMAIN EMAIL
# H21: never curl|bash this file. Source checkout is the fallback.
#
#   git clone https://github.com/xloveee/livecam.git /opt/livecam
#   cd /opt/livecam && git checkout "$INSTALL_REF"
#   sudo INSTALL_REF="$INSTALL_REF" ./deploy/bootstrap.sh your.domain you@email.com
#
# Or skip bootstrap and run install.sh from the same checkout:
#   sudo ./deploy/install.sh your.domain you@email.com
#
# Mac dry-run only:
#   INSTALL_DRY_RUN=1 ./deploy/bootstrap.sh example.test admin@example.test
#
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/xloveee/livecam.git}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/livecam}"
# M42: no baked SHA. Explicit INSTALL_REF pins a clone; otherwise keep an
# existing tree, or use this checkout HEAD. (A baked pin rewound installs.)
INSTALL_REF="${INSTALL_REF:-}"
PIN_FROM_ENV=0
if [[ -n "$INSTALL_REF" ]]; then
	PIN_FROM_ENV=1
fi
GO_VERSION="${GO_VERSION:-1.25.5}"
# Set GO_SHA256 to the official go.dev archive digest for GO_VERSION+arch.
GO_SHA256="${GO_SHA256:-}"

is_truthy() {
	case "${1:-}" in
	1 | true | TRUE | yes | YES | on | ON) return 0 ;;
	*) return 1 ;;
	esac
}

usage() {
	cat <<EOF
Usage (from a git checkout — do not pipe this script into bash):

  git clone ${REPO_URL} ${INSTALL_ROOT}
  cd ${INSTALL_ROOT} && git checkout ${INSTALL_REF}
  sudo ./deploy/bootstrap.sh your.domain you@email.com optional-password

  PROXY=caddy|nginx   (default caddy)
  INSTALL_DRY_RUN=1   render only (Mac ok)
  INSTALL_REF         pinned commit/tag for clone (required to clone; else checkout HEAD)
  GO_SHA256           required when this script installs Go
EOF
}

DRY_RUN=0
if is_truthy "${INSTALL_DRY_RUN:-}"; then
	DRY_RUN=1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

is_piped() {
	local src="${BASH_SOURCE[0]:-}"
	case "$src" in
	"" | "-" | "/dev/stdin" | /dev/fd/* | /proc/self/fd/*) return 0 ;;
	esac
	[[ ! -f "$src" ]]
}

REPO_ROOT=""
if ! is_piped; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

# H21: refuse curl|bash / stdin for live install.
if is_piped && [[ "$DRY_RUN" -eq 0 ]]; then
	echo "refusing piped bootstrap (H21). Clone a pinned ref and run ./deploy/bootstrap.sh from disk:" >&2
	usage >&2
	exit 1
fi

if [[ "$(uname -s)" == Darwin && "$DRY_RUN" -eq 0 ]]; then
	echo "live bootstrap is for Ubuntu/Debian droplets only. Use INSTALL_DRY_RUN=1 on this Mac." >&2
	exit 1
fi

if [[ "$DRY_RUN" -eq 0 && "$INSTALL_ROOT" == "/opt/src/livecam" ]]; then
	echo "refusing to clone or install over /opt/src/livecam" >&2
	exit 1
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
	if [[ -z "$REPO_ROOT" || ! -f "$REPO_ROOT/deploy/install.sh" ]]; then
		echo "INSTALL_DRY_RUN=1 must be run from a git checkout (./deploy/bootstrap.sh)" >&2
		exit 1
	fi
	exec "$REPO_ROOT/deploy/install.sh" "$@"
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "live bootstrap requires root (or use INSTALL_DRY_RUN=1)" >&2
	exit 1
fi

if [[ ! -f /etc/os-release ]]; then
	echo "Ubuntu/Debian required" >&2
	exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
ubuntu | debian) ;;
*)
	echo "Ubuntu/Debian required, got ${ID:-unknown}" >&2
	exit 1
	;;
esac

if [[ -z "$INSTALL_REF" && -n "$REPO_ROOT" ]] && git -C "$REPO_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
	INSTALL_REF="$(git -C "$REPO_ROOT" rev-parse HEAD)"
	echo "M42: INSTALL_REF=$INSTALL_REF (checkout HEAD)"
fi
if [[ -z "$INSTALL_REF" && ! -f "$INSTALL_ROOT/deploy/install.sh" ]]; then
	echo "INSTALL_REF is required (pinned commit or tag) to clone into $INSTALL_ROOT" >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git curl ufw ca-certificates

if [[ -f /proc/meminfo ]]; then
	mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
	if [[ "${mem_kb:-0}" -lt 4000000 && ! -f /swapfile ]]; then
		echo "adding 2G swap (MemTotal ${mem_kb} kB < 4G)"
		fallocate -l 2G /swapfile
		chmod 600 /swapfile
		mkswap /swapfile
		swapon /swapfile
		grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
	fi
fi

if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
	if is_truthy "${INSTALL_ALLOW_RUSTUP:-}"; then
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
	else
		echo "rustc/cargo required. Install from https://rustup.rs (or set INSTALL_ALLOW_RUSTUP=1)." >&2
		exit 1
	fi
fi
if [[ -f "$HOME/.cargo/env" ]]; then
	# shellcheck disable=SC1091
	. "$HOME/.cargo/env"
fi
export PATH="$HOME/.cargo/bin:/usr/local/go/bin:$PATH"

if ! command -v go >/dev/null 2>&1; then
	if [[ -z "$GO_SHA256" ]]; then
		echo "GO_SHA256 is required when installing Go (official go.dev digest for go${GO_VERSION})." >&2
		exit 1
	fi
	arch=""
	case "$(uname -m)" in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*)
		echo "unsupported arch $(uname -m) for Go tarball" >&2
		exit 1
		;;
	esac
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tar.gz
	echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c -
	rm -rf /usr/local/go
	tar -C /usr/local -xzf /tmp/go.tar.gz
	ln -sfn /usr/local/go/bin/go /usr/local/bin/go
	ln -sfn /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi
export PATH="/usr/local/go/bin:$PATH"

if [[ ! -f "$INSTALL_ROOT/deploy/install.sh" ]]; then
	if [[ -e "$INSTALL_ROOT" && ! -d "$INSTALL_ROOT" ]]; then
		echo "$INSTALL_ROOT exists and is not a directory" >&2
		exit 1
	fi
	if [[ -d "$INSTALL_ROOT" && -n "$(ls -A "$INSTALL_ROOT" 2>/dev/null || true)" ]]; then
		echo "$INSTALL_ROOT exists but has no deploy/install.sh; refusing to clone over it" >&2
		exit 1
	fi
	git clone "$REPO_URL" "$INSTALL_ROOT"
	git -C "$INSTALL_ROOT" checkout "$INSTALL_REF"
else
	# Existing tree: do not rewind to a stale pin (M42).
	if [[ "$PIN_FROM_ENV" -eq 1 ]]; then
		git -C "$INSTALL_ROOT" fetch --all --tags >/dev/null 2>&1 || true
		git -C "$INSTALL_ROOT" checkout "$INSTALL_REF"
	fi
fi

exec "$INSTALL_ROOT/deploy/install.sh" "$@"
