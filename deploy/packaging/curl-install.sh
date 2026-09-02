#!/usr/bin/env bash
# Ollama-shaped VPS installer for livecam.
# Intended: curl -fsSL <raw url> | sudo sh -s -- DOMAIN EMAIL
#
# Truncated downloads are a no-op: all work is in main(), invoked only at EOF.
# This file may be piped. deploy/bootstrap.sh still refuses pipes (H21).
set -euo pipefail

is_truthy() {
	case "${1:-}" in
	1 | true | TRUE | yes | YES | on | ON) return 0 ;;
	*) return 1 ;;
	esac
}

main() {
	local domain="${1:-}"
	local email="${2:-}"
	if [[ -z "$domain" || -z "$email" ]]; then
		echo "usage: curl -fsSL <curl-install.sh> | sudo sh -s -- your.domain you@email.com [BROADCAST_PASSWORD]" >&2
		exit 1
	fi

	local dry=0
	if is_truthy "${INSTALL_DRY_RUN:-}"; then
		dry=1
	fi

	if [[ "$(uname -s)" == Darwin && "$dry" -eq 0 ]]; then
		echo "live curl-install is for Linux VPS. Use INSTALL_DRY_RUN=1 or the package path." >&2
		exit 1
	fi

	local repo_url="${REPO_URL:-https://github.com/xloveee/livecam.git}"
	local install_root="${INSTALL_ROOT:-/opt/livecam}"
	# H29: default is the release SHA that shipped curl-install (origin app at 0f9faf6), not a moving branch.
	local ref="${INSTALL_REF:-0f9faf6237c8b2a05958f972de7c7c0ae3e422bd}"

	if [[ "$dry" -eq 1 ]]; then
		local here
		here="$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." 2>/dev/null && pwd || true)"
		if [[ -n "$here" && -f "$here/deploy/install.sh" ]]; then
			exec "$here/deploy/install.sh" "$@"
		fi
		echo "INSTALL_DRY_RUN=1 needs a git checkout (./deploy/packaging/curl-install.sh)" >&2
		exit 1
	fi

	if [[ "$(id -u)" -ne 0 ]]; then
		echo "live curl-install requires root (or INSTALL_DRY_RUN=1)" >&2
		exit 1
	fi

	if [[ ! -f "$install_root/deploy/install.sh" ]]; then
		if [[ -e "$install_root" && ! -d "$install_root" ]]; then
			echo "$install_root exists and is not a directory" >&2
			exit 1
		fi
		if [[ -d "$install_root" && -n "$(ls -A "$install_root" 2>/dev/null || true)" ]]; then
			echo "$install_root exists but has no deploy/install.sh; refusing to clone over it" >&2
			exit 1
		fi
		command -v git >/dev/null 2>&1 || { echo "git is required to clone $repo_url" >&2; exit 1; }
		git clone "$repo_url" "$install_root"
		git -C "$install_root" checkout "$ref"
	elif [[ -n "${INSTALL_REF:-}" ]]; then
		git -C "$install_root" fetch --all --tags >/dev/null 2>&1 || true
		git -C "$install_root" checkout "$ref"
	fi

	# Run the on-disk installer (never pipe bootstrap.sh).
	exec "$install_root/deploy/install.sh" "$@"
}

main "$@"
