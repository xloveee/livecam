#!/usr/bin/env bash
# VPS / custom-domain installer for livecam.
# Any hostname works. indep.stream is a demo name only — never required.
#
# One-line droplet path: see deploy/bootstrap.sh (Caddy auto-TLS default).
#   sudo ./deploy/install.sh your.domain you@email.com [BROADCAST_PASSWORD]
#   INSTALL_DRY_RUN=1 ./deploy/install.sh example.test admin@example.test
#   PROXY=nginx sudo ./deploy/install.sh your.domain you@email.com
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE_DIR="$SCRIPT_DIR/templates"

usage() {
	cat <<'EOF'
Usage: deploy/install.sh DOMAIN EMAIL [BROADCAST_PASSWORD]

  DOMAIN               Public hostname you pointed at this VPS
  EMAIL                Let's Encrypt / operator contact
  BROADCAST_PASSWORD   Optional /broadcast page password
                       (or set BROADCAST_PASSWORD in the environment)

Environment:
  INSTALL_DRY_RUN=1    Render Caddyfile, nginx, systemd, and .env under
                       deploy/out/<domain>. No root, no public-IP
                       lookup, no certbot, no packages, no network.
  PROXY                caddy (default, auto-TLS) or nginx (certbot)
  INSTALL_ROOT         Install prefix (default /opt/livecam)
  PUBLIC_IP            Override SFU advertised IPv4
  SERVICE_USER         systemd User= (default www-data)
  INSTALL_SKIP_PACKAGES=1
  INSTALL_SKIP_BUILD=1
  INSTALL_SKIP_CERTBOT=1
  INSTALL_SKIP_SYSTEMD=1

Dry-run with no args uses DOMAIN=example.test (not indep.stream).

Pinned VPS path (fresh Ubuntu/Debian, DNS A first):
  git clone https://github.com/xloveee/livecam.git /opt/livecam
  cd /opt/livecam && git checkout "$INSTALL_REF"
  sudo ./deploy/install.sh your.domain you@email.com optional-password
EOF
}

is_truthy() {
	case "${1:-}" in
	1 | true | TRUE | yes | YES | on | ON) return 0 ;;
	*) return 1 ;;
	esac
}

DRY_RUN=0
if is_truthy "${INSTALL_DRY_RUN:-}"; then
	DRY_RUN=1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	exit 0
fi

DOMAIN="${1:-${DOMAIN:-}}"
EMAIL="${2:-${EMAIL:-}}"
PASSWORD="${3:-${BROADCAST_PASSWORD:-}}"
# M30: prefer env BROADCAST_PASSWORD over argv (visible in ps).

if [[ "$DRY_RUN" -eq 1 ]]; then
	# Default dry-run hostname is example.test — never indep.stream.
	DOMAIN="${DOMAIN:-example.test}"
	EMAIL="${EMAIL:-admin@${DOMAIN}}"
fi

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
	usage
	exit 2
fi

if ! [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
	echo "invalid DOMAIN: $DOMAIN" >&2
	exit 2
fi

if ! [[ "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
	echo "invalid EMAIL: $EMAIL" >&2
	exit 2
fi

if [[ "$PASSWORD" == *$'\n'* ]]; then
	echo "BROADCAST_PASSWORD must be a single line" >&2
	exit 2
fi

PROXY="$(printf '%s' "${PROXY:-caddy}" | tr '[:upper:]' '[:lower:]')"
case "$PROXY" in
caddy | nginx) ;;
*)
	echo "PROXY must be caddy or nginx (got $PROXY)" >&2
	exit 2
	;;
esac

INSTALL_ROOT="${INSTALL_ROOT:-/opt/livecam}"
SERVICE_USER="${SERVICE_USER:-www-data}"

# HARD RULE: never live-install on the livestream Mac.
if [[ "$(uname -s)" == Darwin && "$DRY_RUN" -eq 0 ]]; then
	echo "live install is for Ubuntu/Debian droplets only. Use INSTALL_DRY_RUN=1 on this Mac." >&2
	exit 1
fi

# M29: realpath compare — refuse Mac tree and any path under it.
if [[ "$DRY_RUN" -eq 0 ]]; then
	_root_real="$(realpath "$INSTALL_ROOT" 2>/dev/null || echo "$INSTALL_ROOT")"
	_mac_real="$(realpath /opt/src/livecam 2>/dev/null || echo /opt/src/livecam)"
	if [[ "$_root_real" == "$_mac_real" || "$_root_real" == "$_mac_real"/* ]]; then
		echo "refusing to install over $_root_real (Mac livestream tree)" >&2
		exit 1
	fi
fi

random_alnum() {
	local n="${1:-32}"
	LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$n"
}

# Prefer an existing live .env over minting (H22).
load_existing_env "$INSTALL_ROOT/deploy/.env"


# Read KEY=value from a dotenv file (first match). Empty if missing.
env_get() {
	local f="$1" key="$2"
	[[ -f "$f" ]] || return 0
	awk -F= -v k="$key" '
		$0 ~ /^[[:space:]]*#/ { next }
		index($0, "=") == 0 { next }
		$1 == k {
			sub(/^[^=]*=/, "")
			print
			exit
		}
	' "$f"
}

# H22: reuse secrets from an existing live .env instead of minting new ones.
load_existing_env() {
	local f="$1"
	[[ -f "$f" ]] || return 0
	echo "H22: loading SESSION_SECRET / ALLOWED_STREAM_KEYS / BROADCAST_PASSWORD / SFU_INTERNAL_SECRET from $f"
	if [[ -z "$SESSION_SECRET" ]]; then
		SESSION_SECRET="$(env_get "$f" SESSION_SECRET)"
	fi
	if [[ -z "$ALLOWED_STREAM_KEYS" ]]; then
		ALLOWED_STREAM_KEYS="$(env_get "$f" ALLOWED_STREAM_KEYS)"
	fi
	if [[ -z "$PASSWORD" ]]; then
		PASSWORD="$(env_get "$f" BROADCAST_PASSWORD)"
	fi
	if [[ -z "$SFU_INTERNAL_SECRET" ]]; then
		SFU_INTERNAL_SECRET="$(env_get "$f" SFU_INTERNAL_SECRET)"
	fi
}

backup_existing_env() {
	local f="$1"
	[[ -f "$f" ]] || return 0
	local bak="${f}.bak.$(date +%Y%m%d%H%M%S)"
	cp -a "$f" "$bak"
	echo "H22: backed up existing .env to $bak"
}


if [[ "$DRY_RUN" -eq 1 ]]; then
	# Documentation IPv4 (TEST-NET-3). No outbound lookup.
	PUBLIC_IP="${PUBLIC_IP:-203.0.113.10}"
	SESSION_SECRET="${SESSION_SECRET:-dryrun-session-secret-min16}"
	ALLOWED_STREAM_KEYS="${ALLOWED_STREAM_KEYS:-dryrun00000000000000000000000001}"
	SFU_INTERNAL_SECRET="${SFU_INTERNAL_SECRET:-dryrun-sfu-internal-min16}"
	OUT_DIR="${INSTALL_OUT_DIR:-$SCRIPT_DIR/out/$DOMAIN}"
else
	PUBLIC_IP="${PUBLIC_IP:-}"
	SESSION_SECRET="${SESSION_SECRET:-}"
	ALLOWED_STREAM_KEYS="${ALLOWED_STREAM_KEYS:-}"
	SFU_INTERNAL_SECRET="${SFU_INTERNAL_SECRET:-}"
	OUT_DIR="$INSTALL_ROOT/deploy"
fi

render() {
	local src="$1"
	local dest="$2"
	local content
	content="$(cat "$src")"
	content="${content//__DOMAIN__/$DOMAIN}"
	content="${content//__EMAIL__/$EMAIL}"
	content="${content//__INSTALL_ROOT__/$INSTALL_ROOT}"
	content="${content//__PUBLIC_IP__/$PUBLIC_IP}"
	content="${content//__BROADCAST_PASSWORD__/$PASSWORD}"
	content="${content//__SESSION_SECRET__/$SESSION_SECRET}"
	content="${content//__ALLOWED_STREAM_KEYS__/$ALLOWED_STREAM_KEYS}"
	content="${content//__SFU_INTERNAL_SECRET__/$SFU_INTERNAL_SECRET}"
	content="${content//__SERVICE_USER__/$SERVICE_USER}"
	mkdir -p "$(dirname "$dest")"
	printf '%s\n' "$content" >"$dest"
}

write_rendered() {
	local dest_dir="$1"
	mkdir -p "$dest_dir"
	render "$TEMPLATE_DIR/Caddyfile" "$dest_dir/Caddyfile"
	render "$TEMPLATE_DIR/nginx.conf" "$dest_dir/nginx.conf"
	render "$TEMPLATE_DIR/nginx-http.conf" "$dest_dir/nginx-http.conf"
	render "$TEMPLATE_DIR/sfu.service" "$dest_dir/sfu.service"
	render "$TEMPLATE_DIR/go-proxy.service" "$dest_dir/go-proxy.service"
	# M30: write .env as 0640 via temp+mv (never 0644 then chmod).
	local env_tmp
	env_tmp="$(mktemp "$dest_dir/.env.XXXXXX")"
	chmod 640 "$env_tmp"
	render "$TEMPLATE_DIR/env" "$env_tmp"
	mv -f "$env_tmp" "$dest_dir/.env"
}

if [[ "$DRY_RUN" -eq 1 ]]; then
	write_rendered "$OUT_DIR"
	echo "dry-run: rendered $OUT_DIR"
	echo "  Caddyfile  nginx.conf  sfu.service  go-proxy.service  .env"
	echo "  proxy=$PROXY  domain=$DOMAIN  email=$EMAIL  public_ip=$PUBLIC_IP"
	echo "  (no root, no certbot, no network, indep.stream not required)"
	exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "live install requires root (or use INSTALL_DRY_RUN=1)" >&2
	exit 1
fi

if [[ -z "$PUBLIC_IP" ]]; then
	# M11: HTTPS only — cleartext checkip was MITMable into SFU_PUBLIC_IP/ICE.
	PUBLIC_IP="$(curl -fsS --max-time 8 https://checkip.amazonaws.com 2>/dev/null || true)"
	PUBLIC_IP="${PUBLIC_IP//$'\n'/}"
fi
if [[ -z "$PUBLIC_IP" ]]; then
	PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
if [[ -z "$PUBLIC_IP" ]]; then
	echo "could not detect PUBLIC_IP — set PUBLIC_IP=..." >&2
	exit 1
fi

if [[ -z "$SESSION_SECRET" ]]; then
	SESSION_SECRET="$(random_alnum 32)"
fi
if [[ -z "$ALLOWED_STREAM_KEYS" ]]; then
	ALLOWED_STREAM_KEYS="$(random_alnum 32)"
fi
if [[ -z "$SFU_INTERNAL_SECRET" ]]; then
	# M37: rust/Go Fatal if < 16.
	SFU_INTERNAL_SECRET="$(random_alnum 32)"
fi

install_caddy_pkg() {
	if command -v caddy >/dev/null 2>&1; then
		return 0
	fi
	export DEBIAN_FRONTEND=noninteractive
	if apt-get install -y caddy; then
		return 0
	fi
	apt-get install -y debian-keyring debian-archive-keyring \
		apt-transport-https ca-certificates curl gnupg
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' |
		gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' |
		tee /etc/apt/sources.list.d/caddy-stable.list
	chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg \
		/etc/apt/sources.list.d/caddy-stable.list
	apt-get update -y
	apt-get install -y caddy
}

if ! is_truthy "${INSTALL_SKIP_PACKAGES:-}"; then
	if command -v apt-get >/dev/null 2>&1; then
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -y
		pkgs=(build-essential gcc git curl ufw ca-certificates)
		if [[ "$PROXY" == nginx ]]; then
			pkgs+=(nginx certbot python3-certbot-nginx)
		fi
		apt-get install -y "${pkgs[@]}"
		if [[ "$PROXY" == caddy ]]; then
			install_caddy_pkg
		fi
	else
		echo "apt-get not found; install git curl ufw, a compiler, and $PROXY yourself" >&2
	fi
fi

# Low-RAM VPS: rustc + aws-lc-sys needs swap (configure.md Step 4).
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

if ! is_truthy "${INSTALL_SKIP_BUILD:-}"; then
	if [[ ! -x "$INSTALL_ROOT/rust-core/target/release/rust-core" ]]; then
		if command -v cargo >/dev/null 2>&1; then
			echo "building rust-core (release)"
			(cd "$INSTALL_ROOT/rust-core" && cargo build --release)
		else
			echo "warning: rust-core binary missing and cargo not on PATH" >&2
		fi
	fi
	if [[ ! -x "$INSTALL_ROOT/go-features/api/api-server" ]]; then
		if command -v go >/dev/null 2>&1; then
			echo "building go-proxy"
			(cd "$INSTALL_ROOT/go-features/api" && go build -o api-server)
		else
			echo "warning: api-server missing and go not on PATH" >&2
		fi
	fi
fi

mkdir -p "$INSTALL_ROOT/archive" "$INSTALL_ROOT/hls" \
	"$INSTALL_ROOT/data/offline_banners" "$INSTALL_ROOT/deploy"

backup_existing_env "$INSTALL_ROOT/deploy/.env"
write_rendered "$INSTALL_ROOT/deploy"
# Canonical names expected by systemd EnvironmentFile=
# (already written as .env). Keep copies of unit/nginx next to it.
chmod 640 "$INSTALL_ROOT/deploy/.env" || true
if id "$SERVICE_USER" >/dev/null 2>&1; then
	chown "root:$SERVICE_USER" "$INSTALL_ROOT/deploy/.env" || true
	chown -R "$SERVICE_USER:$SERVICE_USER" \
		"$INSTALL_ROOT/archive" "$INSTALL_ROOT/hls" "$INSTALL_ROOT/data" || true
fi

NGINX_AVAIL="/etc/nginx/sites-available/livecam"
NGINX_ENAB="/etc/nginx/sites-enabled/livecam"
CERT_FULL="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"

if [[ "$PROXY" == nginx ]]; then
	if [[ -d /etc/nginx/sites-available ]]; then
		if [[ ! -f "$CERT_FULL" ]]; then
			cp "$INSTALL_ROOT/deploy/nginx-http.conf" "$NGINX_AVAIL"
		else
			cp "$INSTALL_ROOT/deploy/nginx.conf" "$NGINX_AVAIL"
		fi
		ln -sfn "$NGINX_AVAIL" "$NGINX_ENAB"
		# Drop the distro default so it does not steal :80/:443.
		rm -f /etc/nginx/sites-enabled/default
		if command -v nginx >/dev/null 2>&1; then
			nginx -t
			if command -v systemctl >/dev/null 2>&1; then
				systemctl reload nginx || systemctl start nginx
			else
				nginx -s reload || true
			fi
		fi
	fi

	if ! is_truthy "${INSTALL_SKIP_CERTBOT:-}"; then
		if [[ ! -f "$CERT_FULL" ]]; then
			if command -v certbot >/dev/null 2>&1; then
				certbot --nginx -d "$DOMAIN" --email "$EMAIL" \
					--agree-tos --non-interactive --redirect || {
					echo "certbot failed — DNS A/AAAA for $DOMAIN must point here" >&2
					exit 1
				}
			else
				echo "warning: certbot not installed; TLS not obtained" >&2
			fi
		fi
		if [[ -f "$CERT_FULL" && -d /etc/nginx/sites-available ]]; then
			cp "$INSTALL_ROOT/deploy/nginx.conf" "$NGINX_AVAIL"
			nginx -t && systemctl reload nginx
		fi
	fi
else
	mkdir -p /etc/caddy
	cp "$INSTALL_ROOT/deploy/Caddyfile" /etc/caddy/Caddyfile
	if command -v caddy >/dev/null 2>&1; then
		caddy validate --config /etc/caddy/Caddyfile
	fi
	if command -v systemctl >/dev/null 2>&1; then
		if systemctl is-active --quiet nginx 2>/dev/null; then
			echo "stopping nginx so Caddy can bind 80/443"
			systemctl stop nginx || true
			systemctl disable nginx || true
		fi
		systemctl enable caddy
		systemctl restart caddy
	fi
fi

if command -v ufw >/dev/null 2>&1; then
	# M13: fail closed — ignored ufw left Go/rust on the WAN (with M1/H2).
	ufw allow 22/tcp || { echo "ufw allow 22 failed" >&2; exit 1; }
	ufw allow 80/tcp || { echo "ufw allow 80 failed" >&2; exit 1; }
	ufw allow 443/tcp || { echo "ufw allow 443 failed" >&2; exit 1; }
	ufw allow 50000/udp || { echo "ufw allow 50000/udp failed" >&2; exit 1; }
	ufw deny 8080/tcp || { echo "ufw deny 8080 failed" >&2; exit 1; }
	ufw deny 8443/tcp || { echo "ufw deny 8443 failed" >&2; exit 1; }
	ufw --force enable || { echo "ufw enable failed" >&2; exit 1; }
fi

if ! is_truthy "${INSTALL_SKIP_SYSTEMD:-}"; then
	cp "$INSTALL_ROOT/deploy/sfu.service" /etc/systemd/system/sfu.service
	cp "$INSTALL_ROOT/deploy/go-proxy.service" /etc/systemd/system/go-proxy.service
	systemctl daemon-reload
	systemctl enable sfu go-proxy
	systemctl restart sfu
	systemctl restart go-proxy
fi

echo "installed $DOMAIN"
echo "  proxy:   $PROXY"
echo "  health:  https://$DOMAIN/api/health"
echo "  go live: https://$DOMAIN/broadcast"
echo "  stream key: see $INSTALL_ROOT/deploy/.env (ALLOWED_STREAM_KEYS) — not printed"
echo "  env: $INSTALL_ROOT/deploy/.env"
