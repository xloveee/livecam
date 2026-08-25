# Deploy — self-hosted OBS replacement

Point any domain at a **fresh Ubuntu or Debian** droplet, run one command, go live from a browser, iOS, Android, or macOS. Donations: PayPal and Cash App. `indep.stream` is a **demo hostname only** — the installer never requires it.

## Pinned install (fresh Ubuntu / Debian)

After DNS A points at the droplet, clone a **pinned** commit (do not `curl | bash`):

```bash
export INSTALL_REF=5129a60e21aef3ba49408d598a90b9d8d101ee18
git clone https://github.com/xloveee/livecam.git /opt/livecam
cd /opt/livecam && git checkout "$INSTALL_REF"
sudo ./deploy/install.sh your.domain you@email.com optional-password
```

That uses the tree on disk (`deploy/install.sh`). Optional: `./deploy/bootstrap.sh` from the same checkout (refuses stdin). Set `GO_SHA256` if bootstrap must install Go. Opens **22/80/443 tcp** and **50000 udp**; starts systemd `sfu` + `go-proxy`.

**Caddy auto-TLS is the default** (`templates/Caddyfile` → `reverse_proxy 127.0.0.1:8443`, WebSocket included, request path kept). nginx + Let's Encrypt certbot instead:

```bash
cd /opt/livecam && sudo PROXY=nginx ./deploy/install.sh your.domain you@email.com optional-password
```

`PROXY=nginx` uses existing nginx when present, plus certbot. nginx `proxy_pass` is `http://127.0.0.1:8443` **without** a trailing slash so `/api/...` is not stripped.

Then:

1. Open `https://your.domain/broadcast`
2. Go live from the browser (camera **or** a looping video file — see [test/README.md](../test/README.md)), or from the Flutter app, or OBS WHIP: `https://your.domain/api/whip/`
3. Viewers: `https://your.domain/watch/{stream-key}`
4. Donations: enable PayPal and/or Cash App in Broadcast → Donate (no merchant API keys for v1). Invite short links: authenticated `POST /api/shorten` then public `GET /s/{code}` 302s to that room’s invite `/watch/{room}?invite=…` (not a watch bypass). Compatible (`master.m3u8`) and Preview (`pip.m3u8`) use the same invite + `max_viewers` gate as WHEP — `/hls/` is not a public bypass.

Already cloned on the VPS:

```bash
sudo ./deploy/install.sh your.domain you@email.com
sudo ./deploy/install.sh your.domain you@email.com 'your-broadcast-password'
PROXY=nginx sudo ./deploy/install.sh your.domain you@email.com
```

Step-by-step (packages, Rust, Go, swap) remains in [configure.md](../configure.md).

## Dry-run (no root, no network, no certbot)

Renders the same files under `deploy/out/<domain>/`. On the livestream Mac this is the **only** allowed proof — never live-install here.

```bash
INSTALL_DRY_RUN=1 ./deploy/bootstrap.sh example.test admin@example.test
INSTALL_DRY_RUN=1 ./deploy/install.sh example.test admin@example.test
# or, with no args, DOMAIN defaults to example.test:
INSTALL_DRY_RUN=1 ./deploy/install.sh
```

Check:

```bash
./test/install-dry-run.sh
```

Dry-run uses `PUBLIC_IP=203.0.113.10` (documentation range). It does not look up a public IP and does not mention `indep.stream`.

## Templates

| File | Becomes |
|------|---------|
| `templates/Caddyfile` | Caddy auto-TLS reverse proxy (`reverse_proxy 127.0.0.1:8443`) |
| `templates/nginx.conf` | TLS reverse proxy (`server_name` = your domain) |
| `templates/nginx-http.conf` | HTTP-only bootstrap for ACME |
| `templates/sfu.service` | systemd unit for the Rust SFU |
| `templates/go-proxy.service` | systemd unit for the Go feature layer |
| `templates/env` | `deploy/.env` (paths, `BROADCAST_PASSWORD`, stream key) |

Placeholders are `__DOMAIN__`, `__EMAIL__`, `__INSTALL_ROOT__`, `__PUBLIC_IP__`, `__BROADCAST_PASSWORD__`, `__SESSION_SECRET__`, `__ALLOWED_STREAM_KEYS__`, `__SERVICE_USER__`.

## Environment

| Variable | Meaning |
|----------|---------|
| `INSTALL_DRY_RUN=1` | Write `deploy/out/<domain>/` only |
| `PROXY` | `caddy` (default, auto-TLS) or `nginx` (certbot) |
| `INSTALL_ROOT` | Default `/opt/livecam` |
| `PUBLIC_IP` | Override advertised SFU IPv4 |
| `SERVICE_USER` | systemd `User=` (default `www-data`) |
| `INSTALL_SKIP_PACKAGES=1` | Do not `apt-get` |
| `INSTALL_SKIP_BUILD=1` | Do not compile rust-core / api-server |
| `INSTALL_SKIP_CERTBOT=1` | Do not run certbot (nginx path) |
| `INSTALL_SKIP_SYSTEMD=1` | Do not install or start units |

`deploy/.env.example` stays free of secrets. The live installer generates `SESSION_SECRET` and `ALLOWED_STREAM_KEYS`.
