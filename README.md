# Independent WebRTC Livestream Broadcasting Platform

A modular, timeless architecture for independent WebRTC livestream broadcasting. Designed to allow independent creators to broadcast directly from OBS Studio, a phone browser, or any WebRTC-capable device to millions of viewers without relying on third-party platforms like Twitch or YouTube.

## Architecture Highlights

1.  **Rust Core (Media Plane)**: An impenetrable fortress dedicated entirely to routing WebRTC media packets (SFU). It receives a single high-quality stream via WHIP (from OBS) and distributes it to viewers via WHEP. It handles Simulcast, dynamic quality switching, and recording VODs directly to disk.
2.  **Go + C99 Feature Layer (The Gatekeeper)**: A resilient proxy layer. Go handles the web networking (`net/http`) while strict, memory-safe C99 code handles the complex business logic (JWT validation, Chat Moderation, Rate Limiting).
3.  **Origin-Edge Scaling**: Designed to run as a single node for smaller broadcasts, or cascade from an Origin server to multiple Edge servers globally to handle millions of concurrent viewers.
4.  **No Node.js**: Zero dependency on heavy javascript backend ecosystems.

## Directory Structure

```text
INDEP_BROADCASTING/
├── rust-core/           # Rust SFU, WHIP/WHEP API, and Archiving
│   ├── src/
│   │   ├── api.rs       # Internal WHIP/WHEP HTTP handlers
│   │   ├── config.rs    # Environment-based configuration
│   │   ├── archive/     # VOD recording logic
│   │   ├── sfu/         # Media routing event loop
│   │   └── main.rs
├── go-features/         # Go HTTP wrappers bridging to C99 logic
│   ├── api/             # Main proxy, config endpoint, static serving
│   │   └── c_src/       # Strict C99 implementation files
│   ├── auth/            # Authentication and JWT validation
│   └── chat/            # Real-time chat and moderation engine
├── client/              # Static HTML/JS — WHEP Viewer + Browser Broadcast
└── deploy/              # Configs, scripts (Docker, Systemd, TURN)
```

## Prerequisites

- **Rust** (1.83+ stable) — `rustup update stable`
- **Go** (1.21+) — with CGo enabled (default)
- **OBS Studio** (30+) — with WHIP output support

## Getting Started (Local Development)

### 1. Build and start the Rust Core

```bash
cd rust-core
cargo build
cargo run
```

The Rust SFU will bind its HTTP API to `127.0.0.1:8080` and its UDP media socket to `127.0.0.1:50000` by default.

### 2. Build and start the Go Proxy

```bash
cd go-features/api
go build -o api-server
./api-server
```

The Go proxy listens on `:8443` by default.

### 3. Open a browser

Navigate to `http://localhost:8443/watch/my-room` to load the viewer page.

### 4. Broadcast

**Option A — OBS Studio (desktop, highest quality)**

1. Open **OBS Studio**.
2. Go to **Settings → Stream**.
3. Select **Custom WebRTC (WHIP)**.
4. Server URL: `http://localhost:8443/api/whip/`
5. Stream Key: a 32-character alphanumeric string (e.g., `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`)
6. Click **Start Streaming**.

**Option B — Browser (phone, tablet, laptop — no app needed)**

1. Navigate to `http://localhost:8443/broadcast`
2. Grant camera and microphone permissions.
3. Choose your camera, mic, and resolution from the dropdowns.
4. Enter your stream key and click **Start Broadcast**.

Both options use the same WHIP endpoint and produce the same stream format. The stream key doubles as the room ID. Viewers at `/watch/{stream-key}` will receive the broadcast.

## Production Deployment

### Environment Variables

**Rust Core** (`rust-core`):

| Variable | Default | Description |
|---|---|---|
| `SFU_HTTP_HOST` | `127.0.0.1` | Bind address for internal HTTP API |
| `SFU_HTTP_PORT` | `8080` | Internal HTTP port |
| `SFU_BIND_IP` | `0.0.0.0` | Local IP to bind the UDP media socket to |
| `SFU_PUBLIC_IP` | `127.0.0.1` | **Your server's public IP** — advertised in ICE candidates |
| `SFU_UDP_PORT` | `50000` | Public UDP port for WebRTC media |
| `SFU_ARCHIVE_DIR` | `archive` | Directory for VOD recordings |

**Go Proxy** (`go-features/api`):

| Variable | Default | Description |
|---|---|---|
| `GO_LISTEN_PORT` | `8443` | HTTP listen port |
| `STUN_URL` | `stun:stun.l.google.com:19302` | STUN server URL for browser ICE |
| `TURN_URL` | *(none)* | Optional TURN relay URL |
| `TURN_USERNAME` | *(none)* | TURN credential username |
| `TURN_CREDENTIAL` | *(none)* | TURN credential password |

### TLS (Required for production WebRTC)

Browsers require HTTPS for WebRTC. Place a reverse proxy (Caddy or nginx) in front of the Go service:

**Caddy** (auto-TLS):

```
broadcast.yourdomain.com {
    reverse_proxy localhost:8443
}
```

**nginx** (with Let's Encrypt):

```nginx
server {
    listen 443 ssl;
    server_name broadcast.yourdomain.com;
    ssl_certificate     /etc/letsencrypt/live/broadcast.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/broadcast.yourdomain.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8443;
    }
}
```

### Firewall

```bash
ufw allow 443/tcp       # HTTPS signaling
ufw allow 50000/udp     # WebRTC media
```

### STUN/TURN

- **STUN** is sufficient when your server has a public IP and clients are on typical home/office NATs.
- **TURN** (relay) is needed for clients behind symmetric NATs or restrictive firewalls. Self-host with [coturn](https://github.com/coturn/coturn) or use a managed service.

## URL Model

| Flow | URL |
|---|---|
| **Publish (OBS WHIP)** | `https://yourdomain.com/api/whip/{streamKey}` |
| **Publish (Browser)** | `https://yourdomain.com/broadcast` |
| **Watch (Browser WHEP)** | `https://yourdomain.com/watch/{roomId}` |
| **Quality Change** | `POST https://yourdomain.com/api/quality/{roomId}` |
| **ICE Config (Browser)** | `https://yourdomain.com/api/config` |
