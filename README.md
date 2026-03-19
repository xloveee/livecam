# livecam

Self-hosted WebRTC live streaming & livecam platform. OBS WHIP broadcaster, browser-based broadcast, simulcast SFU, viewer caps, VOD recording, HLS fallback. Built with Rust (str0m), Go, C99. Run your own livecam or creator stream — no Twitch, no YouTube, no middlemen. AGPLv3.

## Questions this repository answers

**Content creators**

- How do I stream without depending on Twitch, YouTube, or other platforms?
- Can I own my stream, audience, and chat instead of a third party?
- Can I broadcast from my phone or browser without installing an app?
- Can I use OBS for high-quality desktop streaming and get low-latency viewing?
- How do I add real-time chat to my own stream with basic moderation?

**Streaming platform operators**

- How do I build a low-latency WebRTC live platform without Node.js?
- What is a minimal WHIP/WHEP SFU stack (Rust media plane, Go proxy)?
- How do I handle simulcast, quality switching, and VOD recording?
- Can I scale from a single node to Origin-Edge for many concurrent viewers?
- How do I add chat with C99-backed moderation and rate limiting?

## Architecture Highlights

1.  **Rust Core (Media Plane)**: An impenetrable fortress dedicated entirely to routing WebRTC media packets (SFU). It receives a single high-quality stream via WHIP (from OBS) and distributes it to viewers via WHEP. It handles Simulcast, dynamic quality switching, and recording VODs directly to disk.
2.  **Go + C99 Feature Layer (The Gatekeeper)**: A resilient proxy layer. Go handles the web networking (`net/http`) while strict, memory-safe C99 code handles the complex business logic (JWT validation, Chat Moderation, Rate Limiting).
3.  **Origin-Edge Scaling**: Designed to run as a single node for smaller broadcasts, or cascade from an Origin server to multiple Edge servers globally to handle millions of concurrent viewers.
4.  **No Node.js**: Zero dependency on heavy javascript backend ecosystems.

## Directory Structure

```text
livecam/
├── rust-core/           # Rust SFU, WHIP/WHEP API, and Archiving
│   ├── src/
│   │   ├── api.rs       # Internal WHIP/WHEP HTTP handlers
│   │   ├── config.rs    # Environment-based configuration
│   │   ├── sfu/         # Media routing event loop
│   │   └── main.rs
├── go-features/         # Go HTTP wrappers bridging to C99 logic
│   ├── api/             # Main proxy, config endpoint, static serving
│   │   └── c_src/       # Strict C99 implementation files (auth, rate limiting)
│   ├── chat/            # Real-time chat (WebSocket hub + moderation)
│   │   └── c_src/       # C99 chat logic (command parser, rate limiter)
│   └── vendor/          # Vendored Go dependencies (gorilla/websocket)
├── client/              # Static HTML/JS — WHEP Viewer + Browser Broadcast + Chat
└── deploy/              # Configs, scripts (Docker, Systemd, TURN)
```

## Prerequisites

- **Rust** (1.83+ stable) — `rustup update stable`
- **Go** (1.21+) — with CGo enabled (default)
- **OBS Studio** (30+) — with WHIP output support
- **Browser** — Chromium-based browsers only (Chrome, Edge, Brave, etc.). Firefox is not supported yet. Other browsers are TBD.

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
2. Enter the broadcast page password and your stream key, then click **Log In**.
3. Grant camera and microphone permissions.
4. Choose your camera, mic, and resolution from the dropdowns.
5. Click **Start Broadcast**.

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
| `SESSION_SECRET` | *(insecure default)* | Secret for broadcaster session tokens (16+ chars) |
| `BROADCAST_PASSWORD` | *(none — open mode)* | Page-level password required to access `/broadcast` |

### TLS + nginx (Required for production WebRTC)

Browsers require HTTPS for WebRTC. Place a reverse proxy in front of the Go service. The chat system uses WebSocket, which requires special proxy headers.

**nginx** (with Let's Encrypt):

```nginx
server {
    listen 443 ssl;
    server_name broadcast.yourdomain.com;
    ssl_certificate     /etc/letsencrypt/live/broadcast.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/broadcast.yourdomain.com/privkey.pem;

    # WebSocket — required for chat
    location /api/chat/ {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # Everything else (HTTP API, static files, WHIP/WHEP)
    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Caddy** (auto-TLS, handles WebSocket automatically):

```
broadcast.yourdomain.com {
    reverse_proxy localhost:8443
}
```

### STUN/TURN

- **STUN** is sufficient when your server has a public IP and clients are on typical home/office NATs.
- **TURN** (relay) is needed for clients behind symmetric NATs or restrictive firewalls. Self-host with [coturn](https://github.com/coturn/coturn) or use a managed service.

## Real-time Chat

The chat system runs over WebSocket alongside the video stream. It connects automatically when a viewer joins or a broadcaster logs in.

### Features

- Per-room chat rooms (room ID = stream key)
- Broadcaster and moderator roles with command support
- Rate limiting (slow mode) enforced in C99
- Message sanitization (control character stripping, length caps)
- Nickname validation (1–25 chars, alphanumeric + underscore)
- Auto-reconnect on connection drop

### Chat Commands (Broadcaster / Mod only)

| Command | Effect |
|---------|--------|
| `/ban username` | Permanent ban from room chat |
| `/unban username` | Remove ban |
| `/timeout username seconds` | Temporary mute (default 300s) |
| `/slow seconds` | Minimum seconds between messages (0 = off) |
| `/subscribers` | Toggle subscriber-only mode |
| `/clear` | Clear chat for all viewers |
| `/mod username` | Grant mod role to user |
| `/unmod username` | Revoke mod role |

### Chat Protocol

Clients connect via `wss://yourdomain.com/api/chat/{roomId}?nick=Name`. Messages are JSON:

```json
{"type": "msg", "text": "hello chat"}
{"type": "cmd", "text": "/slow 5"}
```

## URL Model

| Flow | URL |
|---|---|
| **Publish (OBS WHIP)** | `https://yourdomain.com/api/whip/{streamKey}` |
| **Publish (Browser)** | `https://yourdomain.com/broadcast` |
| **Broadcaster Auth** | `POST https://yourdomain.com/api/auth/broadcast` |
| **Watch (Browser WHEP)** | `https://yourdomain.com/watch/{roomId}` |
| **Quality Change** | `POST https://yourdomain.com/api/quality/{roomId}` |
| **ICE Config (Browser)** | `https://yourdomain.com/api/config` |
| **Chat (WebSocket)** | `wss://yourdomain.com/api/chat/{roomId}?nick=Name` |

## Branch Strategy

| Branch | Features |
|--------|----------|
| `main` | Stream only (WHIP/WHEP, browser broadcast, viewer page) |
| `feature/chat` | Stream + real-time chat |
| `feature/donations` | Stream + chat + donations *(planned)* |

Each tier builds on the previous. Merge upstream fixes from `main` into feature branches with `git merge main`.
