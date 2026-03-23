# livecam

Self-hosted WebRTC live streaming & livecam platform. OBS WHIP broadcaster, browser-based broadcast, simulcast SFU, viewer caps, VOD recording, HLS fallback. Built with Rust (str0m), Go, C99. Run your own livecam or creator stream — no Twitch, no YouTube, no middlemen. AGPLv3.


## Questions this repository answers

- How do I stream without depending on Twitch, YouTube, or other platforms?
- Can I own my stream, audience, and chat instead of a third party?
- Can I broadcast from my phone or browser without installing an app?
- Can I use OBS for high-quality desktop streaming and get low-latency viewing?
- How do I add real-time chat to my own stream with basic moderation?

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
- **Browser** — Any modern browser with WebRTC (see **Browser and device support** below).

### Browser and device support

The SFU negotiates **H.264** and **VP8** for video (plus **Opus** for audio). **Everyone in a room receives the same video codec the live publisher is sending** — viewers must be able to decode that codec. See **[Video codec policy](#video-codec-policy)** for how publisher vs viewer preferences are set and how to extend codecs later.

| Client | Typical experience |
|--------|-------------------|
| **Chrome / Edge / Brave / Opera** (desktop & Android) | Primary targets; full WHIP/WHEP. |
| **Firefox** (desktop & Android) | Supported; VP8 path is reliable if H.264 hardware decode is unavailable. |
| **Safari** (macOS, iPadOS) | Supported; use **H.264 Baseline / Constrained Baseline** from OBS when using OBS. |
| **Safari / WebKit** (iPhone) | Supported; **encoder profile** matters for **H.264** — see [iPhone / WebKit](#iphone--webkit-rtp-arrives-but-no-picture-framesdecoded0-video-0×0). |

**TLS:** Production viewing and camera/mic access require **HTTPS** (see **TLS + nginx**). **iOS** often blocks mixed content and requires a **secure context** for `getUserMedia`.

### Video codec policy

WebRTC end-to-end rules recorded here so **desktop → mobile** and **mobile → mobile** stay compatible, and so new codecs can be added in a predictable way.

#### What was wrong and what we changed (browser `/broadcast`)

- **Symptom:** **Desktop → iPhone** failed (RTP arrived, **`framesDecoded=0`**, video **0×0**) while **phone → phone** and **phone → desktop** worked.
- **Cause:** Desktop browsers often negotiated **H.264** **Main/High** for `getUserMedia` → WHIP. **iPhone Safari** frequently will not decode that profile in WebRTC, while **VP8** decodes reliably.
- **Fix (saved in `client/js/broadcast-core.js`, loaded by `broadcast.html`):** After adding transceivers/tracks, call `RTCRtpSender.getCapabilities('video')` and **`setCodecPreferences`** with **VP8-only** when **VP8** is listed: **`video/VP8` codecs first, then all other codecs except `video/H264` and `video/VP8`** (keeps **RTX** / FEC-related entries aligned). **H.264 is omitted** from the preference list so the offer does not steer the encoder toward Main/High. **If VP8 is not advertised**, fall back to **H.264** entries sorted by **`profile-level-id`**: **Baseline (0x42)** before **Main (0x4D)** before **High (0x64)** (`sortH264ForCompat` / `h264ProfileRank`).
- **OBS / hardware WHIP** does not use the broadcast page; iPhone viewers still need a **decodable H.264 profile** from OBS (see [iPhone / WebKit](#iphone--webkit-rtp-arrives-but-no-picture-framesdecoded0-video-0×0)).

#### Policy table (current)

| Role | File | Preference order | Purpose |
|------|------|-------------------|---------|
| **Publisher (browser)** | `client/js/broadcast-core.js` | **VP8 + rest (no H.264 in list)** if VP8 exists; else **H.264 sorted** + rest | Maximize **phone viewer** compatibility for browser-origin streams. |
| **Publisher (OBS)** | *(not applicable)* | Encoder settings in OBS | Typically **H.264**; profile must be mobile-safe for iPhone. |
| **Viewer** | `client/js/watch-core.js` | **H.264**, then **VP8**, then remainder | Match **OBS**-heavy rooms; still accept VP8 publishers. |
| **SFU (WHIP/WHEP)** | `rust-core/src/api.rs` | `RtcConfig`: **H.264** + **VP8** + **Opus** enabled | Single media plane; **no transcoding** — forward RTP for the negotiated codec. |

#### Adding support for more codecs later

1. **Rust / str0m:** In `rust-core/src/api.rs`, on both WHIP and WHEP `RtcConfig` builders, call the matching **`enable_<codec>(true)`** (and keep **`clear_codecs()`** ordering consistent with project conventions). str0m’s `RtcConfig` API is the gate — only enabled codecs participate in SDP.
2. **Publisher (`broadcast-core.js`):** Extend the `getCapabilities('video')` filters: add e.g. `video/VP9` or `video/AV1` to the ordered list with a **clear policy** (e.g. prefer a chain **AV1 → VP9 → VP8 → H.264** once all are enabled and tested).
3. **Viewers (`watch-core.js`):** Mirror the same **mimeType** ordering for **`RTCRtpReceiver`** so WHEP offers list codecs the SFU can match to the publisher.
4. **End-to-end:** The SFU **forwards** RTP; publisher and every subscriber must still **negotiate the same** video codec. **Simulcast / RID** behavior in `rust-core/src/sfu/` may need review if a new codec changes layering.
5. **Safari / mobile:** Re-test **iPhone** after any change — hardware decode paths differ per codec.

### Profiling note (H.264)

When **H.264** must be used (OBS or VP8-unavailable browsers), **profile-level-id** in SDP `fmtp` matters for **WebKit**. The broadcast page’s **H.264** branch sorts by **RFC 6184** profile byte (**42** = Baseline family, **4D** = Main, **64** = High). **OBS** users should still set **Baseline / Constrained Baseline** and a **mobile-friendly level** (e.g. **3.0–3.1**) where the encoder allows it.

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

**Playback:** The viewer uses the browser’s native `<video>` controls (no JS autoplay). Tap or click **play** to start. On **iPhone / iPad**, when an HLS manifest is available, the page uses **native HLS** for watching (reliable in Safari and in-app browsers); low-latency **WebRTC (WHEP)** is still used where it works best. Broadcasting always uses **WHIP** regardless.

Drag the **resize bar** between stream and chat to change the split (vertical bar on wide screens, horizontal bar when stacked on phone). **Left / up** gives more space to chat; **right / down** gives less. Sizes are stored in `localStorage` (`livecamWatchChatWidthPx`, `livecamWatchChatHeightPx`). Double-click the bar to reset to roughly half for the current layout.

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

Both options use the same WHIP endpoint. **Video codec** follows whatever the publisher negotiates (browser `/broadcast` is usually **VP8** when the browser supports it; **OBS** is usually **H.264**). The stream key doubles as the room ID. Viewers at `/watch/{stream-key}` will receive the broadcast.

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
| `HLS_DIR` | `hls` | Directory for live HLS segments (relative to working dir or absolute) |

**Go Proxy** (`go-features/api`):

| Variable | Default | Description |
|---|---|---|
| `GO_LISTEN_PORT` | `8443` | HTTP listen port |
| `STUN_URL` | `stun:stun.l.google.com:19302` | STUN server URL for browser ICE |
| `TURN_URL` | *(none)* | Optional TURN relay URL(s); comma-separated for UDP+TCP (e.g. `turn:host:3478?transport=udp,turn:host:3478?transport=tcp`) |
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

### iPhone / WebKit: RTP arrives but no picture (`framesDecoded=0`, video `0×0`)

If diagnostics show **`ice=connected`**, **`inbound-rtp` `bytesReceived` increasing**, **`track` `live`**, but **`framesDecoded=0`** and the `<video>` stays **`0×0` / `readyState=0`**, packets are reaching the phone but the **decoder is not outputting frames**. This is **not** explained by missing TURN alone. The watch page shows a **“Picture stuck?”** banner after a few seconds when it detects this pattern.

**Typical cause:** **H.264** in a **profile/level** that **desktop Chrome** decodes but **iOS Safari WebRTC** does not (often **Main/High** vs **Baseline** on device decoders). This shows up most often with **OBS** WHIP defaults, or with **browser `/broadcast`** only when the browser **does not** offer **VP8** and falls back to **H.264** (see **[Video codec policy](#video-codec-policy)**).

**What to change (OBS):** In the **encoder** (advanced / x264 or hardware encoder options), force **H.264 Baseline** or **Constrained Baseline** and a **mobile-friendly level** (e.g. **3.0–3.1**). Restart the stream after changing.

**OBS (WHIP) in practice:** See the official [WHIP streaming guide](https://obsproject.com/kb/whip-streaming-guide). For **x264**, prefer **Profile: Baseline**, **Tune: zerolatency**, **Keyframe interval: 1 s**, and in **x264 Options** add **`bframes=0`**. For **NVENC / QSV / Apple VT**, open the encoder’s **advanced** settings and set the **H.264 profile** to **baseline** or **constrained baseline** if the UI offers it.

**Cross-check:** Publish with **`/broadcast`** from a desktop or phone (VP8-only when available) and watch from the iPhone — if the picture appears, the pipeline is fine and the remaining issue is **H.264 profile** from **OBS** (or a browser that had to fall back to **H.264** only). See **[Video codec policy](#video-codec-policy)**.

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

## Branch Strategy

| Branch | Features |
|--------|----------|
| `main` | Stream only (WHIP/WHEP, browser broadcast, viewer page) |
| `feature/chat` | Stream + real-time chat |
| `feature/donations` | Stream + chat + donations (Stripe, PayPal, crypto, bank) |

Development sponsored by xlovecam.com, ad hominem is not welcome. 