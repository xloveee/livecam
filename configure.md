# Server Configuration Guide

Step-by-step guide for deploying the Independent Broadcasting platform on a fresh VPS (DigitalOcean, Hetzner, Vultr, AWS EC2, or any bare-metal server running Ubuntu/Debian).

## Prerequisites

- A VPS with a **public IPv4 address** (minimum 2 vCPU, 2GB RAM for small broadcasts)
- A **domain name** with DNS pointed at the server's IP
- **SSH access** as root or a sudo-capable user
- **OBS Studio 30+** on your local machine (with WHIP output support)

## Step 1: System Packages

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential gcc git curl ufw nginx certbot python3-certbot-nginx
```

## Step 2: Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup update stable
rustc --version   # must be 1.83+
```

## Step 3: Install Go

```bash
GO_VERSION="1.23.6"
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

## Step 4: Add Swap (Required on servers with less than 4GB RAM)

The Rust release build compiles `aws-lc-sys` (a heavy C/Rust cryptographic crate) and will be OOM-killed on low-RAM servers without swap:

```bash
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
```

## Step 5: Clone and Build

```bash
cd /opt
git clone https://github.com/xloveee/livecam.git
cd livecam

# Build Rust Core (takes 5-10 minutes on a 2 vCPU droplet)
cd rust-core
cargo build --release
cd ..

# Build Go Proxy (CGo — requires gcc, included in build-essential)
cd go-features/api
go build -o api-server
cd ../..
```

The release binary will be at `rust-core/target/release/rust-core`.

## Step 6: Determine Your Public IP

DigitalOcean and most VPS providers assign a public IP directly to the interface:

```bash
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)
echo "Your public IP: $PUBLIC_IP"
```

## Step 7: Firewall

```bash
sudo ufw allow 22/tcp        # SSH
sudo ufw allow 80/tcp        # Let's Encrypt HTTP challenge
sudo ufw allow 443/tcp       # HTTPS (nginx → Go proxy)
sudo ufw allow 50000/udp     # WebRTC media (direct to Rust SFU)
sudo ufw enable
sudo ufw status
```

## Step 8: TLS Certificate (Let's Encrypt)

Point your DNS A record for `indep.stream` to your server's public IP before running this. Certbot requires the domain to resolve to the server.

```bash
sudo certbot --nginx -d indep.stream
```

Follow the prompts. Certbot will obtain a certificate and auto-configure nginx.

## Step 9: Configure nginx

Edit `/etc/nginx/sites-available/default` (or the file certbot created):

```nginx
server {
    listen 443 ssl;
    server_name indep.stream;

    ssl_certificate     /etc/letsencrypt/live/indep.stream/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/indep.stream/privkey.pem;

    # Proxy all HTTP traffic to the Go feature layer
    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name indep.stream;
    return 301 https://$host$request_uri;
}
```

```bash
sudo nginx -t
sudo systemctl reload nginx
```

nginx only handles HTTPS signaling. WebRTC UDP media goes directly to the Rust SFU on port 50000, bypassing nginx entirely.

## Step 10: Create Environment File

You can start from the repository template:

```bash
sudo cp /opt/livecam/deploy/.env.example /opt/livecam/deploy/.env
sudo chown root:www-data /opt/livecam/deploy/.env
sudo chmod 640 /opt/livecam/deploy/.env
sudo nano /opt/livecam/deploy/.env
```

Or create the file from scratch:

```bash
cat > /opt/livecam/deploy/.env <<'EOF'
# Rust Core
SFU_PUBLIC_IP=YOUR_PUBLIC_IP_HERE
SFU_UDP_PORT=50000
SFU_HTTP_HOST=127.0.0.1
SFU_HTTP_PORT=8080
SFU_ARCHIVE_DIR=/opt/livecam/archive
HLS_DIR=/opt/livecam/hls

# Go Proxy
# Optional: small sponsor line in the web UI (see README — LIVECAM_SPONSOR_FOOTER_*).
# LIVECAM_SPONSOR_FOOTER_TEXT=Development sponsored by XLoveCam
# LIVECAM_SPONSOR_FOOTER_URL=https://xlovecam.com
GO_LISTEN_PORT=8443
CLIENT_DIR=/opt/livecam/client
RUST_CORE_URL=http://127.0.0.1:8080
STUN_URL=stun:stun.l.google.com:19302
# TURN_URL=turn:turn.indep.stream:3478
# TURN_USERNAME=your_turn_user
# TURN_CREDENTIAL=your_turn_password

# Broadcaster whitelist (comma-separated, 32-char alphanumeric keys).
# Only these keys will be accepted for WHIP publish.
# Leave empty or omit to accept any valid key (open mode).
ALLOWED_STREAM_KEYS=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
EOF
```

Replace `YOUR_PUBLIC_IP_HERE` with the output from Step 6.

Replace the `ALLOWED_STREAM_KEYS` value with your own key(s). Generate one with:

```bash
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32; echo
```

Multiple keys (up to 64) can be comma-separated for multiple broadcasters.

Lock down the file permissions — only root and the service user should read it:

```bash
sudo chown root:www-data /opt/livecam/deploy/.env
sudo chmod 640 /opt/livecam/deploy/.env
```

This ensures no other user on the server can read your stream keys or TURN credentials.

## Step 11: Create systemd Services

### Rust Core SFU

```bash
sudo cat > /etc/systemd/system/sfu.service <<'EOF'
[Unit]
Description=Rust Core SFU (WebRTC Media Plane)
After=network.target

[Service]
Type=simple
User=www-data
EnvironmentFile=/opt/livecam/deploy/.env
WorkingDirectory=/opt/livecam/rust-core
ExecStart=/opt/livecam/rust-core/target/release/rust-core
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
```

### Go Feature Layer

```bash
sudo cat > /etc/systemd/system/go-proxy.service <<'EOF'
[Unit]
Description=Go Feature Layer (WHIP/WHEP Proxy + Auth)
After=network.target sfu.service
Requires=sfu.service

[Service]
Type=simple
User=www-data
EnvironmentFile=/opt/livecam/deploy/.env
WorkingDirectory=/opt/livecam/go-features/api
ExecStart=/opt/livecam/go-features/api/api-server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and Start

```bash
# Set permissions
sudo mkdir -p /opt/livecam/archive /opt/livecam/hls
sudo chown -R www-data:www-data /opt/livecam/archive /opt/livecam/hls

# Load, enable, and start
sudo systemctl daemon-reload
sudo systemctl enable sfu go-proxy
sudo systemctl start sfu
sudo systemctl start go-proxy

# Verify
sudo systemctl status sfu
sudo systemctl status go-proxy
```

## Step 12: Verify the Deployment

```bash
# Health check — should return {"go":"ok","rust":"ok"}
curl -s https://indep.stream/api/health

# ICE config — should return STUN server URLs
curl -s https://indep.stream/api/config
```

If the health check shows `"rust":"unreachable"`, check that the Rust Core is running:

```bash
sudo journalctl -u sfu -f
```

## Step 13: Go Live from OBS

On your local machine:

1. Open **OBS Studio**
2. **Settings → Stream**
3. Service: **Custom WebRTC (WHIP)**
4. Server: `https://indep.stream/api/whip/`
5. Stream Key: any 32-character alphanumeric string (e.g., `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`)
6. Click **Start Streaming**

## Step 14: Go Live from a Phone or Browser

No app install needed. Works from any device with a camera (phone, tablet, laptop).

1. Open `https://indep.stream/broadcast` in any browser (Safari, Chrome, Firefox).
2. Grant camera and microphone permissions when prompted.
3. Select your preferred camera, microphone, and resolution from the dropdowns.
4. Enter a stream key (same 32-character alphanumeric format as OBS, e.g., `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`).
5. Optionally set a **Max Viewers** limit (leave at `0` for unlimited).
6. Optionally set a **Room Password** to restrict viewer access. Viewers will be prompted to enter it before they can watch. Leave blank for a public stream.
7. Click **Start Broadcast**.

The browser performs the same WHIP handshake as OBS — `createOffer()` → `POST /api/whip/{key}` → `setRemoteDescription(answer)`. The stream key doubles as the room ID. Viewers can watch at `/watch/{stream-key}`.

The room password and max viewers can both be changed mid-stream without interrupting the broadcast.

> **Note:** Browser broadcasts send a single quality layer (no Simulcast), so viewers won't see a quality dropdown. For multi-quality streams, use OBS with Simulcast enabled.

## Step 15: Watch the Stream

Open a browser and navigate to:

```
https://indep.stream/watch/a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

The room ID in the URL must match the stream key used by the broadcaster (OBS or browser).

---

## Monitoring and Logs

```bash
# Rust Core logs
sudo journalctl -u sfu -f

# Go Proxy logs
sudo journalctl -u go-proxy -f

# nginx access logs
sudo tail -f /var/log/nginx/access.log

# Check active connections
sudo ss -ulnp | grep 50000    # UDP media socket
sudo ss -tlnp | grep 8080     # Rust internal API
sudo ss -tlnp | grep 8443     # Go proxy
```

## VOD Archive

Recorded streams are saved to the `SFU_ARCHIVE_DIR` directory (default: `/opt/livecam/archive/`). Each broadcast produces a file named `{room_id}_{unix_timestamp}.raw` containing raw media samples.

## Optional: Self-Hosted TURN (coturn)

Only needed if viewers behind strict corporate firewalls or symmetric NATs cannot connect via STUN alone.

```bash
sudo apt install -y coturn

# /etc/turnserver.conf
sudo cat > /etc/turnserver.conf <<'EOF'
listening-port=3478
tls-listening-port=5349
realm=indep.stream
server-name=indep.stream
lt-cred-mech
user=broadcastuser:a_strong_password
cert=/etc/letsencrypt/live/indep.stream/fullchain.pem
pkey=/etc/letsencrypt/live/indep.stream/privkey.pem
no-tcp-relay
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
EOF

sudo systemctl enable coturn
sudo systemctl start coturn

# Open TURN ports
sudo ufw allow 3478/tcp
sudo ufw allow 3478/udp
sudo ufw allow 5349/tcp
sudo ufw allow 5349/udp
```

Then update the environment file:

```bash
TURN_URL=turn:indep.stream:3478
TURN_USERNAME=broadcastuser
TURN_CREDENTIAL=a_strong_password
```

Restart the Go proxy to pick up the new TURN config:

```bash
sudo systemctl restart go-proxy
```

## Resource Scaling and Compute Costs

### Understanding the bandwidth math

An SFU does **zero transcoding**. CPU usage is minimal — the server receives UDP packets from the broadcaster and copies them out to each viewer. The bottleneck is always **network bandwidth**, not CPU or RAM.

A typical OBS broadcast:

| Quality | Video bitrate | Audio | Total per viewer |
|---|---|---|---|
| 720p30 | 2.5 Mbps | 128 kbps | ~2.6 Mbps |
| 1080p30 | 4.5 Mbps | 128 kbps | ~4.6 Mbps |
| 1080p60 | 6.0 Mbps | 128 kbps | ~6.1 Mbps |

The server receives **one** inbound stream and sends **N copies** outbound (one per viewer). So:

```
Outbound bandwidth = (viewers) x (stream bitrate)
```

For a 1080p30 stream at 4.6 Mbps:
- 10 viewers   = 46 Mbps outbound
- 100 viewers  = 460 Mbps outbound
- 500 viewers  = 2.3 Gbps outbound
- 1,000 viewers = 4.6 Gbps outbound

### Per-viewer memory and CPU

Each viewer holds one `Rtc` instance in memory. Based on str0m's architecture:

| Resource | Per viewer | 100 viewers | 1,000 viewers |
|---|---|---|---|
| RAM | ~64 KB | ~6 MB | ~64 MB |
| CPU (packet copy) | negligible | ~5% of 1 core | ~30% of 1 core |

CPU only becomes relevant at extreme scale (5,000+ viewers on a single node) where the per-packet `memcpy` and the linear `accepts()` scan add up. RAM is never the bottleneck.

### DigitalOcean Droplet recommendations

Based on current DO pricing (January 2026) and the bandwidth math above. Transfer allowances are pooled per account.

#### Tier 1: Development / Small Audience (1-50 viewers)

| | Spec |
|---|---|
| **Droplet** | Basic, 2 vCPU / 2 GB RAM |
| **Cost** | **$18/mo** |
| **Transfer included** | 3,000 GiB/mo (3 TB) |
| **Max sustained outbound** | ~50 viewers at 1080p30 continuously |
| **Bandwidth budget** | 50 viewers x 4.6 Mbps = 230 Mbps |
| | 230 Mbps x 3600s = 103 GB/hour |
| | At 4 hours/day, 30 days = 12.4 TB/mo (exceeds allowance) |
| **Realistic use** | A few hours of streaming per week, or 720p to keep bitrate down |

This is your starting point. Good for testing, small private broadcasts, and development.

#### Tier 2: Regular Broadcasts (50-200 viewers)

| | Spec |
|---|---|
| **Droplet** | CPU-Optimized, 2 vCPU / 4 GB RAM |
| **Cost** | **$42/mo** |
| **Transfer included** | 4,000 GiB/mo (4 TB) |
| **NIC speed** | Up to 2 Gbps |
| **Max sustained outbound** | ~430 viewers at 1080p30 (limited by NIC) |
| **Realistic use** | Daily 2-hour streams with 100 viewers at 1080p = ~4 TB/mo (fits allowance) |

The CPU-Optimized line is explicitly recommended by DO for "media streaming." The dedicated vCPUs ensure the SFU event loop isn't preempted.

#### Tier 3: Serious Broadcasts (200-1,000 viewers)

| | Spec |
|---|---|
| **Droplet** | CPU-Optimized, 4 vCPU / 8 GB RAM |
| **Cost** | **$84/mo** |
| **Transfer included** | 5,000 GiB/mo (5 TB) |
| **NIC speed** | Up to 4 Gbps |
| **Max sustained outbound** | ~870 viewers at 1080p30 (NIC limit) |
| **Realistic use** | Daily 3-hour streams with 500 viewers = ~30 TB/mo |
| **Overage cost** | (30 TB - 5 TB) x $0.01/GiB x 1024 = ~$256/mo in bandwidth |
| **Total** | **~$340/mo** |

At this scale, bandwidth overage ($0.01/GiB) dominates the cost. The droplet itself is cheap.

#### Tier 4: Large Audience (1,000-5,000 viewers, single node)

| | Spec |
|---|---|
| **Droplet** | CPU-Optimized, 8 vCPU / 16 GB RAM |
| **Cost** | **$168/mo** |
| **Transfer included** | 6,000 GiB/mo (6 TB) |
| **NIC speed** | Up to 10 Gbps (Premium Intel) |
| **Max sustained outbound** | ~2,170 viewers at 1080p30 (NIC limit) |
| **Realistic use** | Daily 3-hour streams with 2,000 viewers = ~120 TB/mo |
| **Overage cost** | (120 TB - 6 TB) x $0.01/GiB x 1024 = ~$1,167/mo |
| **Total** | **~$1,335/mo** |

Beyond ~2,000 concurrent viewers on a single node, you hit the 10 Gbps NIC ceiling. At that point you need Origin-Edge scaling (multiple servers).

### Bandwidth is the real cost

Here's the cost breakdown for a daily 3-hour 1080p30 stream over a full month:

| Concurrent viewers | Outbound/month | DO overage cost | Droplet cost | Total/month |
|---|---|---|---|---|
| 50 | 3.1 TB | $0 (within allowance) | $18 | **$18** |
| 100 | 6.2 TB | ~$22 | $42 | **$64** |
| 500 | 31 TB | ~$266 | $84 | **$350** |
| 1,000 | 62 TB | ~$573 | $84 | **$657** |
| 2,000 | 124 TB | ~$1,208 | $168 | **$1,376** |
| 5,000 | 310 TB | ~$3,112 | $336 | **$3,448** |

Overage is calculated as: `(total_TB - included_TB) x 1024 x $0.01`.

### Cost optimization strategies

1. **Lower the bitrate.** 720p at 2.5 Mbps cuts bandwidth nearly in half versus 1080p at 4.6 Mbps. For many broadcasts, 720p is perfectly acceptable.

2. **Use Hetzner instead of DO.** Hetzner dedicated servers include 20 TB of outbound traffic and cost ~$40-80/mo. A Hetzner AX42 (8-core Ryzen, 64 GB RAM, 20 TB transfer) at ~$55/mo would handle 500 daily viewers for a fraction of the DO cost.

3. **Origin-Edge scaling.** Put the Origin server behind a CDN or deploy Edge SFU nodes in each region. Viewers connect to the nearest Edge. The Origin only sends one copy to each Edge, not one per viewer.

4. **Stream only when live.** The math above assumes daily streaming. If you broadcast 2-3 times per week instead of daily, bandwidth costs drop proportionally.

### Broadcaster machine requirements

The broadcaster (your local OBS machine) is doing the heavy lifting of encoding. Minimum specs:

| Component | 720p30 | 1080p30 | 1080p60 |
|---|---|---|---|
| CPU | 4-core i5 / Ryzen 5 | 6-core i5 / Ryzen 5 | 8-core i7 / Ryzen 7 |
| GPU (NVENC/QSV) | GTX 1650+ | RTX 2060+ | RTX 3060+ |
| RAM | 8 GB | 16 GB | 16 GB |
| Upload speed | 5 Mbps stable | 8 Mbps stable | 10 Mbps stable |

Hardware encoding (NVENC on NVIDIA, QSV on Intel) is strongly preferred over x264 software encoding — it offloads the CPU entirely and produces consistent frame pacing for WebRTC. OBS defaults to hardware encoding when available.

The upload speed requirement is the stream bitrate plus ~30% headroom for retransmits and RTCP feedback. A 4.6 Mbps 1080p stream needs at least 6 Mbps stable upload.

---

## Quick Reference

| Service | Bind Address | Protocol | Public? |
|---|---|---|---|
| nginx | `:443` | TCP (HTTPS) | Yes |
| Go Proxy | `:8443` | TCP (HTTP) | No (behind nginx) |
| Rust Core API | `:8080` | TCP (HTTP) | No (internal only) |
| Rust Core SFU | `:50000` | UDP (WebRTC) | **Yes** |
| coturn (optional) | `:3478` | TCP+UDP | Yes |

| URL | Purpose |
|---|---|
| `https://indep.stream/broadcast` | Browser broadcast page (phone/tablet/laptop) |
| `https://indep.stream/api/whip/{key}` | WHIP ingest (OBS + browser broadcast) |
| `https://indep.stream/watch/{room}` | Viewer page |
| `https://indep.stream/api/whep/{room}` | Viewer SDP negotiation |
| `https://indep.stream/api/room_password/{room}` | Set/clear room viewer password |
| `https://indep.stream/api/config` | Browser ICE server config |
| `https://indep.stream/api/health` | System health check |
