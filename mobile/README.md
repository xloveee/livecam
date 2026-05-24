# livecam Mobile

Flutter client for [livecam](../README.md): broadcast via WHIP, watch via WHEP/HLS, real-time chat, and optional RTMP restream to Twitch/Kick.

## Prerequisites

- Flutter 3.16+ with Dart 3.2+
- Android Studio / Xcode for device builds
- HTTPS livecam server (production WebRTC requires TLS)

## Setup

```bash
cd mobile
flutter pub get
```

## Run

```bash
flutter run
```

## Features

- Save server profiles (any livecam instance, e.g. indep.stream)
- WHIP broadcast with VP8 codec preference (iPhone viewer compatibility)
- WHEP viewer with HLS fallback
- WebSocket chat (same protocol as web client)
- RTMP/RTMPS destinations for Twitch, Kick, custom ingest
- Bearer token auth (mobile-friendly; see Go API changes)

## Platform notes

- **Android**: foreground service keeps the broadcast alive; grant camera/mic permissions.
- **iOS**: background audio mode for streaming continuity; test on real devices for codec paths.
- **TURN**: server must expose TURN via `GET /api/config` for restrictive NATs.
