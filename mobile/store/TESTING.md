# Device testing checklist

Run server checks first:

```bash
./scripts/verify_server.sh https://indep.stream 'BROADCAST_PASSWORD' 'YOUR_32_CHAR_STREAM_KEY'
```

## Automated (dev machine)

```bash
cd mobile
flutter analyze
flutter test
flutter run --release -d <device_id>
```

## Manual matrix

| # | Test | Steps | Pass |
|---|------|-------|------|
| 1 | Server profile | Add indep.stream URL, key, password | Saves/reloads |
| 2 | Auth + WHIP | Broadcast → Go Live | No 401; live badge |
| 3 | Web viewer | Open `/watch/{key}` on desktop | Video + chat |
| 4 | VP8 → iPhone | Android publishes, iPhone watches | Picture decodes |
| 5 | WHEP watch | Android watch same room | Low latency |
| 6 | HLS fallback | iOS watch (or force offline WHEP) | HLS plays |
| 7 | Chat | Send message from app | Appears on web |
| 8 | Chat reconnect | Toggle airplane mode briefly | Reconnects |
| 9 | Stop | Stop broadcast | Room offline |
| 10 | Background Android | Go live, home button | Notification visible |
| 11 | Cellular | Repeat broadcast on LTE | Connects (TURN if needed) |
| 12 | Release build | `flutter run --release` | Same as debug |

Log failures with device model, OS version, and `about:webrtc` / server logs.

## App Review demo credentials

Provide reviewers in store notes:

- Server URL: `https://indep.stream`
- Stream key: *(32-char test key)*
- Broadcast password: *(if set)*
- Privacy policy: `https://indep.stream/privacy`
