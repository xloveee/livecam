# livecam Mobile

Flutter client for [livecam](../README.md): broadcast via WHIP, watch via WHEP/HLS, real-time chat.

## Quick start (dev machine)

```bash
git clone -b app git@github.com:xloveee/livecam.git
cd livecam/mobile
chmod +x scripts/*.sh
./scripts/bootstrap.sh
flutter run --release
```

## Server verification

```bash
./scripts/verify_server.sh https://indep.stream 'BROADCAST_PASSWORD' 'YOUR_32_CHAR_STREAM_KEY'
```

## Store publishing

| Doc | Purpose |
|-----|---------|
| [store/TESTING.md](store/TESTING.md) | Device test checklist |
| [store/RELEASE_SIGNING.md](store/RELEASE_SIGNING.md) | Android keystore + iOS signing |
| [store/BETA_AND_SUBMISSION.md](store/BETA_AND_SUBMISSION.md) | TestFlight + Play + production |
| [store/PLAY_STORE_LISTING.md](store/PLAY_STORE_LISTING.md) | Google Play copy |
| [store/APP_STORE_LISTING.md](store/APP_STORE_LISTING.md) | App Store copy |

Privacy policy (required for stores): **https://indep.stream/privacy**

## Feature flags

RTMP to Twitch/Kick is disabled in v1 (`lib/config/feature_flags.dart`) until native encoding is implemented.

## Prerequisites

- Flutter 3.16+ / Dart 3.2+
- Android Studio and/or Xcode (Mac for iOS)
- HTTPS livecam server with Bearer auth (app branch Go proxy)
