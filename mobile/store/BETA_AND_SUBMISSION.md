# Beta testing and store submission

## Prerequisites

- [ ] `mobile/scripts/bootstrap.sh` run on Mac (iOS) or Linux/Mac (Android)
- [ ] `./scripts/verify_server.sh` passes against production HTTPS
- [ ] [TESTING.md](TESTING.md) manual matrix completed on real devices
- [ ] Privacy policy live at https://indep.stream/privacy
- [ ] Release signing configured ([RELEASE_SIGNING.md](RELEASE_SIGNING.md))

## Phase 1 — Internal beta

### Android (Play Console, $25 one-time)

1. Create app → **Internal testing**
2. Upload `app-release.aab` from `flutter build appbundle --release`
3. Add tester Google accounts (up to 100)
4. Share opt-in link; collect feedback 1–2 weeks

### iOS (TestFlight, $99/year Apple Developer)

1. Create App ID `com.livecam.mobile` in Developer portal
2. Create app in App Store Connect
3. Upload build (`flutter build ipa` or Xcode Archive)
4. **Internal testing** → team members
5. **External testing** → requires Beta App Review (copy from APP_STORE_LISTING.md)

## Phase 2 — Production submission

### Google Play

1. Complete store listing ([PLAY_STORE_LISTING.md](PLAY_STORE_LISTING.md))
2. Data safety ([DATA_SAFETY_QUESTIONNAIRE.md](DATA_SAFETY_QUESTIONNAIRE.md))
3. Content rating (IARC)
4. Promote Internal → Closed → **Production** (or direct Production)
5. Review time: typically 1–7 days

### Apple App Store

1. Complete metadata ([APP_STORE_LISTING.md](APP_STORE_LISTING.md))
2. App Privacy ([APP_PRIVACY_QUESTIONNAIRE.md](APP_PRIVACY_QUESTIONNAIRE.md))
3. App Review Information: demo stream key + password
4. Submit for review
5. Review time: typically 24–48 hours (longer for first UGC app)

## Reviewer credentials template

```
Server URL: https://indep.stream
Stream key: [32-char alphanumeric]
Broadcast password: [if BROADCAST_PASSWORD is set]
Steps: Add server profile → Broadcast → Go Live → open https://indep.stream/watch/{key} in browser to verify.
Privacy: https://indep.stream/privacy
```

## Post-launch

- Bump `version: 1.0.1+2` in pubspec.yaml for each release
- Android: versionCode must increase every upload
- Monitor Play Console / App Store Connect crashes

## CI (optional later)

GitHub Actions can build Android AAB on push to `app` branch when `ANDROID_KEYSTORE_BASE64` secret is configured. iOS still requires Mac runners or local Xcode upload.
