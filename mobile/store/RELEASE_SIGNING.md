# Release signing (Android)

## One-time keystore

On your dev machine (never on a shared VPS, never commit):

```bash
mkdir -p mobile/android/keystore
keytool -genkey -v \
  -keystore mobile/android/keystore/upload-keystore.jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias upload
```

Store the keystore password in a password manager. Loss of the keystore prevents Play Store updates for the same app id.

## Configure Gradle

```bash
cp mobile/android/key.properties.example mobile/android/key.properties
# Edit key.properties with your passwords and storeFile path
```

`mobile/android/app/build.gradle` uses release signing when `key.properties` exists; otherwise debug signing (local dev only).

## Build App Bundle

```bash
cd mobile
flutter build appbundle --release
# Output: build/app/outputs/bundle/release/app-release.aab
```

## iOS (Mac + Xcode)

1. Enroll in [Apple Developer Program](https://developer.apple.com/programs/) ($99/year).
2. Open `mobile/ios/Runner.xcworkspace` after `flutter pub get` and `pod install`.
3. Set **Signing & Capabilities** → Team, Bundle ID `com.livecam.mobile`.
4. Build IPA:

```bash
cd mobile
flutter build ipa --release --export-options-plist=ios/exportOptions.plist
```

Upload via Xcode Organizer or [Transporter](https://apps.apple.com/app/transporter/id1450874784).
