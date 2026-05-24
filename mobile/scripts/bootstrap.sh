#!/usr/bin/env bash
# Run on a dev machine (Mac or Linux) with Flutter installed — not on the VPS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v flutter >/dev/null 2>&1; then
  echo "Install Flutter 3.16+ first: https://docs.flutter.dev/get-started/install"
  exit 1
fi

echo "==> flutter doctor"
flutter doctor

echo "==> Generate missing platform scaffolding (keeps lib/ and pubspec.yaml)"
flutter create . --org com.livecam --project-name livecam_mobile --platforms=android,ios

echo "==> Restore custom native files from git (if any were overwritten)"
if git rev-parse --git-dir >/dev/null 2>&1; then
  git checkout -- \
    android/app/src/main/AndroidManifest.xml \
    android/app/src/main/kotlin/com/livecam/mobile/ \
    android/app/src/main/res/values/styles.xml \
    ios/Runner/Info.plist \
    ios/Runner/AppDelegate.h \
    ios/Runner/AppDelegate.m \
    ios/Runner/BroadcastServicePlugin.m \
    2>/dev/null || true
fi

echo "==> Dependencies"
flutter pub get

echo "==> Analyze"
flutter analyze

echo "==> iOS pods (Mac only)"
if [[ "$(uname -s)" == "Darwin" ]]; then
  (cd ios && pod install --repo-update)
fi

echo ""
echo "Done. Connect a device and run:"
echo "  flutter run --release"
echo ""
echo "Release builds:"
echo "  flutter build appbundle --release   # Android Play Store"
echo "  flutter build ipa --release         # iOS TestFlight (Mac + Xcode)"
