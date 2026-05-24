#!/usr/bin/env bash
# Build release artifacts (run on dev machine after bootstrap + signing setup).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v flutter >/dev/null 2>&1; then
  echo "Flutter required. Run scripts/bootstrap.sh first."
  exit 1
fi

echo "==> Android App Bundle"
flutter build appbundle --release
echo "    $(ls -la build/app/outputs/bundle/release/app-release.aab 2>/dev/null || echo 'AAB not found')"

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> iOS IPA"
  flutter build ipa --release --export-options-plist=ios/exportOptions.plist
  echo "    build/ios/ipa/*.ipa"
else
  echo "SKIP iOS IPA (requires macOS)"
fi

echo "Done. Upload AAB to Play Console; IPA via Transporter or Xcode."
