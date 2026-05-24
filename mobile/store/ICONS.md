# App icons and screenshots

## Icons (required before store submit)

Generate with [flutter_launcher_icons](https://pub.dev/packages/flutter_launcher_icons) after bootstrap:

1. Add a 1024×1024 PNG at `store/icon_source.png`
2. Add to `pubspec.yaml` dev_dependencies and config (see package docs)
3. Run `dart run flutter_launcher_icons`

Minimum sizes:
- **iOS**: 1024×1024 App Store icon
- **Android**: adaptive icon foreground + background (432×432)

Until icons exist, `flutter create` supplies default Flutter launcher icons.

## Screenshots

Capture from release build on real devices:

| Store | Sizes |
|-------|-------|
| Google Play | Phone 1080×1920 min; 7" tablet optional |
| App Store | 6.7" (1290×2796) and 5.5" (1242×2208) iPhone |

Suggested scenes:
1. Home — server list
2. Broadcast — camera preview + Go Live
3. Watch — stream + chat split
4. Server profile edit

Save under `store/screenshots/` (gitignored) for your upload workflow.
