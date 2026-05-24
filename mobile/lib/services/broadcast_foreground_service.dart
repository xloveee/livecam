import 'package:flutter/services.dart';

/// Android foreground service bridge for live broadcasting.
class BroadcastForegroundService {
  static const MethodChannel _channel =
      MethodChannel('com.livecam.mobile/broadcast_service');

  static Future<void> start({required String title, required String body}) async {
    try {
      await _channel.invokeMethod('start', {'title': title, 'body': body});
    } on PlatformException catch (_) {
      /* non-Android or missing plugin */
    }
  }

  static Future<void> stop() async {
    try {
      await _channel.invokeMethod('stop');
    } on PlatformException catch (_) {}
  }
}
