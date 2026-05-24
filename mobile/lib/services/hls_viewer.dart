import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:video_player/video_player.dart';
import 'package:http/http.dart' as http;

import '../models/server_profile.dart';

class HlsViewer {
  HlsViewer({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  VideoPlayerController? _controller;

  VideoPlayerController? get controller => _controller;

  Future<bool> isManifestAvailable(ServerProfile server, String roomId) async {
    final url = Uri.parse('${server.normalizedBaseUrl}/hls/$roomId/master.m3u8');
    try {
      final response = await _client.head(url);
      return response.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  Future<VideoPlayerController> play(ServerProfile server, String roomId) async {
    await stop();
    final url = '${server.normalizedBaseUrl}/hls/$roomId/master.m3u8';
    _controller = VideoPlayerController.networkUrl(
      Uri.parse(url),
      httpHeaders: const {'Cache-Control': 'no-cache'},
    );
    await _controller!.initialize();
    await _controller!.setLooping(true);
    await _controller!.play();
    return _controller!;
  }

  Future<void> stop() async {
    if (_controller != null) {
      await _controller!.pause();
      await _controller!.dispose();
      _controller = null;
    }
  }

  void dispose() {
    _client.close();
  }
}

bool preferHlsOnPlatform() => Platform.isIOS;
