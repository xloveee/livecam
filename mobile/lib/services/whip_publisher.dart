import 'dart:async';

import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:http/http.dart' as http;

import '../models/server_profile.dart';
import 'ice_config_service.dart';

enum WhipState { idle, connecting, live, error, disconnected }

class WhipStats {
  WhipStats({
    this.bitrateKbps = 0,
    this.packetsSent = 0,
    this.viewerCount = 0,
  });

  final double bitrateKbps;
  final int packetsSent;
  final int viewerCount;
}

class WhipPublisher {
  WhipPublisher({
    IceConfigService? iceConfig,
    http.Client? client,
  })  : _iceConfig = iceConfig ?? IceConfigService(),
        _client = client ?? http.Client();

  final IceConfigService _iceConfig;
  final http.Client _client;

  RTCPeerConnection? _pc;
  MediaStream? _localStream;
  Timer? _disconnectTimer;
  Timer? _statsTimer;
  WhipState _state = WhipState.idle;
  int _prevVideoBytes = 0;
  int _prevTimestamp = 0;

  final StreamController<WhipState> _stateCtrl =
      StreamController<WhipState>.broadcast();
  final StreamController<WhipStats> _statsCtrl =
      StreamController<WhipStats>.broadcast();

  Stream<WhipState> get stateStream => _stateCtrl.stream;
  Stream<WhipStats> get statsStream => _statsCtrl.stream;
  WhipState get state => _state;
  MediaStream? get localStream => _localStream;
  RTCVideoRenderer? previewRenderer;

  void _setState(WhipState s) {
    _state = s;
    _stateCtrl.add(s);
  }

  Future<MediaStream> openCamera({
    bool frontCamera = true,
    int width = 1280,
    int height = 720,
    int fps = 30,
  }) async {
    await closeCamera();
    final stream = await navigator.mediaDevices.getUserMedia({
      'audio': true,
      'video': {
        'facingMode': frontCamera ? 'user' : 'environment',
        'width': width,
        'height': height,
        'frameRate': fps,
      },
    });
    _localStream = stream;
    if (previewRenderer != null) {
      previewRenderer!.srcObject = stream;
    }
    return stream;
  }

  Future<void> closeCamera() async {
    if (_localStream != null) {
      for (final track in _localStream!.getTracks()) {
        await track.stop();
      }
      await _localStream!.dispose();
      _localStream = null;
    }
    if (previewRenderer != null) {
      previewRenderer!.srcObject = null;
    }
  }

  Future<void> switchCamera() async {
    if (_localStream == null) return;
    final videoTrack = _localStream!.getVideoTracks().firstOrNull;
    if (videoTrack == null) return;
    await Helper.switchCamera(videoTrack);
  }

  Future<void> start({
    required ServerProfile server,
    required String authToken,
    bool simulcast = true,
  }) async {
    if (_localStream == null) {
      throw StateError('Camera not opened');
    }
  _setState(WhipState.connecting);
    _clearDisconnectTimer();

    final iceServers = await _iceConfig.iceServersForProfile(server);
    _pc = await createPeerConnection({
      'iceServers': iceServers.map((s) => s.toMap()).toList(),
      'sdpSemantics': 'unified-plan',
      'bundlePolicy': 'max-bundle',
      'rtcpMuxPolicy': 'require',
    });

    _pc!.onIceConnectionState = (state) => _onIceState(state);
    _pc!.onConnectionState = (state) => _onConnectionState(state);

    for (final track in _localStream!.getTracks()) {
      if (track.kind == 'video' && simulcast) {
        await _pc!.addTransceiver(
          track: track,
          kind: RTCRtpMediaType.RTCRtpMediaTypeVideo,
          init: RTCRtpTransceiverInit(
            direction: TransceiverDirection.SendOnly,
            sendEncodings: [
              RTCRtpEncoding(rid: 'h', maxBitrate: 2500000),
              RTCRtpEncoding(rid: 'm', maxBitrate: 1000000, scaleResolutionDownBy: 2),
              RTCRtpEncoding(rid: 'l', maxBitrate: 400000, scaleResolutionDownBy: 4),
            ],
          ),
        );
      } else {
        await _pc!.addTrack(track, _localStream!);
      }
    }

    await _applyVp8CodecPreferences(_pc!);

    final offer = await _pc!.createOffer();
    await _pc!.setLocalDescription(offer);

    final url = Uri.parse(
      '${server.normalizedBaseUrl}/api/whip/${server.streamKey}',
    );
    final response = await _client.post(
      url,
      headers: {
        'Content-Type': 'application/sdp',
        'Authorization': 'Bearer $authToken',
      },
      body: offer.sdp,
    );

    if (response.statusCode != 200 && response.statusCode != 201) {
      _setState(WhipState.error);
      throw Exception('WHIP failed (${response.statusCode}): ${response.body}');
    }

    final answer = RTCSessionDescription(response.body, 'answer');
    await _pc!.setRemoteDescription(answer);
    _setState(WhipState.live);
    _startStatsLoop();
  }

  Future<void> _applyVp8CodecPreferences(RTCPeerConnection pc) async {
    try {
      final caps = await getRtpSenderCapabilities('video');
      if (caps == null) return;

      final vp8 = caps.codecs
          .where((c) => c.mimeType?.toLowerCase() == 'video/vp8')
          .toList();
      final h264 = _sortH264ForCompat(caps.codecs
          .where((c) => c.mimeType?.toLowerCase() == 'video/h264')
          .toList());
      final rest = caps.codecs.where((c) {
        final m = c.mimeType?.toLowerCase() ?? '';
        return m != 'video/vp8' && m != 'video/h264';
      }).toList();

      final transceivers = await pc.getTransceivers();
      for (final tr in transceivers) {
        if (tr.sender.track?.kind == 'video') {
          if (vp8.isNotEmpty) {
            await tr.setCodecPreferences(vp8 + rest);
          } else if (h264.isNotEmpty) {
            await tr.setCodecPreferences(h264 + rest);
          }
          break;
        }
      }
    } catch (_) {
      /* codec prefs optional */
    }
  }

  List<RTCRtpCodecCapability> _sortH264ForCompat(
      List<RTCRtpCodecCapability> codecs) {
    int rank(RTCRtpCodecCapability c) {
      final line = c.sdpFmtpLine ?? '';
      final match = RegExp(r'profile-level-id=([0-9a-fA-F]{6})').firstMatch(line);
      if (match == null) return 50;
      final profile = int.parse(match.group(1)!.substring(0, 2), radix: 16);
      if (profile == 0x42) return 0;
      if (profile == 0x4d) return 1;
      if (profile == 0x64) return 2;
      return 25;
    }

    final sorted = List<RTCRtpCodecCapability>.from(codecs);
    sorted.sort((a, b) => rank(a).compareTo(rank(b)));
    return sorted;
  }

  void _onIceState(RTCIceConnectionState state) {
    switch (state) {
      case RTCIceConnectionState.RTCIceConnectionStateConnected:
      case RTCIceConnectionState.RTCIceConnectionStateCompleted:
        _clearDisconnectTimer();
        if (_state == WhipState.connecting) {
          _setState(WhipState.live);
        }
        break;
      case RTCIceConnectionState.RTCIceConnectionStateDisconnected:
        _scheduleDisconnectGrace();
        break;
      case RTCIceConnectionState.RTCIceConnectionStateFailed:
      case RTCIceConnectionState.RTCIceConnectionStateClosed:
        stop();
        _setState(WhipState.disconnected);
        break;
      default:
        break;
    }
  }

  void _onConnectionState(RTCPeerConnectionState state) {
    if (state == RTCPeerConnectionState.RTCPeerConnectionStateFailed ||
        state == RTCPeerConnectionState.RTCPeerConnectionStateClosed) {
      stop();
      _setState(WhipState.disconnected);
    }
  }

  void _scheduleDisconnectGrace() {
    _clearDisconnectTimer();
    _disconnectTimer = Timer(const Duration(seconds: 5), () {
      stop();
      _setState(WhipState.disconnected);
    });
  }

  void _clearDisconnectTimer() {
    _disconnectTimer?.cancel();
    _disconnectTimer = null;
  }

  void _startStatsLoop() {
    _statsTimer?.cancel();
    _statsTimer = Timer.periodic(const Duration(seconds: 2), (_) async {
      if (_pc == null) return;
      try {
        final stats = await _pc!.getStats();
        var bytes = 0;
        var packets = 0;
        var ts = DateTime.now().millisecondsSinceEpoch;
        stats.forEach((_, report) {
          if (report.type == 'outbound-rtp' &&
              (report.values['kind'] == 'video' ||
                  report.values['mediaType'] == 'video')) {
            bytes = (report.values['bytesSent'] as num?)?.toInt() ?? 0;
            packets = (report.values['packetsSent'] as num?)?.toInt() ?? 0;
          }
        });
        var kbps = 0.0;
        if (_prevTimestamp > 0 && ts > _prevTimestamp && bytes >= _prevVideoBytes) {
          kbps = ((bytes - _prevVideoBytes) * 8) /
              (ts - _prevTimestamp) /
              1000.0;
        }
        _prevVideoBytes = bytes;
        _prevTimestamp = ts;
        _statsCtrl.add(WhipStats(bitrateKbps: kbps, packetsSent: packets));
      } catch (_) {}
    });
  }

  Future<void> stop() async {
    _clearDisconnectTimer();
    _statsTimer?.cancel();
    _statsTimer = null;
    if (_pc != null) {
      await _pc!.close();
      _pc = null;
    }
    if (_state == WhipState.live || _state == WhipState.connecting) {
      _setState(WhipState.idle);
    }
  }

  Future<void> dispose() async {
    await stop();
    await closeCamera();
    await _stateCtrl.close();
    await _statsCtrl.close();
    _client.close();
  }
}

extension _FirstOrNull<T> on List<T> {
  T? get firstOrNull => isEmpty ? null : first;
}
