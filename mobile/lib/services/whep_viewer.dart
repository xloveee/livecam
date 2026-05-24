import 'dart:async';

import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:http/http.dart' as http;

import '../models/server_profile.dart';
import 'ice_config_service.dart';

enum WhepState { idle, connecting, live, offline, error, rateLimited, needPassword }

class WhepViewer {
  WhepViewer({
    IceConfigService? iceConfig,
    http.Client? client,
  })  : _iceConfig = iceConfig ?? IceConfigService(),
        _client = client ?? http.Client();

  static const whepConnectTimeoutMs = 40000;

  final IceConfigService _iceConfig;
  final http.Client _client;

  RTCPeerConnection? _pc;
  String? _sessionId;
  ServerProfile? _server;
  String? _roomId;
  Timer? _connectTimeout;
  WhepState _state = WhepState.idle;

  final StreamController<WhepState> _stateCtrl =
      StreamController<WhepState>.broadcast();
  final StreamController<MediaStream> _remoteStreamCtrl =
      StreamController<MediaStream>.broadcast();

  Stream<WhepState> get stateStream => _stateCtrl.stream;
  Stream<MediaStream> get remoteStreamStream => _remoteStreamCtrl.stream;
  WhepState get state => _state;
  String? get sessionId => _sessionId;
  RTCVideoRenderer? remoteRenderer;

  void _setState(WhepState s) {
    _state = s;
    _stateCtrl.add(s);
  }

  Future<void> connect({
    required ServerProfile server,
    required String roomId,
    String? roomPassword,
  }) async {
    await disconnect();
    _server = server;
    _roomId = roomId;
    _setState(WhepState.connecting);

    final iceServers = await _iceConfig.iceServersForProfile(server);
    _pc = await createPeerConnection({
      'iceServers': iceServers.map((s) => s.toMap()).toList(),
      'sdpSemantics': 'unified-plan',
      'bundlePolicy': 'max-bundle',
      'rtcpMuxPolicy': 'require',
    });

    _pc!.onTrack = (event) {
      _clearConnectTimeout();
      if (event.streams.isNotEmpty) {
        final stream = event.streams.first;
        if (remoteRenderer != null) {
          remoteRenderer!.srcObject = stream;
        }
        _remoteStreamCtrl.add(stream);
        _setState(WhepState.live);
      }
    };

    _pc!.onIceConnectionState = (iceState) {
      if (iceState == RTCIceConnectionState.RTCIceConnectionStateFailed) {
        _setState(WhepState.error);
      }
    };

    await _pc!.addTransceiver(
      kind: RTCRtpMediaType.RTCRtpMediaTypeVideo,
      init: RTCRtpTransceiverInit(direction: TransceiverDirection.RecvOnly),
    );
    await _pc!.addTransceiver(
      kind: RTCRtpMediaType.RTCRtpMediaTypeAudio,
      init: RTCRtpTransceiverInit(direction: TransceiverDirection.RecvOnly),
    );

    await _applyReceiverCodecPreferences(_pc!);

    final offer = await _pc!.createOffer();
    await _pc!.setLocalDescription(offer);

    final headers = <String, String>{'Content-Type': 'application/sdp'};
    if (roomPassword != null && roomPassword.isNotEmpty) {
      headers['X-Room-Password'] = roomPassword;
    }

    final url = Uri.parse('${server.normalizedBaseUrl}/api/whep/$roomId');
    final response = await _client.post(url, headers: headers, body: offer.sdp);

    if (response.statusCode == 404) {
      _setState(WhepState.offline);
      await _closePc();
      return;
    }
    if (response.statusCode == 403) {
      _setState(WhepState.needPassword);
      await _closePc();
      return;
    }
    if (response.statusCode == 429) {
      _setState(WhepState.rateLimited);
      await _closePc();
      return;
    }
    if (response.statusCode != 200 && response.statusCode != 201) {
      _setState(WhepState.error);
      await _closePc();
      throw Exception('WHEP failed (${response.statusCode})');
    }

    _sessionId = response.headers['x-session-id'];
    final answer = RTCSessionDescription(response.body, 'answer');
    await _pc!.setRemoteDescription(answer);

    _connectTimeout = Timer(
      const Duration(milliseconds: whepConnectTimeoutMs),
      () {
        if (_state == WhepState.connecting) {
          _setState(WhepState.offline);
          disconnect();
        }
      },
    );
  }

  Future<void> _applyReceiverCodecPreferences(RTCPeerConnection pc) async {
    try {
      final caps = await getRtpReceiverCapabilities('video');
      if (caps == null) return;
      final h264 = caps.codecs
          .where((c) => c.mimeType?.toLowerCase() == 'video/h264')
          .toList();
      final vp8 = caps.codecs
          .where((c) => c.mimeType?.toLowerCase() == 'video/vp8')
          .toList();
      final rest = caps.codecs.where((c) {
        final m = c.mimeType?.toLowerCase() ?? '';
        return m != 'video/h264' && m != 'video/vp8';
      }).toList();

      final transceivers = await pc.getTransceivers();
      for (final tr in transceivers) {
        if (tr.receiver.track?.kind == 'video' ||
            tr.mid == transceivers.first.mid) {
          if (h264.isNotEmpty) {
            await tr.setCodecPreferences(h264 + vp8 + rest);
          } else if (vp8.isNotEmpty) {
            await tr.setCodecPreferences(vp8 + rest);
          }
          break;
        }
      }
    } catch (_) {}
  }

  void _clearConnectTimeout() {
    _connectTimeout?.cancel();
    _connectTimeout = null;
  }

  Future<void> disconnect() async {
    _clearConnectTimeout();
    final server = _server;
    final roomId = _roomId;
    final sid = _sessionId;
    if (sid != null && server != null && roomId != null) {
      try {
        final url = Uri.parse('${server.normalizedBaseUrl}/api/whep/$roomId');
        await _client.delete(url, headers: {'X-Session-Id': sid});
      } catch (_) {}
    }
    await _closePc();
    _sessionId = null;
    if (remoteRenderer != null) {
      remoteRenderer!.srcObject = null;
    }
    _setState(WhepState.idle);
  }

  Future<void> disconnectFromServer(ServerProfile server, String roomId) async {
    _server = server;
    _roomId = roomId;
    await disconnect();
  }

  Future<void> _closePc() async {
    if (_pc != null) {
      await _pc!.close();
      _pc = null;
    }
  }

  Future<void> dispose() async {
    await disconnect();
    await _stateCtrl.close();
    await _remoteStreamCtrl.close();
    _client.close();
  }
}
