import 'package:flutter/material.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:video_player/video_player.dart';

import '../models/server_profile.dart';
import '../services/chat_client.dart';
import '../services/hls_viewer.dart';
import '../services/storage_service.dart';
import '../services/whep_viewer.dart';
import '../widgets/chat_panel.dart';

class WatchScreen extends StatefulWidget {
  const WatchScreen({super.key, required this.server});

  final ServerProfile server;

  @override
  State<WatchScreen> createState() => _WatchScreenState();
}

class _WatchScreenState extends State<WatchScreen> {
  final WhepViewer _whep = WhepViewer();
  final HlsViewer _hls = HlsViewer();
  final ChatClient _chat = ChatClient();
  final RTCVideoRenderer _renderer = RTCVideoRenderer();

  WhepState _state = WhepState.idle;
  bool _usingHls = false;
  String _roomId = '';
  String? _roomPassword;
  String _nick = '';
  bool _chatVisible = true;

  @override
  void initState() {
    super.initState();
    _roomId = widget.server.streamKey;
    _init();
  }

  Future<void> _init() async {
    await _renderer.initialize();
    _whep.remoteRenderer = _renderer;
    _whep.stateStream.listen((s) async {
      if (!mounted) return;
      setState(() => _state = s);
      if (s == WhepState.offline || s == WhepState.error) {
        await _tryHlsFallback();
      }
    });
    final savedNick = await StorageService.instance.loadChatNick();
    _nick = savedNick ?? 'Viewer';
    await _connect();
  }

  Future<void> _connect() async {
    setState(() => _usingHls = false);
    if (preferHlsOnPlatform()) {
      final ok = await _hls.isManifestAvailable(widget.server, _roomId);
      if (ok) {
        await _startHls();
        _connectChat();
        return;
      }
    }
    try {
      await _whep.connect(
        server: widget.server,
        roomId: _roomId,
        roomPassword: _roomPassword,
      );
      if (_state == WhepState.live) {
        _connectChat();
      }
    } catch (_) {
      await _tryHlsFallback();
    }
  }

  Future<void> _tryHlsFallback() async {
    final ok = await _hls.isManifestAvailable(widget.server, _roomId);
    if (ok) {
      await _startHls();
      _connectChat();
    }
  }

  Future<void> _startHls() async {
    await _hls.play(widget.server, _roomId);
    setState(() => _usingHls = true);
  }

  void _connectChat() {
    _chat.connect(
      server: widget.server,
      roomId: _roomId,
      nick: _nick,
    );
  }

  Future<void> _promptPassword() async {
    final ctrl = TextEditingController();
    final pwd = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Room password'),
        content: TextField(
          controller: ctrl,
          obscureText: true,
          decoration: const InputDecoration(labelText: 'Password'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, ctrl.text), child: const Text('Join')),
        ],
      ),
    );
    if (pwd != null) {
      _roomPassword = pwd;
      await _connect();
    }
  }

  String get _statusLabel {
    switch (_state) {
      case WhepState.connecting:
        return 'Connecting...';
      case WhepState.live:
        return _usingHls ? 'Live (HLS)' : 'Live (WebRTC)';
      case WhepState.offline:
        return 'Offline';
      case WhepState.needPassword:
        return 'Password required';
      case WhepState.rateLimited:
        return 'Rate limited';
      case WhepState.error:
        return 'Connection error';
      default:
        return _usingHls ? 'Live (HLS)' : 'Idle';
    }
  }

  @override
  void dispose() {
    _chat.dispose();
    _whep.disconnectFromServer(widget.server, _roomId);
    _whep.dispose();
    _hls.stop();
    _hls.dispose();
    _renderer.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_state == WhepState.needPassword && _roomPassword == null) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _promptPassword());
    }

    return Scaffold(
      appBar: AppBar(
        title: Text('Watch — ${widget.server.name}'),
        actions: [
          IconButton(
            icon: Icon(_chatVisible ? Icons.chat : Icons.chat_outlined),
            onPressed: () => setState(() => _chatVisible = !_chatVisible),
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _connect,
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            flex: _chatVisible ? 3 : 1,
            child: Stack(
              fit: StackFit.expand,
              children: [
                if (_usingHls && _hls.controller != null)
                  Center(
                    child: AspectRatio(
                      aspectRatio: _hls.controller!.value.aspectRatio,
                      child: VideoPlayer(_hls.controller!),
                    ),
                  )
                else
                  RTCVideoView(
                    _renderer,
                    objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitContain,
                  ),
                Positioned(
                  left: 8,
                  top: 8,
                  child: Chip(label: Text(_statusLabel)),
                ),
              ],
            ),
          ),
          if (_chatVisible)
            Expanded(
              flex: 2,
              child: ChatPanel(client: _chat),
            ),
        ],
      ),
    );
  }
}
