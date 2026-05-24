import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:wakelock_plus/wakelock_plus.dart';

import '../models/server_profile.dart';
import '../models/stream_destination.dart';
import '../services/auth_service.dart';
import '../services/broadcast_foreground_service.dart';
import '../services/rtmp_publisher.dart';
import '../services/storage_service.dart';
import '../services/whip_publisher.dart';
import '../widgets/video_preview.dart';

class BroadcastScreen extends StatefulWidget {
  const BroadcastScreen({super.key, required this.server});

  final ServerProfile server;

  @override
  State<BroadcastScreen> createState() => _BroadcastScreenState();
}

class _BroadcastScreenState extends State<BroadcastScreen> {
  final WhipPublisher _whip = WhipPublisher();
  final RtmpPublisher _rtmp = RtmpPublisher();
  final AuthService _auth = AuthService();

  bool _useLivecam = true;
  bool _useRtmp = false;
  List<StreamDestination> _destinations = [];
  StreamDestination? _selectedRtmp;
  bool _frontCamera = true;
  bool _busy = false;
  String _status = 'Ready';
  double _bitrate = 0;
  WhipState _whipState = WhipState.idle;
  RtmpState _rtmpState = RtmpState.idle;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    await _requestPermissions();
    await _loadDestinations();
    _whip.stateStream.listen((s) {
      if (mounted) setState(() => _whipState = s);
    });
    _whip.statsStream.listen((stats) {
      if (mounted) setState(() => _bitrate = stats.bitrateKbps);
    });
    _rtmp.stateStream.listen((s) {
      if (mounted) setState(() => _rtmpState = s);
    });
    try {
      await _whip.openCamera(frontCamera: _frontCamera);
      setState(() {});
    } catch (e) {
      setState(() => _status = 'Camera error: $e');
    }
  }

  Future<void> _loadDestinations() async {
    final list = await StorageService.instance.loadDestinations();
    setState(() {
      _destinations = list.where((d) => d.enabled).toList();
      _selectedRtmp = _destinations.isNotEmpty ? _destinations.first : null;
    });
  }

  Future<void> _requestPermissions() async {
    await [Permission.camera, Permission.microphone].request();
  }

  bool get _isLive =>
      _whipState == WhipState.live || _rtmpState == RtmpState.live;

  Future<void> _goLive() async {
    if (_busy) return;
    if (!_useLivecam && !_useRtmp) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Select at least one destination')),
      );
      return;
    }
    setState(() {
      _busy = true;
      _status = 'Authenticating...';
    });

    try {
      String? token;
      if (_useLivecam) {
        final auth = await _auth.login(widget.server);
        token = auth.token;
      }

      await BroadcastForegroundService.start(
        title: 'livecam — LIVE',
        body: widget.server.name,
      );
      await WakelockPlus.enable();

      if (_useLivecam && token != null) {
        setState(() => _status = 'Starting WHIP...');
        await _whip.start(server: widget.server, authToken: token);
      }

      if (_useRtmp && _selectedRtmp != null) {
        setState(() => _status = 'Starting RTMP...');
        await _rtmp.start(destination: _selectedRtmp!, frontCamera: _frontCamera);
      }

      setState(() => _status = 'LIVE');
    } catch (e) {
      setState(() => _status = 'Failed: $e');
      await _stopAll();
    } finally {
      setState(() => _busy = false);
    }
  }

  Future<void> _stopAll() async {
    await _whip.stop();
    await _rtmp.stop();
    await BroadcastForegroundService.stop();
    await WakelockPlus.disable();
    setState(() => _status = 'Stopped');
  }

  Future<void> _switchCamera() async {
    setState(() => _frontCamera = !_frontCamera);
    if (_isLive) {
      await _whip.switchCamera();
      await _rtmp.switchCamera();
    } else {
      await _whip.openCamera(frontCamera: _frontCamera);
      setState(() {});
    }
  }

  @override
  void dispose() {
    _whip.dispose();
    _rtmp.dispose();
    WakelockPlus.disable();
    BroadcastForegroundService.stop();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Broadcast — ${widget.server.name}'),
        actions: [
          IconButton(
            icon: Icon(_frontCamera ? Icons.camera_front : Icons.camera_rear),
            onPressed: _switchCamera,
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: VideoPreview(stream: _whip.localStream),
          ),
          Padding(
            padding: const EdgeInsets.all(12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(_status, style: Theme.of(context).textTheme.titleMedium),
                if (_bitrate > 0)
                  Text('↑ ${_bitrate.toStringAsFixed(0)} kbps'),
                const SizedBox(height: 8),
                CheckboxListTile(
                  value: _useLivecam,
                  onChanged: _isLive
                      ? null
                      : (v) => setState(() => _useLivecam = v ?? true),
                  title: const Text('livecam (WHIP)'),
                  subtitle: Text(widget.server.normalizedBaseUrl),
                ),
                CheckboxListTile(
                  value: _useRtmp,
                  onChanged: _isLive
                      ? null
                      : (v) => setState(() => _useRtmp = v ?? false),
                  title: const Text('RTMP (Twitch/Kick)'),
                ),
                if (_useRtmp && _destinations.isNotEmpty)
                  DropdownButtonFormField<StreamDestination>(
                    value: _selectedRtmp,
                    decoration: const InputDecoration(labelText: 'RTMP destination'),
                    items: _destinations
                        .map((d) => DropdownMenuItem(value: d, child: Text(d.name)))
                        .toList(),
                    onChanged: _isLive
                        ? null
                        : (d) => setState(() => _selectedRtmp = d),
                  ),
                if (_useRtmp && _destinations.isEmpty)
                  const Text('Add RTMP destinations from home screen menu'),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Expanded(
                      child: FilledButton(
                        onPressed: _isLive || _busy ? null : _goLive,
                        child: const Text('Go Live'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: OutlinedButton(
                        onPressed: _isLive ? _stopAll : null,
                        child: const Text('Stop'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
