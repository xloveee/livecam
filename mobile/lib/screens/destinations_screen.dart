import 'package:flutter/material.dart';
import 'package:uuid/uuid.dart';

import '../models/stream_destination.dart';
import '../services/storage_service.dart';

class DestinationsScreen extends StatefulWidget {
  const DestinationsScreen({super.key});

  @override
  State<DestinationsScreen> createState() => _DestinationsScreenState();
}

class _DestinationsScreenState extends State<DestinationsScreen> {
  List<StreamDestination> _destinations = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final list = await StorageService.instance.loadDestinations();
    setState(() {
      _destinations = list;
      _loading = false;
    });
  }

  Future<void> _addDestination(DestinationPlatform platform) async {
    final id = const Uuid().v4();
    final keyCtrl = TextEditingController();
    final urlCtrl = TextEditingController(
      text: platform == DestinationPlatform.twitch
          ? 'rtmps://live.twitch.tv/app'
          : platform == DestinationPlatform.kick
              ? 'rtmps://fa723fc1b171.global-contribute.live-video.net/app'
              : '',
    );

    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Add ${platform.name} destination'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (platform == DestinationPlatform.custom)
              TextField(
                controller: urlCtrl,
                decoration: const InputDecoration(labelText: 'RTMP URL'),
              ),
            TextField(
              controller: keyCtrl,
              decoration: const InputDecoration(labelText: 'Stream key'),
              obscureText: true,
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Add')),
        ],
      ),
    );

    if (ok == true && keyCtrl.text.trim().isNotEmpty) {
      final dest = StreamDestination(
        id: id,
        name: platform.name[0].toUpperCase() + platform.name.substring(1),
        platform: platform,
        rtmpUrl: urlCtrl.text.trim().isEmpty
            ? (platform == DestinationPlatform.twitch
                ? 'rtmps://live.twitch.tv/app'
                : 'rtmps://fa723fc1b171.global-contribute.live-video.net/app')
            : urlCtrl.text.trim(),
        streamKey: keyCtrl.text.trim(),
      );
      _destinations.add(dest);
      await StorageService.instance.saveDestinations(_destinations);
      await _load();
    }
  }

  Future<void> _toggleEnabled(StreamDestination d, bool enabled) async {
    final idx = _destinations.indexWhere((x) => x.id == d.id);
    if (idx < 0) return;
    _destinations[idx] = StreamDestination(
      id: d.id,
      name: d.name,
      platform: d.platform,
      rtmpUrl: d.rtmpUrl,
      streamKey: d.streamKey,
      enabled: enabled,
    );
    await StorageService.instance.saveDestinations(_destinations);
    await _load();
  }

  Future<void> _delete(StreamDestination d) async {
    _destinations.removeWhere((x) => x.id == d.id);
    await StorageService.instance.saveDestinations(_destinations);
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('RTMP destinations')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              children: [
                for (final d in _destinations)
                  ListTile(
                    title: Text(d.name),
                    subtitle: Text(d.rtmpUrl),
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Switch(
                          value: d.enabled,
                          onChanged: (v) => _toggleEnabled(d, v),
                        ),
                        IconButton(
                          icon: const Icon(Icons.delete_outline),
                          onPressed: () => _delete(d),
                        ),
                      ],
                    ),
                  ),
                const Divider(),
                ListTile(
                  leading: const Icon(Icons.live_tv),
                  title: const Text('Add Twitch'),
                  onTap: () => _addDestination(DestinationPlatform.twitch),
                ),
                ListTile(
                  leading: const Icon(Icons.sports_esports),
                  title: const Text('Add Kick'),
                  onTap: () => _addDestination(DestinationPlatform.kick),
                ),
                ListTile(
                  leading: const Icon(Icons.link),
                  title: const Text('Add custom RTMP'),
                  onTap: () => _addDestination(DestinationPlatform.custom),
                ),
              ],
            ),
    );
  }
}
