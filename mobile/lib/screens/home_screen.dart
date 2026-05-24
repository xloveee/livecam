import 'package:flutter/material.dart';

import '../models/server_profile.dart';
import '../services/storage_service.dart';
import 'broadcast_screen.dart';
import 'destinations_screen.dart';
import 'server_edit_screen.dart';
import 'watch_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<ServerProfile> _servers = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final servers = await StorageService.instance.loadServers();
    setState(() {
      _servers = servers;
      _loading = false;
    });
  }

  Future<void> _addServer() async {
    final id = await StorageService.instance.newServerId();
    if (!mounted) return;
    final result = await Navigator.push<ServerProfile>(
      context,
      MaterialPageRoute(
        builder: (_) => ServerEditScreen(
          profile: ServerProfile(
            id: id,
            name: 'My Server',
            baseUrl: 'https://indep.stream',
            streamKey: '',
          ),
        ),
      ),
    );
    if (result != null) {
      await StorageService.instance.upsertServer(result);
      await _load();
    }
  }

  Future<void> _editServer(ServerProfile profile) async {
    final result = await Navigator.push<ServerProfile>(
      context,
      MaterialPageRoute(builder: (_) => ServerEditScreen(profile: profile)),
    );
    if (result != null) {
      await StorageService.instance.upsertServer(result);
      await _load();
    }
  }

  Future<void> _deleteServer(ServerProfile profile) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete server?'),
        content: Text('Remove "${profile.name}"?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
        ],
      ),
    );
    if (ok == true) {
      await StorageService.instance.deleteServer(profile.id);
      await _load();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('livecam Mobile'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_input_antenna),
            tooltip: 'RTMP destinations',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const DestinationsScreen()),
            ),
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _servers.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Text('No servers configured'),
                      const SizedBox(height: 12),
                      FilledButton.icon(
                        onPressed: _addServer,
                        icon: const Icon(Icons.add),
                        label: const Text('Add server'),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: _servers.length,
                  itemBuilder: (context, index) {
                    final s = _servers[index];
                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      child: ListTile(
                        title: Text(s.name),
                        subtitle: Text('${s.normalizedBaseUrl}\nRoom: ${s.streamKey.isEmpty ? "(not set)" : s.streamKey}'),
                        isThreeLine: true,
                        onTap: () => _editServer(s),
                        trailing: PopupMenuButton<String>(
                          onSelected: (value) async {
                            switch (value) {
                              case 'broadcast':
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => BroadcastScreen(server: s),
                                  ),
                                );
                                break;
                              case 'watch':
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => WatchScreen(server: s),
                                  ),
                                );
                                break;
                              case 'delete':
                                await _deleteServer(s);
                                break;
                            }
                          },
                          itemBuilder: (_) => [
                            const PopupMenuItem(value: 'broadcast', child: Text('Go Live')),
                            const PopupMenuItem(value: 'watch', child: Text('Watch')),
                            const PopupMenuItem(value: 'delete', child: Text('Delete')),
                          ],
                        ),
                      ),
                    );
                  },
                ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addServer,
        child: const Icon(Icons.add),
      ),
    );
  }
}
