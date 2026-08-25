import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

import '../models/server_profile.dart';
import '../models/stream_destination.dart';

class StorageService {
  StorageService._();
  static final StorageService instance = StorageService._();

  static const _serversKey = 'livecam_servers';
  static const _destinationsKey = 'livecam_destinations';
  static const _nickKey = 'livecam_chat_nick';
  static const _tokenPrefix = 'livecam_token_';
  static const _secretsPrefix = 'livecam_server_secrets_';

  final FlutterSecureStorage _secure = const FlutterSecureStorage();

  Future<List<ServerProfile>> loadServers() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_serversKey);
    if (raw == null || raw.isEmpty) return [];
    final list = jsonDecode(raw) as List<dynamic>;
    final out = <ServerProfile>[];
    for (final e in list) {
      final m = Map<String, dynamic>.from(e as Map);
      final id = m['id'] as String? ?? '';
      // M26: secrets live in FlutterSecureStorage; migrate legacy prefs JSON once.
      final secRaw = await _secure.read(key: '$_secretsPrefix$id');
      if (secRaw != null && secRaw.isNotEmpty) {
        final sec = jsonDecode(secRaw) as Map<String, dynamic>;
        m['streamKey'] = sec['streamKey'] ?? m['streamKey'] ?? '';
        m['broadcastPassword'] = sec['broadcastPassword'] ?? '';
      }
      out.add(ServerProfile.fromJson(m));
    }
    return out;
  }

  Future<void> saveServers(List<ServerProfile> servers) async {
    final prefs = await SharedPreferences.getInstance();
    for (final s in servers) {
      await _secure.write(
        key: '$_secretsPrefix${s.id}',
        value: jsonEncode({
          'streamKey': s.streamKey,
          'broadcastPassword': s.broadcastPassword,
        }),
      );
    }
    // Prefs hold public metadata only (M26).
    final encoded = jsonEncode(servers.map((s) => s.toPublicJson()).toList());
    await prefs.setString(_serversKey, encoded);
  }

  Future<ServerProfile> upsertServer(ServerProfile profile) async {
    final servers = await loadServers();
    final idx = servers.indexWhere((s) => s.id == profile.id);
    if (idx >= 0) {
      servers[idx] = profile;
    } else {
      servers.add(profile);
    }
    await saveServers(servers);
    return profile;
  }

  Future<void> deleteServer(String id) async {
    final servers = await loadServers();
    servers.removeWhere((s) => s.id == id);
    await saveServers(servers);
    await _secure.delete(key: '$_tokenPrefix$id');
  }

  Future<String> newServerId() async => const Uuid().v4();

  Future<void saveAuthToken(String serverId, String token) async {
    await _secure.write(key: '$_tokenPrefix$serverId', value: token);
  }

  Future<String?> loadAuthToken(String serverId) =>
      _secure.read(key: '$_tokenPrefix$serverId');

  Future<void> clearAuthToken(String serverId) =>
      _secure.delete(key: '$_tokenPrefix$serverId');

  Future<List<StreamDestination>> loadDestinations() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_destinationsKey);
    if (raw == null || raw.isEmpty) return [];
    final list = jsonDecode(raw) as List<dynamic>;
    return list
        .map((e) => StreamDestination.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<void> saveDestinations(List<StreamDestination> destinations) async {
    final prefs = await SharedPreferences.getInstance();
    final encoded = jsonEncode(destinations.map((d) => d.toJson()).toList());
    await prefs.setString(_destinationsKey, encoded);
  }

  Future<String?> loadChatNick() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_nickKey);
  }

  Future<void> saveChatNick(String nick) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_nickKey, nick);
  }
}
