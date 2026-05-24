import 'dart:convert';

import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:http/http.dart' as http;

import '../models/server_profile.dart';

class IceConfigService {
  IceConfigService({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  Future<List<Map<String, dynamic>>> fetchIceServers(ServerProfile server) async {
    final url = Uri.parse('${server.normalizedBaseUrl}/api/config');
    final response = await _client.get(url);
    if (response.statusCode != 200) {
      throw Exception('ICE config failed (${response.statusCode})');
    }
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final servers = body['iceServers'] as List<dynamic>? ?? [];
    return servers.cast<Map<String, dynamic>>();
  }

  Future<List<RTCIceServer>> iceServersForProfile(ServerProfile server) async {
    final raw = await fetchIceServers(server);
    return raw.map(_mapIceServer).toList();
  }

  RTCIceServer _mapIceServer(Map<String, dynamic> entry) {
    final urls = entry['urls'];
    if (urls is List) {
      return RTCIceServer(
        urls: urls.map((e) => e.toString()).toList(),
        username: entry['username'] as String?,
        credential: entry['credential'] as String?,
      );
    }
    return RTCIceServer(
      urls: urls.toString(),
      username: entry['username'] as String?,
      credential: entry['credential'] as String?,
    );
  }
}
