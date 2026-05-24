import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/room_info.dart';
import '../models/server_profile.dart';
import 'storage_service.dart';

class AuthResult {
  AuthResult({required this.token, required this.streamKey});
  final String token;
  final String streamKey;
}

class AuthService {
  AuthService({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  Future<AuthResult> login(ServerProfile server) async {
    final url = Uri.parse('${server.normalizedBaseUrl}/api/auth/broadcast');
    final response = await _client.post(
      url,
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'password': server.broadcastPassword,
        'stream_key': server.streamKey,
      }),
    );
    if (response.statusCode != 200) {
      throw Exception('Authentication failed (${response.statusCode})');
    }
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final token = body['token'] as String?;
    if (token == null || token.isEmpty) {
      throw Exception('Server did not return auth token');
    }
    await StorageService.instance.saveAuthToken(server.id, token);
    return AuthResult(
      token: token,
      streamKey: body['stream_key'] as String? ?? server.streamKey,
    );
  }

  Future<bool> checkSession(ServerProfile server, String token) async {
    final url = Uri.parse(
      '${server.normalizedBaseUrl}/api/auth/broadcast?stream_key=${Uri.encodeComponent(server.streamKey)}',
    );
    final response = await _client.get(
      url,
      headers: {'Authorization': 'Bearer $token'},
    );
    return response.statusCode == 200;
  }

  Future<RoomInfo> fetchRoomInfo(ServerProfile server, {String? roomId}) async {
    final id = roomId ?? server.streamKey;
    final url = Uri.parse('${server.normalizedBaseUrl}/api/room_info/$id');
    final response = await _client.get(url);
    if (response.statusCode != 200) {
      throw Exception('Room info failed (${response.statusCode})');
    }
    return RoomInfo.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
  }
}
