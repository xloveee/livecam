import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:web_socket_channel/io.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../models/server_profile.dart';

class ChatMessage {
  ChatMessage({
    required this.type,
    this.nick = '',
    this.text = '',
    this.role = 'viewer',
    this.isLive,
    this.viewerCount,
  });

  final String type;
  final String nick;
  final String text;
  final String role;
  final bool? isLive;
  final int? viewerCount;

  factory ChatMessage.fromJson(Map<String, dynamic> json) => ChatMessage(
        type: json['type'] as String? ?? 'msg',
        nick: json['nick'] as String? ?? '',
        text: json['text'] as String? ?? '',
        role: json['role'] as String? ?? 'viewer',
        isLive: json['is_live'] as bool?,
        viewerCount: (json['viewer_count'] as num?)?.toInt(),
      );
}

class ChatClient {
  WebSocketChannel? _channel;
  Timer? _reconnectTimer;
  String? _roomId;
  String? _nick;
  ServerProfile? _server;
  String? _authToken;
  bool _manualClose = false;

  final StreamController<ChatMessage> _messages =
      StreamController<ChatMessage>.broadcast();
  final StreamController<bool> _connection =
      StreamController<bool>.broadcast();

  Stream<ChatMessage> get messages => _messages.stream;
  Stream<bool> get connectionState => _connection.stream;

  static bool isValidNick(String nick) {
    if (nick.isEmpty || nick.length > 25) return false;
    return RegExp(r'^[a-zA-Z0-9_]+$').hasMatch(nick);
  }

  String? _roomPassword;

  void connect({
    required ServerProfile server,
    required String roomId,
    required String nick,
    String? authToken,
    String? roomPassword,
  }) {
    _manualClose = false;
    _server = server;
    _roomId = roomId;
    _nick = nick;
    _authToken = authToken;
    _roomPassword = roomPassword;
    _openSocket();
  }

  /// Build handshake headers (H20): Bearer auth + room password header.
  /// Invite must not ride on the query string.
  Map<String, String> handshakeHeaders({String? authToken, String? roomPassword}) {
    final headers = <String, String>{};
    final token = authToken ?? _authToken;
    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
    final invite = roomPassword ?? _roomPassword;
    if (invite != null && invite.isNotEmpty) {
      headers['X-Room-Password'] = invite;
    }
    return headers;
  }

  Uri handshakeUri({
    ServerProfile? server,
    String? roomId,
    String? nick,
  }) {
    final s = server ?? _server!;
    final id = roomId ?? _roomId!;
    final n = nick ?? _nick!;
    final base = Uri.parse(s.normalizedBaseUrl);
    final wsScheme = base.scheme == 'https' ? 'wss' : 'ws';
    return Uri(
      scheme: wsScheme,
      host: base.host,
      port: base.hasPort ? base.port : null,
      path: '/api/chat/$id',
      queryParameters: {'nick': n},
    );
  }

  void _openSocket() {
    disconnectSocketOnly();
    final server = _server;
    final roomId = _roomId;
    final nick = _nick;
    if (server == null || roomId == null || nick == null) return;

    final uri = handshakeUri();
    final headers = handshakeHeaders();

    // H20: IO channel so we can send Authorization / X-Room-Password.
    _channel = IOWebSocketChannel.connect(
      uri,
      headers: headers.isEmpty ? null : headers,
      customClient: HttpClient()..connectionTimeout = const Duration(seconds: 15),
    );
    _connection.add(false);

    _channel!.stream.listen(
      (data) {
        _connection.add(true);
        try {
          final json = jsonDecode(data as String) as Map<String, dynamic>;
          _messages.add(ChatMessage.fromJson(json));
        } catch (_) {}
      },
      onDone: () {
        _connection.add(false);
        if (!_manualClose) {
          _scheduleReconnect();
        }
      },
      onError: (_) {
        _connection.add(false);
        if (!_manualClose) {
          _scheduleReconnect();
        }
      },
    );
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 3), _openSocket);
  }

  void sendMessage(String text) {
    if (_channel == null || text.trim().isEmpty) return;
    _channel!.sink.add(jsonEncode({'type': 'msg', 'text': text.trim()}));
  }

  void sendCommand(String cmd) {
    if (_channel == null || cmd.trim().isEmpty) return;
    _channel!.sink.add(jsonEncode({'type': 'cmd', 'text': cmd.trim()}));
  }

  void disconnectSocketOnly() {
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _channel?.sink.close();
    _channel = null;
  }

  void disconnect() {
    _manualClose = true;
    disconnectSocketOnly();
    _connection.add(false);
  }

  void dispose() {
    disconnect();
    _messages.close();
    _connection.close();
  }
}
