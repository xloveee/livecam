import 'dart:async';
import 'dart:convert';

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

  void connect({
    required ServerProfile server,
    required String roomId,
    required String nick,
    String? authToken,
  }) {
    _manualClose = false;
    _server = server;
    _roomId = roomId;
    _nick = nick;
    _authToken = authToken;
    _openSocket();
  }

  void _openSocket() {
    disconnectSocketOnly();
    final server = _server;
    final roomId = _roomId;
    final nick = _nick;
    if (server == null || roomId == null || nick == null) return;

    final base = Uri.parse(server.normalizedBaseUrl);
    final wsScheme = base.scheme == 'https' ? 'wss' : 'ws';
    final uri = Uri(
      scheme: wsScheme,
      host: base.host,
      port: base.hasPort ? base.port : null,
      path: '/api/chat/$roomId',
      queryParameters: {'nick': nick},
    );

    _channel = WebSocketChannel.connect(uri);
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
