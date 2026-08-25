class ServerProfile {
  ServerProfile({
    required this.id,
    required this.name,
    required this.baseUrl,
    required this.streamKey,
    this.broadcastPassword = '',
  });

  final String id;
  final String name;
  final String baseUrl;
  final String streamKey;
  final String broadcastPassword;

  String get normalizedBaseUrl {
    var u = baseUrl.trim();
    while (u.endsWith('/')) {
      u = u.substring(0, u.length - 1);
    }
    return u;
  }

  /// Prefs-safe JSON (M26): no stream key / broadcast password.
  Map<String, dynamic> toPublicJson() => {
        'id': id,
        'name': name,
        'baseUrl': baseUrl,
        'streamKeyHint': maskedStreamKey,
      };

  String get maskedStreamKey {
    if (streamKey.length <= 4) return '••••';
    return '${streamKey.substring(0, 2)}…${streamKey.substring(streamKey.length - 2)}';
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'baseUrl': baseUrl,
        'streamKey': streamKey,
        'broadcastPassword': broadcastPassword,
      };

  factory ServerProfile.fromJson(Map<String, dynamic> json) => ServerProfile(
        id: json['id'] as String,
        name: json['name'] as String,
        baseUrl: json['baseUrl'] as String,
        streamKey: (json['streamKey'] as String?) ?? '',
        broadcastPassword: json['broadcastPassword'] as String? ?? '',
      );

  ServerProfile copyWith({
    String? name,
    String? baseUrl,
    String? streamKey,
    String? broadcastPassword,
  }) =>
      ServerProfile(
        id: id,
        name: name ?? this.name,
        baseUrl: baseUrl ?? this.baseUrl,
        streamKey: streamKey ?? this.streamKey,
        broadcastPassword: broadcastPassword ?? this.broadcastPassword,
      );
}
