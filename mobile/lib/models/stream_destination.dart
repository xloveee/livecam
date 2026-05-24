enum DestinationPlatform { twitch, kick, custom }

class StreamDestination {
  StreamDestination({
    required this.id,
    required this.name,
    required this.platform,
    required this.rtmpUrl,
    required this.streamKey,
    this.enabled = true,
  });

  final String id;
  final String name;
  final DestinationPlatform platform;
  final String rtmpUrl;
  final String streamKey;
  final bool enabled;

  String get fullRtmpUrl {
    final base = rtmpUrl.trim().replaceAll(RegExp(r'/+$'), '');
    final key = streamKey.trim();
    if (key.isEmpty) return base;
    return '$base/$key';
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'platform': platform.name,
        'rtmpUrl': rtmpUrl,
        'streamKey': streamKey,
        'enabled': enabled,
      };

  factory StreamDestination.fromJson(Map<String, dynamic> json) {
    final platformName = json['platform'] as String? ?? 'custom';
    return StreamDestination(
      id: json['id'] as String,
      name: json['name'] as String,
      platform: DestinationPlatform.values.firstWhere(
        (p) => p.name == platformName,
        orElse: () => DestinationPlatform.custom,
      ),
      rtmpUrl: json['rtmpUrl'] as String,
      streamKey: json['streamKey'] as String,
      enabled: json['enabled'] as bool? ?? true,
    );
  }

  static StreamDestination twitchPreset({required String id, required String streamKey}) =>
      StreamDestination(
        id: id,
        name: 'Twitch',
        platform: DestinationPlatform.twitch,
        rtmpUrl: 'rtmps://live.twitch.tv/app',
        streamKey: streamKey,
      );

  static StreamDestination kickPreset({required String id, required String streamKey}) =>
      StreamDestination(
        id: id,
        name: 'Kick',
        platform: DestinationPlatform.kick,
        rtmpUrl: 'rtmps://fa723fc1b171.global-contribute.live-video.net/app',
        streamKey: streamKey,
      );
}
