class RoomInfo {
  RoomInfo({
    required this.viewerCount,
    required this.maxViewers,
    required this.hasPassword,
    required this.isLive,
    this.offlineBanner = '',
    this.offlineBannerImage = '',
  });

  final int viewerCount;
  final int maxViewers;
  final bool hasPassword;
  final bool isLive;
  final String offlineBanner;
  final String offlineBannerImage;

  factory RoomInfo.fromJson(Map<String, dynamic> json) => RoomInfo(
        viewerCount: (json['viewer_count'] as num?)?.toInt() ?? 0,
        maxViewers: (json['max_viewers'] as num?)?.toInt() ?? 0,
        hasPassword: json['has_password'] as bool? ?? false,
        isLive: json['is_live'] as bool? ?? false,
        offlineBanner: json['offline_banner'] as String? ?? '',
        offlineBannerImage: json['offline_banner_image'] as String? ?? '',
      );
}
