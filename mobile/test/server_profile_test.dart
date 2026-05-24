import 'package:flutter_test/flutter_test.dart';
import 'package:livecam_mobile/models/server_profile.dart';

void main() {
  test('normalizedBaseUrl strips trailing slashes', () {
    final p = ServerProfile(
      id: '1',
      name: 'test',
      baseUrl: 'https://indep.stream///',
      streamKey: 'a' * 32,
    );
    expect(p.normalizedBaseUrl, 'https://indep.stream');
  });

  test('round-trip JSON', () {
    final p = ServerProfile(
      id: 'uuid',
      name: 'indep.stream',
      baseUrl: 'https://indep.stream',
      streamKey: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
      broadcastPassword: 'secret',
    );
    final restored = ServerProfile.fromJson(p.toJson());
    expect(restored.name, p.name);
    expect(restored.streamKey, p.streamKey);
  });
}
