import 'package:flutter_test/flutter_test.dart';
import 'package:livecam_mobile/models/server_profile.dart';
import 'package:livecam_mobile/services/chat_client.dart';

void main() {
  test('H20 handshake puts auth and invite on headers, not query', () {
    final client = ChatClient();
    final server = ServerProfile(
      id: '1',
      name: 't',
      baseUrl: 'https://live.example',
      streamKey: 'abcdefghijklmnopqrstuvwxyz012345',
    );
    final headers = client.handshakeHeaders(
      authToken: 'tok-abc',
      roomPassword: 'invite-secret',
    );
    expect(headers['Authorization'], 'Bearer tok-abc');
    expect(headers['X-Room-Password'], 'invite-secret');
    final uri = client.handshakeUri(
      server: server,
      roomId: 'abcdefghijklmnopqrstuvwxyz012345',
      nick: 'alice',
    );
    expect(uri.queryParameters.containsKey('invite'), isFalse);
    expect(uri.queryParameters['nick'], 'alice');
    expect(uri.path, '/api/chat/abcdefghijklmnopqrstuvwxyz012345');
  });
}
