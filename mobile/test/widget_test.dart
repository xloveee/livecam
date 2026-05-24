import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:livecam_mobile/app.dart';

void main() {
  testWidgets('App loads home screen', (tester) async {
    await tester.pumpWidget(const LivecamApp());
    expect(find.text('livecam Mobile'), findsOneWidget);
  });
}
