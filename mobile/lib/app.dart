import 'package:flutter/material.dart';

import 'screens/home_screen.dart';

class LivecamApp extends StatelessWidget {
  const LivecamApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'livecam Mobile',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFFE53935),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const HomeScreen(),
    );
  }
}
