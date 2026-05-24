import 'package:flutter/material.dart';

import '../models/server_profile.dart';

class ServerEditScreen extends StatefulWidget {
  const ServerEditScreen({super.key, required this.profile});

  final ServerProfile profile;

  @override
  State<ServerEditScreen> createState() => _ServerEditScreenState();
}

class _ServerEditScreenState extends State<ServerEditScreen> {
  late final TextEditingController _nameCtrl;
  late final TextEditingController _urlCtrl;
  late final TextEditingController _keyCtrl;
  late final TextEditingController _pwdCtrl;

  @override
  void initState() {
    super.initState();
    _nameCtrl = TextEditingController(text: widget.profile.name);
    _urlCtrl = TextEditingController(text: widget.profile.baseUrl);
    _keyCtrl = TextEditingController(text: widget.profile.streamKey);
    _pwdCtrl = TextEditingController(text: widget.profile.broadcastPassword);
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _urlCtrl.dispose();
    _keyCtrl.dispose();
    _pwdCtrl.dispose();
    super.dispose();
  }

  void _save() {
    final key = _keyCtrl.text.trim();
    if (key.length != 32 || !RegExp(r'^[a-zA-Z0-9]+$').hasMatch(key)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Stream key must be 32 alphanumeric characters')),
      );
      return;
    }
    Navigator.pop(
      context,
      widget.profile.copyWith(
        name: _nameCtrl.text.trim(),
        baseUrl: _urlCtrl.text.trim(),
        streamKey: key,
        broadcastPassword: _pwdCtrl.text,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Server profile'),
        actions: [
          TextButton(onPressed: _save, child: const Text('Save')),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _nameCtrl,
            decoration: const InputDecoration(labelText: 'Name', hintText: 'indep.stream'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _urlCtrl,
            decoration: const InputDecoration(
              labelText: 'Base URL',
              hintText: 'https://yourdomain.com',
            ),
            keyboardType: TextInputType.url,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _keyCtrl,
            decoration: const InputDecoration(
              labelText: 'Stream key (32 chars)',
            ),
            maxLength: 32,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _pwdCtrl,
            decoration: const InputDecoration(
              labelText: 'Broadcast password (optional)',
            ),
            obscureText: true,
          ),
        ],
      ),
    );
  }
}
