import 'package:flutter/material.dart';

import '../services/chat_client.dart';

class ChatPanel extends StatefulWidget {
  const ChatPanel({super.key, required this.client});

  final ChatClient client;

  @override
  State<ChatPanel> createState() => _ChatPanelState();
}

class _ChatPanelState extends State<ChatPanel> {
  final TextEditingController _input = TextEditingController();
  final List<ChatMessage> _messages = [];
  bool _connected = false;

  @override
  void initState() {
    super.initState();
    widget.client.messages.listen((msg) {
      if (!mounted) return;
      setState(() => _messages.add(msg));
    });
    widget.client.connectionState.listen((c) {
      if (!mounted) return;
      setState(() => _connected = c);
    });
  }

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  void _send() {
    final text = _input.text;
    if (text.isEmpty) return;
    if (text.startsWith('/')) {
      widget.client.sendCommand(text);
    } else {
      widget.client.sendMessage(text);
    }
    _input.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Material(
      elevation: 4,
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            child: Row(
              children: [
                Icon(
                  _connected ? Icons.circle : Icons.circle_outlined,
                  size: 12,
                  color: _connected ? Colors.green : Colors.grey,
                ),
                const SizedBox(width: 6),
                Text(_connected ? 'Chat connected' : 'Connecting...'),
              ],
            ),
          ),
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: _messages.length,
              itemBuilder: (context, index) {
                final m = _messages[index];
                switch (m.type) {
                  case 'system':
                  case 'error':
                    return Text(m.text, style: const TextStyle(color: Colors.grey));
                  case 'room_state':
                    return Text(
                      m.isLive == true ? 'Stream is live' : 'Stream offline',
                      style: const TextStyle(fontStyle: FontStyle.italic),
                    );
                  default:
                    return RichText(
                      text: TextSpan(
                        style: DefaultTextStyle.of(context).style,
                        children: [
                          TextSpan(
                            text: '${m.nick}: ',
                            style: const TextStyle(fontWeight: FontWeight.bold),
                          ),
                          TextSpan(text: m.text),
                        ],
                      ),
                    );
                }
              },
            ),
          ),
          SafeArea(
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _input,
                    decoration: const InputDecoration(
                      hintText: 'Message or /command',
                      contentPadding: EdgeInsets.symmetric(horizontal: 12),
                    ),
                    onSubmitted: (_) => _send(),
                  ),
                ),
                IconButton(onPressed: _send, icon: const Icon(Icons.send)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
