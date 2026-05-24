import 'package:flutter/material.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';

class VideoPreview extends StatelessWidget {
  const VideoPreview({super.key, this.stream});

  final MediaStream? stream;

  @override
  Widget build(BuildContext context) {
    if (stream == null) {
      return const ColoredBox(
        color: Colors.black,
        child: Center(child: Icon(Icons.videocam_off, color: Colors.white54, size: 48)),
      );
    }
    return _VideoPreviewRenderer(stream: stream!);
  }
}

class _VideoPreviewRenderer extends StatefulWidget {
  const _VideoPreviewRenderer({required this.stream});

  final MediaStream stream;

  @override
  State<_VideoPreviewRenderer> createState() => _VideoPreviewRendererState();
}

class _VideoPreviewRendererState extends State<_VideoPreviewRenderer> {
  final RTCVideoRenderer _renderer = RTCVideoRenderer();

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    await _renderer.initialize();
    _renderer.srcObject = widget.stream;
    if (mounted) setState(() {});
  }

  @override
  void didUpdateWidget(covariant _VideoPreviewRenderer oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.stream != widget.stream) {
      _renderer.srcObject = widget.stream;
    }
  }

  @override
  void dispose() {
    _renderer.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
  return ColoredBox(
      color: Colors.black,
      child: RTCVideoView(
        _renderer,
        mirror: true,
        objectFit: RTCVideoViewObjectFit.RTCVideoViewObjectFitCover,
      ),
    );
  }
}
