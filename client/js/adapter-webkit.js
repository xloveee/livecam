/* adapter-webkit.js — WebKit adapter (Safari, DuckDuckGo iOS)
 *
 * Key differences from Chromium:
 *   - H.264 preferred (VP9 hardware decode unavailable on many iOS devices)
 *   - Native HLS (no hls.js needed)
 *   - Older WebKit needs explicit sdpSemantics: 'unified-plan'
 */

function WebKitAdapter(videoEl) {
    WatchAdapter.call(this, videoEl);
}

WebKitAdapter.prototype = Object.create(WatchAdapter.prototype);
WebKitAdapter.prototype.constructor = WebKitAdapter;
WebKitAdapter.prototype.name = 'webkit';

WebKitAdapter.prototype.createPC = function (iceServers) {
    return new RTCPeerConnection({
        iceServers: iceServers,
        sdpSemantics: 'unified-plan'
    });
};

WebKitAdapter.prototype.setupTransceivers = function (pc) {
    var videoTx = pc.addTransceiver('video', { direction: 'recvonly' });
    pc.addTransceiver('audio', { direction: 'recvonly' });
    if (videoTx.setCodecPreferences && RTCRtpReceiver.getCapabilities) {
        try {
            var caps = RTCRtpReceiver.getCapabilities('video');
            if (caps && caps.codecs) {
                var h264 = caps.codecs.filter(function (c) {
                    return c.mimeType === 'video/H264';
                });
                var rest = caps.codecs.filter(function (c) {
                    return c.mimeType !== 'video/H264';
                });
                if (h264.length > 0) {
                    videoTx.setCodecPreferences(h264.concat(rest));
                }
            }
        } catch (e) { /* older WebKit — use default order */ }
    }
};

WebKitAdapter.prototype.startHLS = function (url) {
    this.video.muted = true;
    this.video.src = url;
    this.video.play().catch(function () {});
    this.hlsActive = true;
    return true;
};

WebKitAdapter.prototype.stopHLS = function () {
    this.video.removeAttribute('src');
    this.video.load();
    this.hlsActive = false;
};
