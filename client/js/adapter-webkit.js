/* adapter-webkit.js — WebKit adapter (Safari, DuckDuckGo iOS)
 *
 * WebKit handles remote MediaStreams differently from Chromium:
 *   - event.streams[0] is the reliable way to get the remote stream
 *   - Manual new MediaStream() + addTrack() can lose the stream binding
 *     after ICE restarts or track renegotiation on WebKit
 *   - Explicit load() required before play() for MediaStream sources
 *   - H.264 preferred (VP9 hardware decoding unavailable on many iOS devices)
 *   - Native HLS is supported (no hls.js needed)
 *   - Older WebKit needs explicit sdpSemantics: 'unified-plan'
 */

function WebKitAdapter(videoEl) {
    WatchAdapter.call(this, videoEl);
    this._playPending = null;
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
        } catch (e) { /* older WebKit — fall through with default order */ }
    }
};

WebKitAdapter.prototype.play = function () {
    var v = this.video;
    if (v.readyState >= 1) {
        return v.play().then(function () {
            return { ok: true, error: '' };
        }).catch(function (e) {
            return { ok: false, error: e.name || 'blocked' };
        });
    }
    if (this._playPending) return this._playPending;
    var self = this;
    this._playPending = new Promise(function (resolve) {
        setTimeout(function () {
            self._playPending = null;
            if (v.srcObject && v.readyState === 0) v.load();
            var playTimeout = setTimeout(function () {
                resolve({ ok: false, error: 'play-timeout' });
            }, 4000);
            v.play().then(function () {
                clearTimeout(playTimeout);
                resolve({ ok: true, error: '' });
            }).catch(function (e) {
                clearTimeout(playTimeout);
                resolve({ ok: false, error: e.name || 'blocked' });
            });
        }, 80);
    });
    return this._playPending;
};

WebKitAdapter.prototype.supportsNativeHLS = function () {
    return true;
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
