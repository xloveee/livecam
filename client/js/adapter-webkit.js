/* adapter-webkit.js — WebKit adapter (Safari, DuckDuckGo iOS)
 *
 * WebKit handles remote MediaStreams differently from Chromium:
 *   - event.streams[0] is the reliable way to get the remote stream
 *   - Manual new MediaStream() + addTrack() can lose the stream binding
 *     after ICE restarts or track renegotiation on WebKit
 *   - Native HLS is supported (no hls.js needed)
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

WebKitAdapter.prototype.onTrack = function (event) {
    if (event.streams && event.streams[0]) {
        this.video.srcObject = event.streams[0];
    } else {
        WatchAdapter.prototype.onTrack.call(this, event);
    }
    return event.track.kind;
};

WebKitAdapter.prototype.supportsNativeHLS = function () {
    return true;
};

WebKitAdapter.prototype.startHLS = function (url) {
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
