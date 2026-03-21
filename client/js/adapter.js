/* adapter.js — Base WatchAdapter (Chromium default)
 *
 * To add a new browser:
 *   1. Create adapter-<name>.js extending WatchAdapter
 *   2. Add <script> in watch.html before adapter-detect.js
 *   3. Add UA condition in adapter-detect.js
 */

function WatchAdapter(videoEl) {
    this.video = videoEl;
    this.hlsPlayer = null;
    this.hlsActive = false;
}

WatchAdapter.prototype.name = 'chromium';

WatchAdapter.prototype.canWebRTC = function () {
    return typeof RTCPeerConnection !== 'undefined';
};

WatchAdapter.prototype.createPC = function (iceServers) {
    return new RTCPeerConnection({ iceServers: iceServers });
};

WatchAdapter.prototype.setupTransceivers = function (pc) {
    pc.addTransceiver('video', { direction: 'recvonly' });
    pc.addTransceiver('audio', { direction: 'recvonly' });
};

WatchAdapter.prototype.onTrack = function (event) {
    var stream = this.video.srcObject;
    if (!(stream instanceof MediaStream)) {
        stream = new MediaStream();
        this.video.srcObject = stream;
    }
    stream.addTrack(event.track);
    return event.track.kind;
};

WatchAdapter.prototype.play = function () {
    return this.video.play().then(function () {
        return { ok: true, error: '' };
    }).catch(function (e) {
        return { ok: false, error: e.name || 'blocked' };
    });
};

WatchAdapter.prototype.teardownVideo = function () {
    this.stopHLS();
    this.video.srcObject = null;
    this.video.removeAttribute('src');
};

WatchAdapter.prototype.startHLS = function (url) {
    if (typeof Hls !== 'undefined' && Hls.isSupported()) {
        this.hlsPlayer = new Hls({ enableWorker: true, lowLatencyMode: true });
        this.hlsPlayer.loadSource(url);
        this.hlsPlayer.attachMedia(this.video);
        var self = this;
        this.hlsPlayer.on(Hls.Events.MANIFEST_PARSED, function () {
            self.video.play().catch(function () {});
        });
        this.hlsActive = true;
        return true;
    }
    return false;
};

WatchAdapter.prototype.stopHLS = function () {
    if (this.hlsPlayer) { this.hlsPlayer.destroy(); this.hlsPlayer = null; }
    this.hlsActive = false;
};

WatchAdapter.prototype.onHLSError = function (callback) {
    if (this.hlsPlayer) {
        this.hlsPlayer.on(Hls.Events.ERROR, function (ev, data) {
            if (data.fatal) callback();
        });
    }
};
