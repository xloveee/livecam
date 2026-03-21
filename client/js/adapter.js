/* adapter.js — Thin media adapter between watch-core.js and the browser.
 *
 * The Rust SFU enforces the codec whitelist (H.264 + VP8 + Opus) via
 * RtcConfig::clear_codecs(). All SDP answers only contain those codecs,
 * so no client-side codec preference is needed.
 *
 * The only real browser difference is HLS delivery:
 *   - WebKit/iOS: native <video src="…m3u8"> (no library)
 *   - Chromium:   hls.js
 */

(function () {
    var video = document.getElementById('player');
    var nativeHLS = !!video.canPlayType('application/vnd.apple.mpegurl');

    var adapter = {
        name: nativeHLS ? 'native-hls' : 'chromium',
        video: video,
        hlsPlayer: null,
        hlsActive: false,

        canWebRTC: function () {
            return typeof RTCPeerConnection !== 'undefined';
        },

        createPC: function (iceServers) {
            return new RTCPeerConnection({ iceServers: iceServers });
        },

        setupTransceivers: function (pc) {
            pc.addTransceiver('video', { direction: 'recvonly' });
            pc.addTransceiver('audio', { direction: 'recvonly' });
        },

        onTrack: function (event) {
            var stream = video.srcObject;
            if (!(stream instanceof MediaStream)) {
                stream = new MediaStream();
                video.srcObject = stream;
            }
            stream.addTrack(event.track);
            return event.track.kind;
        },

        play: function () {
            return video.play().then(function () {
                return { ok: true, error: '' };
            }).catch(function (e) {
                return { ok: false, error: e.name || 'blocked' };
            });
        },

        teardownVideo: function () {
            adapter.stopHLS();
            video.srcObject = null;
            video.removeAttribute('src');
        },

        startHLS: function (url) {
            if (nativeHLS) {
                video.src = url;
                video.play().catch(function () {});
                adapter.hlsActive = true;
                return true;
            }
            if (typeof Hls !== 'undefined' && Hls.isSupported()) {
                adapter.hlsPlayer = new Hls({ enableWorker: true, lowLatencyMode: true });
                adapter.hlsPlayer.loadSource(url);
                adapter.hlsPlayer.attachMedia(video);
                adapter.hlsPlayer.on(Hls.Events.MANIFEST_PARSED, function () {
                    video.play().catch(function () {});
                });
                adapter.hlsActive = true;
                return true;
            }
            return false;
        },

        stopHLS: function () {
            if (adapter.hlsPlayer) { adapter.hlsPlayer.destroy(); adapter.hlsPlayer = null; }
            if (nativeHLS && adapter.hlsActive) {
                video.removeAttribute('src');
                video.load();
            }
            adapter.hlsActive = false;
        },

        onHLSError: function (callback) {
            if (adapter.hlsPlayer) {
                adapter.hlsPlayer.on(Hls.Events.ERROR, function (ev, data) {
                    if (data.fatal) callback();
                });
            }
            if (nativeHLS && adapter.hlsActive) {
                video.addEventListener('error', function onErr() {
                    video.removeEventListener('error', onErr);
                    callback();
                });
            }
        }
    };

    window.watchAdapter = adapter;
})();
