/* watch-core.js — viewer state machine, WebRTC, polling, media adapter
 *
 * The Rust SFU enforces the codec whitelist (H.264 + VP8 + Opus) via
 * RtcConfig::clear_codecs(). The SFU drives quality adaptation via
 * MediaEgressStats. Room state is pushed over the chat WebSocket.
 *
 * Playback: assign remote tracks to video.srcObject in onTrack (one MediaStream).
 * Do not call video.play() from JS — the page uses native <video controls> so the
 * user starts playback with an explicit gesture (required on iOS / many WebViews).
 *
 * iOS / iPadOS: many in-app browsers (WKWebView) decode WebRTC video poorly; when
 * native HLS is available we watch via /hls/.../master.m3u8 instead of WHEP.
 * Broadcasting (WHIP) is unchanged — only the viewer path differs.
 */

var video       = document.getElementById('player');
var qualitySelect = document.getElementById('quality-select');
var statusEl    = document.getElementById('status');
var viewerCountEl = document.getElementById('viewer-count');
var offlineBanner = document.getElementById('offline-banner');
var offlineText = document.getElementById('offline-text');
var passwordPrompt = document.getElementById('password-prompt');
var passwordInput  = document.getElementById('room-password-input');
var btnPasswordSubmit = document.getElementById('btn-password-submit');
var passwordError  = document.getElementById('password-error');

var roomId = null;
var roomIdFromURL = false;
var sessionId = null;
var roomPassword = '';
var pc = null;
var pollInterval = null;
var lastBytesReceived = 0;
var stallCount = 0;
var webrtcFailCount = 0;
var connectTimeout = null;
var viewerState = 'init';

/** Custom line from broadcaster (GET /api/room_info → offline_banner); empty → default copy */
var offlineBannerCustom = '';

var decodeBanner = document.getElementById('decode-banner');
var decodeCheckInterval = null;
var decodeStallTicks = 0;

/* ── Media Adapter ─────────────────────────────────────── */

var nativeHLS = !!video.canPlayType('application/vnd.apple.mpegurl');

function isIosLikeDevice() {
    var ua = navigator.userAgent || '';
    if (/iPad|iPhone|iPod/.test(ua)) {
        return true;
    }
    if (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1) {
        return true;
    }
    return false;
}

function shouldPreferHlsViewer() {
    return nativeHLS && isIosLikeDevice();
}

/** Desktop/mobile Firefox (not Chrome). Used for WebRTC interop workarounds. */
function isFirefoxBrowser() {
    if (typeof navigator === 'undefined') {
        return false;
    }
    var ua = navigator.userAgent || '';
    if (/Firefox\//.test(ua) || /FxiOS\//.test(ua)) {
        return true;
    }
    return false;
}

var watchAdapter = {
    name: nativeHLS ? 'native-hls' : (isFirefoxBrowser() ? 'firefox' : 'chromium'),
    hlsPlayer: null,
    hlsActive: false,

    canWebRTC: function () {
        return typeof RTCPeerConnection !== 'undefined';
    },

    createPC: function (iceServers) {
        var base = {
            iceServers: iceServers || [],
            bundlePolicy: 'max-bundle',
            rtcpMuxPolicy: 'require'
        };
        /* Pool size can throw or behave oddly on some Firefox builds; fall back without it. */
        try {
            return new RTCPeerConnection(Object.assign({}, base, { iceCandidatePoolSize: 10 }));
        } catch (e) {
            try {
                return new RTCPeerConnection(base);
            } catch (e2) {
                throw e2;
            }
        }
    },

    setupTransceivers: function (pc) {
        pc.addTransceiver('video', { direction: 'recvonly' });
        pc.addTransceiver('audio', { direction: 'recvonly' });
    },

    onTrack: function (event) {
        var stream = video.srcObject instanceof MediaStream ? video.srcObject : new MediaStream();
        stream.addTrack(event.track);
        video.srcObject = stream;
        return event.track.kind;
    },

    teardownVideo: function () {
        watchAdapter.stopHLS();
        video.srcObject = null;
    },

    startHLS: function (url) {
        if (nativeHLS) {
            video.src = url;
            watchAdapter.hlsActive = true;
            return true;
        }
        if (typeof Hls !== 'undefined' && Hls.isSupported()) {
            watchAdapter.hlsPlayer = new Hls({ enableWorker: true, lowLatencyMode: true });
            watchAdapter.hlsPlayer.loadSource(url);
            watchAdapter.hlsPlayer.attachMedia(video);
            watchAdapter.hlsActive = true;
            return true;
        }
        return false;
    },

    stopHLS: function () {
        if (watchAdapter.hlsPlayer) { watchAdapter.hlsPlayer.destroy(); watchAdapter.hlsPlayer = null; }
        if (nativeHLS && watchAdapter.hlsActive) {
            video.removeAttribute('src');
            video.load();
        }
        watchAdapter.hlsActive = false;
    },

    onHLSError: function (callback) {
        if (watchAdapter.hlsPlayer) {
            watchAdapter.hlsPlayer.on(Hls.Events.ERROR, function (ev, data) {
                if (data.fatal) callback();
            });
        }
        if (nativeHLS && watchAdapter.hlsActive) {
            video.addEventListener('error', function onErr() {
                video.removeEventListener('error', onErr);
                callback();
            });
        }
    }
};

/** Match letterboxing to frame; set portrait/landscape for CSS that prioritizes stream area. */
var lastStreamLayoutSig = '';
function syncVideoAspectAndStreamLayout() {
    if (video.videoWidth && video.videoHeight) {
        video.style.aspectRatio = video.videoWidth + '/' + video.videoHeight;
    }
    var w = video.videoWidth;
    var h = video.videoHeight;
    if (w && h) {
        document.body.classList.toggle('watch-stream-portrait', h > w);
        document.body.classList.toggle('watch-stream-landscape', h <= w);
        var sig = w + 'x' + h;
        if (sig !== lastStreamLayoutSig) {
            lastStreamLayoutSig = sig;
            requestAnimationFrame(function () {
                window.dispatchEvent(new Event('resize'));
            });
        }
    }
    requestAnimationFrame(function () {
        if (typeof window.livecamSyncMobileChatFromPlayer === 'function') {
            window.livecamSyncMobileChatFromPlayer();
        }
    });
}

video.addEventListener('resize', syncVideoAspectAndStreamLayout);
video.addEventListener('loadedmetadata', syncVideoAspectAndStreamLayout);
video.addEventListener('emptied', function () {
    lastStreamLayoutSig = '';
    document.body.classList.remove('watch-stream-portrait', 'watch-stream-landscape');
    video.style.aspectRatio = '';
});

video.addEventListener('playing', function () {
    debugPlayResult = 'ok';
    debugEvent('play:ok');
});

/* Phone: keep stream column scrolled to playback top (avoid snap / layout landing on panels). */
function resetWatchStreamColumnToTop() {
    var col = document.querySelector('main.stream-column');
    if (!col || !window.matchMedia('(max-width: 900px)').matches) {
        return;
    }
    col.scrollTop = 0;
}

function scheduleResetWatchStreamColumnToTop() {
    resetWatchStreamColumnToTop();
    requestAnimationFrame(function () {
        resetWatchStreamColumnToTop();
        requestAnimationFrame(resetWatchStreamColumnToTop);
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleResetWatchStreamColumnToTop);
} else {
    scheduleResetWatchStreamColumnToTop();
}

/* ── State Machine ──────────────────────────────────────── */

function setState(next) {
    if (next === viewerState) return;
    viewerState = next;
    debugEvent('state:' + next);
    renderState();
    managePoll();
}

function applyOfflineBannerFromInfo(info) {
    if (info && typeof info.offline_banner === 'string') {
        offlineBannerCustom = info.offline_banner;
    }
}

function offlineBannerDisplayLine() {
    var t = (offlineBannerCustom || '').trim();
    return t.length ? t : 'No broadcast right now';
}

function renderState() {
    passwordPrompt.style.display = 'none';
    statusEl.classList.remove('error');
    document.body.classList.remove('watch-header-offline-msg');

    switch (viewerState) {
        case 'offline':
            offlineBanner.classList.remove('live');
            offlineText.textContent = offlineBannerDisplayLine();
            document.body.classList.add('watch-header-offline-msg');
            statusEl.textContent = 'Offline';
            viewerCountEl.textContent = '';
            qualitySelect.disabled = true;
            disableChat();
            break;
        case 'need_password':
            passwordPrompt.style.display = 'flex';
            offlineBanner.classList.remove('live');
            statusEl.textContent = 'Password required';
            qualitySelect.disabled = true;
            disableChat();
            break;
        case 'connecting':
            offlineBanner.classList.remove('live');
            statusEl.textContent = 'Connecting...';
            qualitySelect.disabled = true;
            break;
        case 'live':
            offlineBanner.classList.add('live');
            statusEl.textContent = 'Live';
            qualitySelect.disabled = false;
            enableChat();
            break;
        case 'room_full':
            offlineBanner.classList.remove('live');
            offlineText.textContent = 'Room is full — retrying...';
            document.body.classList.add('watch-header-offline-msg');
            statusEl.textContent = 'Waiting';
            qualitySelect.disabled = true;
            disableChat();
            break;
        case 'rate_limited':
            offlineBanner.classList.remove('live');
            offlineText.textContent = 'Too many requests — retrying...';
            document.body.classList.add('watch-header-offline-msg');
            statusEl.textContent = 'Waiting';
            qualitySelect.disabled = true;
            disableChat();
            break;
        default:
            break;
    }
}

function clearPollTimer() {
    if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
}

function managePoll() {
    clearPollTimer();
    if (viewerState === 'room_full' || viewerState === 'rate_limited') {
        pollInterval = setInterval(function () { connectViewer(); }, 5000);
    } else if (viewerState === 'offline' || viewerState === 'need_password') {
        pollInterval = setInterval(pollActive, 5000);
    }
}

async function pollActive() {
    try {
        if (roomIdFromURL && roomId) {
            var infoResp = await fetch('/api/room_info/' + roomId);
            if (!infoResp.ok) return;
            var info = await infoResp.json();
            applyOfflineBannerFromInfo(info);

            if (!info.is_live) {
                setState('offline');
                return;
            }
            if (info.has_password && !roomPassword) {
                setState('need_password');
            } else {
                connectViewer();
            }
            return;
        }

        var resp = await fetch('/api/active');
        if (!resp.ok) return;
        var data = await resp.json();

        if (!data.room_id) {
            setState('offline');
            return;
        }

        roomId = data.room_id;

        if (data.has_password && !roomPassword) {
            setState('need_password');
        } else {
            if (!data.has_password) { roomPassword = ''; passwordInput.value = ''; }
            connectViewer();
        }
    } catch (e) { /* ignore */ }
}

/* ── Utilities ──────────────────────────────────────────── */

function getRoomIdFromURL() {
    var parts = window.location.pathname.split('/').filter(Boolean);
    if (parts.length >= 2 && parts[0] === 'watch') {
        return parts[1];
    }
    return null;
}

async function fetchICEConfig() {
    try {
        var resp = await fetch('/api/config');
        if (!resp.ok) return {};
        return await resp.json();
    } catch (e) {
        return { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
    }
}

async function setQuality(rid) {
    if (!sessionId || !roomId) return;
    try {
        await fetch('/api/quality/' + roomId, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Session-Id': sessionId
            },
            body: JSON.stringify({ rid: rid || null })
        });
    } catch (e) { /* ignore */ }
}

qualitySelect.onchange = function () { setQuality(qualitySelect.value || null); };

/* ── WHEP receiver codec prefs (match OBS + VP8 publishers) ───────────────── */

function getRecvonlyVideoTransceiver(pc) {
    var trs = pc.getTransceivers();
    var i;
    for (i = 0; i < trs.length; i++) {
        var tr = trs[i];
        if (tr && tr.receiver && tr.receiver.track && tr.receiver.track.kind === 'video') {
            return tr;
        }
    }
    /* Before remote tracks arrive, recvonly order matches addTransceiver order (video first). */
    return trs.length ? trs[0] : null;
}

function applyViewerVideoCodecPreferences(pc) {
    /* Firefox: setCodecPreferences often breaks WHEP offer/answer pairing with SFUs; use default codec order. */
    if (isFirefoxBrowser()) {
        debugEvent('codec-prefs:skipped-firefox');
        return;
    }
    try {
        if (typeof RTCRtpReceiver === 'undefined' || !RTCRtpReceiver.getCapabilities) return;
        var caps = RTCRtpReceiver.getCapabilities('video');
        var h264 = caps.codecs.filter(function (c) { return c.mimeType.toLowerCase() === 'video/h264'; });
        var vp8 = caps.codecs.filter(function (c) { return c.mimeType.toLowerCase() === 'video/vp8'; });
        var rest = caps.codecs.filter(function (c) {
            var m = c.mimeType.toLowerCase();
            return m !== 'video/h264' && m !== 'video/vp8';
        });
        var vtr = getRecvonlyVideoTransceiver(pc);
        if (vtr) {
            if (h264.length) {
                vtr.setCodecPreferences(h264.concat(vp8).concat(rest));
            } else if (vp8.length) {
                vtr.setCodecPreferences(vp8.concat(rest));
            }
        }
    } catch (e) {
        debugEvent('codec-prefs:error');
    }
}

function clearDecodeCheck() {
    if (decodeCheckInterval) { clearInterval(decodeCheckInterval); decodeCheckInterval = null; }
    decodeStallTicks = 0;
    if (decodeBanner) decodeBanner.style.display = 'none';
}

/** RTP arrives but WebKit does not decode (e.g. H.264 profile) — see README Video codec policy. */
function startDecodeCheck() {
    clearDecodeCheck();
    if (!decodeBanner) return;
    decodeCheckInterval = setInterval(function () {
        if (!pc || viewerState !== 'live') {
            clearDecodeCheck();
            return;
        }
        pc.getStats(null).then(function (stats) {
            var inbound = null;
            stats.forEach(function (r) {
                if (r.type !== 'inbound-rtp') return;
                var isVid = r.kind === 'video' || r.mediaType === 'video';
                if (!isVid && r.mimeType && String(r.mimeType).indexOf('video') === 0) isVid = true;
                if (isVid) inbound = r;
            });
            if (!inbound) return;
            var bytes = inbound.bytesReceived || 0;
            var fd = inbound.framesDecoded;
            var frames = fd === undefined ? 0 : fd;
            if (bytes > 80000 && frames === 0) {
                decodeStallTicks++;
                if (decodeStallTicks >= 3) decodeBanner.style.display = 'block';
            } else {
                decodeStallTicks = 0;
                if (frames > 0) decodeBanner.style.display = 'none';
            }
        }).catch(function () {});
    }, 2000);
}

/* ── WebRTC Lifecycle ───────────────────────────────────── */

function teardownConnection() {
    debugEvent('teardown');
    debugPlayResult = '';
    clearPollTimer();
    clearDecodeCheck();
    if (connectTimeout) { clearTimeout(connectTimeout); connectTimeout = null; }
    stopStatsLoop();
    if (pc) {
        if (sessionId && roomId) {
            fetch('/api/whep/' + roomId, {
                method: 'DELETE',
                headers: { 'X-Session-Id': sessionId }
            }).catch(function () {});
        }
        var dying = pc;
        pc = null;
        dying.oniceconnectionstatechange = null;
        dying.onconnectionstatechange = null;
        dying.close();
    }
    watchAdapter.teardownVideo();
    video.style.aspectRatio = '';
    sessionId = null;
    lastBytesReceived = 0;
    stallCount = 0;
    qualitySelect.value = '';
}

function onPeerStateChange() {
    if (!pc) return;
    var s = pc.iceConnectionState;
    var conn = pc.connectionState;
    debugEvent('ice:' + s);
    if (s === 'connected' || s === 'completed' || conn === 'connected') {
        if (connectTimeout) { clearTimeout(connectTimeout); connectTimeout = null; }
        setState('live');
        startStatsLoop();
        startDecodeCheck();
    } else if (s === 'disconnected' || s === 'failed' || s === 'closed') {
        teardownConnection();
        setState('offline');
    }
}

/**
 * Entry point for playback. On iOS Safari family, use native HLS when the packager
 * exposes a manifest (reliable); otherwise WHEP. Pass forceWebRtc to skip HLS (e.g. “Back to real-time”).
 */
async function connectViewer(forceWebRtc) {
    if (!roomId) return;
    if (viewerState === 'connecting') return;
    if (!forceWebRtc && shouldPreferHlsViewer()) {
        try {
            var head = await fetch('/hls/' + roomId + '/master.m3u8', { method: 'HEAD' });
            if (head.ok) {
                debugEvent('viewer:hls-native-ios');
                switchToHLS();
                return;
            }
        } catch (e) {
            debugEvent('viewer:hls-head-fail');
        }
    }
    await connectWHEP();
}

async function connectWHEP() {
    if (!roomId) return;
    if (viewerState === 'connecting') return;
    if (!watchAdapter.canWebRTC()) {
        debugEvent('no-webrtc:' + watchAdapter.name);
        switchToHLS();
        return;
    }

    teardownConnection();
    setState('connecting');

    var config = await fetchICEConfig();

    pc = watchAdapter.createPC(config.iceServers || []);

    pc.ontrack = function (event) {
        var kind = watchAdapter.onTrack(event);
        debugEvent('track:' + kind + ' ' + event.track.readyState);
    };

    pc.oniceconnectionstatechange = onPeerStateChange;
    pc.onconnectionstatechange = onPeerStateChange;

    watchAdapter.setupTransceivers(pc);
    applyViewerVideoCodecPreferences(pc);

    try {
        var offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        var headers = { 'Content-Type': 'application/sdp' };
        if (roomPassword) {
            headers['X-Room-Password'] = roomPassword;
        }

        debugEvent('whep-fetch');
        var response = await fetch('/api/whep/' + roomId, {
            method: 'POST',
            headers: headers,
            body: pc.localDescription.sdp
        });
        debugEvent('whep:' + response.status);

        if (response.status === 404) {
            teardownConnection();
            setState('offline');
            return;
        }
        if (response.status === 403) {
            teardownConnection();
            passwordError.textContent = roomPassword ? 'Incorrect password' : '';
            setState('need_password');
            return;
        }
        if (response.status === 503) {
            teardownConnection();
            fetch('/hls/' + roomId + '/master.m3u8', { method: 'HEAD' })
                .then(function (r) {
                    if (r.ok) {
                        switchToHLS();
                    } else {
                        setState('room_full');
                    }
                })
                .catch(function () { setState('room_full'); });
            return;
        }
        if (response.status === 429) {
            teardownConnection();
            setState('rate_limited');
            return;
        }
        if (!response.ok) {
            throw new Error('Server returned ' + response.status);
        }

        sessionId = response.headers.get('X-Session-Id');
        var answerSdp = await response.text();
        await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp });
        debugEvent('sdp-applied');

        connectTimeout = setTimeout(function () {
            if (viewerState === 'connecting') {
                teardownConnection();
                setState('offline');
            }
        }, 10000);

    } catch (err) {
        console.error('WHEP connection failed:', err);
        teardownConnection();
        setState('offline');
    }
}

/* ── User Actions ───────────────────────────────────────── */

btnPasswordSubmit.onclick = function () {
    roomPassword = passwordInput.value;
    if (!roomPassword) {
        passwordError.textContent = 'Please enter a password';
        return;
    }
    passwordError.textContent = '';
    connectViewer();
};

passwordInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') btnPasswordSubmit.click();
});

/* ── Room State Push (via chat WebSocket) ──────────────── */

window.onRoomState = function (state) {
    if (viewerState !== 'live') return;
    if (state.is_live === false) {
        teardownConnection();
        if (roomId) {
            fetch('/api/room_info/' + roomId)
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (info) {
                    if (info) applyOfflineBannerFromInfo(info);
                    setState('offline');
                })
                .catch(function () { setState('offline'); });
        } else {
            setState('offline');
        }
        return;
    }
    if (state.has_password === true && !roomPassword) {
        teardownConnection();
        setState('need_password');
        return;
    }
    if (state.has_password === false && roomPassword) {
        roomPassword = '';
        passwordInput.value = '';
    }
    if (state.viewer_count !== undefined && state.viewer_count !== null) {
        viewerCountEl.textContent = state.viewer_count + ' watching';
    }
};

/* ── Stats Loop (stall detection + debug) ──────────────── */
/*
 * Single interval collects stats once per second. Feeds:
 *   - Media watchdog (stall detection)
 *   - Debug overlay (when ?debug=1)
 */

var statsInterval = null;
var statsTick = 0;

var debugEnabled = /[?&]debug=1/.test(window.location.search);
var debugOverlay = document.getElementById('debug-overlay');
var debugContent = document.getElementById('debug-content');
if (debugEnabled && debugOverlay) {
    debugOverlay.classList.add('visible');
    var debugTitle = debugOverlay.querySelector('.debug-title');
    if (debugTitle) {
        debugTitle.addEventListener('click', function () {
            debugOverlay.classList.toggle('collapsed');
        });
    }
}

var debugTimeline = [];
var debugPlayResult = '';

function debugEvent(label) {
    if (!debugEnabled) return;
    var now = new Date();
    var h = now.getHours(), m = now.getMinutes(), s = now.getSeconds(), ms = now.getMilliseconds();
    var ts = (h < 10 ? '0' : '') + h + ':' +
             (m < 10 ? '0' : '') + m + ':' +
             (s < 10 ? '0' : '') + s + '.' +
             (ms < 100 ? (ms < 10 ? '00' : '0') : '') + ms;
    debugTimeline.push({ ts: ts, label: label });
    if (debugTimeline.length > 30) debugTimeline.shift();
}

if (debugEnabled) {
    setInterval(function () {
        if (!statsInterval) {
            renderDebug({ state: viewerState, iceState: pc ? pc.iceConnectionState : 'no pc' });
        }
    }, 1000);
}

var degradeBanner = document.getElementById('degrade-banner');
var degradeText = document.getElementById('degrade-text');
var hlsBanner = document.getElementById('hls-banner');

var prevVideoBytes = 0;
var prevAudioBytes = 0;
var prevTs = 0;
var prevPackets = 0;
var prevLost = 0;

function startStatsLoop() {
    stopStatsLoop();
    lastBytesReceived = 0;
    stallCount = 0;
    prevVideoBytes = 0;
    prevAudioBytes = 0;
    prevTs = 0;
    prevPackets = 0;
    prevLost = 0;
    statsTick = 0;

    statsInterval = setInterval(async function () {
        if (!pc) {
            if (debugEnabled) renderDebug({ state: viewerState, note: 'No peer connection' });
            return;
        }

        var stats;
        try { stats = await pc.getStats(); } catch (e) { return; }
        statsTick++;

        /* ── Watchdog: detect stalled media ── */
        var totalBytes = 0;
        stats.forEach(function (r) {
            if (r.type === 'inbound-rtp') totalBytes += r.bytesReceived || 0;
        });
        if (totalBytes > lastBytesReceived) {
            lastBytesReceived = totalBytes;
            stallCount = 0;
            if (statsTick > 15) { webrtcFailCount = 0; }
        } else {
            stallCount++;
            if (stallCount >= 3) {
                webrtcFailCount++;
                teardownConnection();
                if (webrtcFailCount >= 2) {
                    tryHLSFallback();
                } else {
                    setState('offline');
                }
                return;
            }
        }

        if (!debugEnabled) return;

        /* ── Full stats parsing (debug only) ── */
        var d = {
            state: viewerState,
            iceState: pc.iceConnectionState,
            videoBitrateKbps: 0, audioBitrateKbps: 0,
            videoRes: '', videoFps: 0, videoCodec: '',
            framesDecoded: 0, framesDropped: 0,
            videoJitterMs: 0, videoLossPct: 0,
            videoNack: 0, videoPli: 0, videoFir: 0,
            audioJitterMs: 0, rttMs: 0,
            localCandidate: '', remoteCandidate: '',
            jitterBufferMs: 0, stallCount: stallCount
        };

        var candidateMap = {};
        stats.forEach(function (r) {
            if (r.type === 'local-candidate' || r.type === 'remote-candidate') {
                candidateMap[r.id] = (r.candidateType || '') + ' ' + (r.protocol || '') + ' ' + (r.address || '') + ':' + (r.port || '');
            }
        });

        stats.forEach(function (r) {
            if (r.type === 'inbound-rtp' && r.kind === 'video') {
                if (prevTs > 0) {
                    var dt = (r.timestamp - prevTs) / 1000;
                    if (dt > 0) {
                        d.videoBitrateKbps = ((r.bytesReceived - prevVideoBytes) * 8) / dt / 1000;
                    }
                    var pktDelta = (r.packetsReceived || 0) - prevPackets;
                    var lostDelta = (r.packetsLost || 0) - prevLost;
                    if (pktDelta + lostDelta > 0) {
                        d.videoLossPct = (lostDelta / (pktDelta + lostDelta)) * 100;
                    }
                }
                prevVideoBytes = r.bytesReceived || 0;
                prevTs = r.timestamp;
                prevPackets = r.packetsReceived || 0;
                prevLost = r.packetsLost || 0;

                if (r.frameWidth) d.videoRes = r.frameWidth + 'x' + r.frameHeight;
                d.videoFps = r.framesPerSecond || 0;
                d.framesDecoded = r.framesDecoded || 0;
                d.framesDropped = r.framesDropped || 0;
                d.videoJitterMs = (r.jitter || 0) * 1000;
                d.videoNack = r.nackCount || 0;
                d.videoPli = r.pliCount || 0;
                d.videoFir = r.firCount || 0;
                if (r.jitterBufferDelay && r.jitterBufferEmittedCount) {
                    d.jitterBufferMs = (r.jitterBufferDelay / r.jitterBufferEmittedCount) * 1000;
                }
            }
            if (r.type === 'inbound-rtp' && r.kind === 'audio') {
                if (prevTs > 0 && r.bytesReceived) {
                    var dt = (r.timestamp - prevTs) / 1000;
                    if (dt > 0) {
                        d.audioBitrateKbps = ((r.bytesReceived - prevAudioBytes) * 8) / dt / 1000;
                    }
                }
                prevAudioBytes = r.bytesReceived || 0;
                d.audioJitterMs = (r.jitter || 0) * 1000;
            }
            if (r.type === 'candidate-pair' && r.state === 'succeeded') {
                if (r.currentRoundTripTime) d.rttMs = r.currentRoundTripTime * 1000;
                d.localCandidate = candidateMap[r.localCandidateId] || '';
                d.remoteCandidate = candidateMap[r.remoteCandidateId] || '';
            }
        });

        stats.forEach(function (r) {
            if (r.type === 'codec' && r.mimeType && r.mimeType.indexOf('video') === 0) {
                d.videoCodec = r.mimeType.replace('video/', '');
            }
        });

        renderDebug(d);
    }, 2000);
}

function stopStatsLoop() {
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
}

/* ── HLS Fallback ───────────────────────────────────────── */

var hlsJsLoading = false;

function ensureHlsJs(callback) {
    if (nativeHLS || typeof Hls !== 'undefined') { callback(); return; }
    if (hlsJsLoading) {
        var poll = setInterval(function () {
            if (typeof Hls !== 'undefined') { clearInterval(poll); callback(); }
        }, 50);
        setTimeout(function () { clearInterval(poll); callback(); }, 8000);
        return;
    }
    hlsJsLoading = true;
    var s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js';
    s.onload = function () { callback(); };
    s.onerror = function () { callback(); };
    document.head.appendChild(s);
}

function checkHLSAvailable() {
    if (!roomId || !hlsBanner) return;
    fetch('/hls/' + roomId + '/master.m3u8', { method: 'HEAD' })
        .then(function (r) {
            if (r.ok) hlsBanner.style.display = 'block';
        })
        .catch(function () {});
}

function tryHLSFallback() {
    if (!roomId) { setState('offline'); return; }
    debugEvent('hls-fallback:webrtcFails=' + webrtcFailCount);
    fetch('/hls/' + roomId + '/master.m3u8', { method: 'HEAD' })
        .then(function (r) {
            if (r.ok) { switchToHLS(); }
            else { setState('offline'); }
        })
        .catch(function () { setState('offline'); });
}

function switchToHLS() {
    if (!roomId) return;
    teardownConnection();
    qualitySelect.disabled = true;

    ensureHlsJs(function () {
        var hlsUrl = '/hls/' + roomId + '/master.m3u8';
        var started = watchAdapter.startHLS(hlsUrl);
        if (started) {
            watchAdapter.onHLSError(function () {
                teardownConnection();
                setState('offline');
            });
            onHLSPlaying();
        } else {
            statusEl.textContent = 'HLS not supported in this browser';
            statusEl.classList.add('error');
        }
    });
}

function onHLSPlaying() {
    setState('live');
    statusEl.textContent = 'Live (HLS)';
    if (degradeBanner) {
        degradeText.textContent = 'Switched to stable playback (HLS). Latency is higher (~5s).';
        if (hlsBanner) hlsBanner.style.display = 'none';
    }
}

function switchToWebRTC() {
    webrtcFailCount = 0;
    if (degradeBanner) degradeBanner.style.display = 'none';
    if (hlsBanner) hlsBanner.style.display = 'none';
    connectViewer(true);
}

/* ── Debug Overlay (?debug=1) ───────────────────────────── */

function renderDebug(d) {
    if (!debugContent) return;
    var html = '';

    html += section('STATE', [
        row('Viewer', d.state || '—'),
        row('ICE', d.iceState || '—', colorIce(d.iceState)),
        row('Adapter', watchAdapter.name, 'good'),
        row('Stall count', d.stallCount != null ? d.stallCount : '—'),
        row('Quality', qualitySelect.value || 'auto (server)'),
        row('Room', roomId || '—'),
        row('Session', sessionId ? sessionId.substring(0, 12) + '…' : '—')
    ]);

    if (d.videoBitrateKbps !== undefined) {
        var dropRate = d.framesDecoded > 0 ? ((d.framesDropped / (d.framesDecoded + d.framesDropped)) * 100) : 0;
        html += section('VIDEO (inbound)', [
            row('Resolution', d.videoRes || '—'),
            row('FPS', d.videoFps ? d.videoFps.toFixed(0) : '—', d.videoFps > 60 ? 'bad' : d.videoFps < 15 ? 'bad' : d.videoFps < 24 ? 'warn' : 'good'),
            row('Bitrate', d.videoBitrateKbps ? d.videoBitrateKbps.toFixed(0) + ' kbps' : '—', d.videoBitrateKbps < 300 ? 'bad' : d.videoBitrateKbps < 800 ? 'warn' : ''),
            row('Codec', d.videoCodec || '—'),
            row('Jitter', d.videoJitterMs ? d.videoJitterMs.toFixed(1) + ' ms' : '0 ms', d.videoJitterMs > 30 ? 'bad' : d.videoJitterMs > 15 ? 'warn' : ''),
            row('Pkt loss', d.videoLossPct ? d.videoLossPct.toFixed(1) + '%' : '0%', d.videoLossPct > 3 ? 'bad' : d.videoLossPct > 1 ? 'warn' : ''),
            row('Decoded', d.framesDecoded || 0),
            row('Dropped', d.framesDropped || 0, d.framesDropped > 0 ? (dropRate > 2 ? 'bad' : 'warn') : ''),
            row('NACK/PLI/FIR', d.videoNack + ' / ' + d.videoPli + ' / ' + d.videoFir),
            row('Jitter buf', d.jitterBufferMs ? d.jitterBufferMs.toFixed(0) + ' ms' : '—')
        ]);
    }

    if (d.audioBitrateKbps !== undefined) {
        html += section('AUDIO (inbound)', [
            row('Bitrate', d.audioBitrateKbps ? d.audioBitrateKbps.toFixed(0) + ' kbps' : '—'),
            row('Jitter', d.audioJitterMs ? d.audioJitterMs.toFixed(1) + ' ms' : '0 ms', d.audioJitterMs > 30 ? 'warn' : '')
        ]);
    }

    html += section('CONNECTION', [
        row('RTT', d.rttMs ? d.rttMs.toFixed(0) + ' ms' : '—', d.rttMs > 200 ? 'bad' : d.rttMs > 80 ? 'warn' : d.rttMs ? 'good' : ''),
        row('Local', d.localCandidate || '—'),
        row('Remote', d.remoteCandidate || '—')
    ]);

    var readyNames = ['NOTHING', 'METADATA', 'CURRENT', 'FUTURE', 'ENOUGH'];
    var netNames = ['EMPTY', 'IDLE', 'LOADING', 'NO_SRC'];
    var trackInfo = '—';
    if (video.srcObject && video.srcObject.getTracks) {
        var tracks = video.srcObject.getTracks();
        if (tracks.length) {
            trackInfo = tracks.map(function (t) {
                return t.kind[0].toUpperCase() + ':' + t.readyState + (t.muted ? '(m)' : '');
            }).join(' ');
        } else {
            trackInfo = 'stream, 0 tracks';
        }
    } else if (video.src) {
        trackInfo = 'HLS src';
    }
    var playColor = debugPlayResult === 'ok' ? 'good' : debugPlayResult ? 'bad' : '';
    html += section('PLAYBACK', [
        row('Paused', video.paused ? 'yes' : 'no', video.paused ? 'bad' : 'good'),
        row('Muted', video.muted ? 'yes' : 'no', video.muted ? 'warn' : ''),
        row('ReadyState', (readyNames[video.readyState] || '?') + ' (' + video.readyState + ')', video.readyState < 2 ? 'bad' : 'good'),
        row('Network', (netNames[video.networkState] || '?') + ' (' + video.networkState + ')'),
        row('Play result', debugPlayResult || '—', playColor),
        row('Tracks', trackInfo),
        row('currentTime', video.currentTime ? video.currentTime.toFixed(1) + 's' : '0'),
        row('videoSize', video.videoWidth ? video.videoWidth + '×' + video.videoHeight : 'none', video.videoWidth ? '' : 'warn')
    ]);

    if (debugTimeline.length > 0) {
        var tlRows = [];
        var start = Math.max(0, debugTimeline.length - 14);
        for (var ti = debugTimeline.length - 1; ti >= start; ti--) {
            tlRows.push(row(debugTimeline[ti].ts, debugTimeline[ti].label));
        }
        html += section('TIMELINE (' + debugTimeline.length + ')', tlRows);
    }

    var hlsStatus = watchAdapter.hlsActive ? 'active' : 'off';
    var hlsBtnLabel = watchAdapter.hlsActive ? 'Switch to WebRTC' : 'Switch to HLS';
    var hlsBtnAction = watchAdapter.hlsActive ? 'switchToWebRTC()' : 'debugTryHLS()';
    html += '<div class="debug-section"><div class="debug-section-label">TOOLS</div>';
    html += row('HLS', hlsStatus, watchAdapter.hlsActive ? 'good' : '');
    html += '<button class="debug-btn" onclick="' + hlsBtnAction + '">' + hlsBtnLabel + '</button>';
    html += '<button class="debug-btn" onclick="debugCopyAll()">Copy to clipboard</button>';
    html += '</div>';

    debugContent.innerHTML = html;
}

function section(label, rows) {
    return '<div class="debug-section"><div class="debug-section-label">' + label + '</div>' + rows.join('') + '</div>';
}

function row(key, val, cls) {
    return '<div class="debug-row"><span class="debug-key">' + key + '</span><span class="debug-val' + (cls ? ' ' + cls : '') + '">' + val + '</span></div>';
}

function debugTryHLS() {
    if (!roomId) return;
    var url = '/hls/' + roomId + '/master.m3u8';
    fetch(url, { method: 'HEAD' }).then(function (r) {
        if (r.ok) {
            switchToHLS();
        } else {
            debugFlash('HLS not available (HTTP ' + r.status + ')');
        }
    }).catch(function () {
        debugFlash('HLS not available (fetch failed)');
    });
}

function debugFlash(msg) {
    if (!debugContent) return;
    var el = document.getElementById('debug-flash');
    if (!el) {
        var div = document.createElement('div');
        div.id = 'debug-flash';
        div.className = 'debug-val bad';
        div.style.cssText = 'text-align:left;padding:0.2rem 0;font-size:0.6rem;';
        debugContent.appendChild(div);
        el = div;
    }
    el.textContent = msg;
    setTimeout(function () { if (el) el.textContent = ''; }, 4000);
}

function debugCopyAll() {
    if (!debugContent) return;
    var rows = debugContent.querySelectorAll('.debug-row');
    var sections = debugContent.querySelectorAll('.debug-section-label');
    var lines = [];
    lines.push('=== DEBUG SNAPSHOT ===');
    lines.push('Time: ' + new Date().toISOString());
    lines.push('UA: ' + navigator.userAgent);
    lines.push('Adapter: ' + watchAdapter.name);
    lines.push('');
    var els = debugContent.querySelectorAll('.debug-section-label, .debug-row');
    for (var i = 0; i < els.length; i++) {
        var el = els[i];
        if (el.classList.contains('debug-section-label')) {
            lines.push('--- ' + el.textContent + ' ---');
        } else {
            var key = el.querySelector('.debug-key');
            var val = el.querySelector('.debug-val');
            if (key && val) {
                lines.push('  ' + key.textContent + ': ' + val.textContent);
            }
        }
    }
    var text = lines.join('\n');
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
            debugFlash('Copied to clipboard');
        }).catch(function () {
            debugCopyFallback(text);
        });
    } else {
        debugCopyFallback(text);
    }
}

function debugCopyFallback(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;left:-9999px;';
    document.body.appendChild(ta);
    ta.select();
    try {
        document.execCommand('copy');
        debugFlash('Copied to clipboard');
    } catch (e) {
        debugFlash('Copy failed — long-press to select text');
    }
    document.body.removeChild(ta);
}

function colorIce(state) {
    if (state === 'connected' || state === 'completed') return 'good';
    if (state === 'checking' || state === 'new') return 'warn';
    if (state === 'disconnected' || state === 'failed' || state === 'closed') return 'bad';
    return '';
}
