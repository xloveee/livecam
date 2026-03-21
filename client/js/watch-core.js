/* watch-core.js — viewer state machine, WebRTC, polling */

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
var audioElement = null;
var pollInterval = null;
var lastBytesReceived = 0;
var stallCount = 0;
var connectTimeout = null;
var viewerState = 'init';

video.addEventListener('resize', function() {
    if (video.videoWidth && video.videoHeight) {
        video.style.aspectRatio = video.videoWidth + '/' + video.videoHeight;
    }
});

/* ── State Machine ──────────────────────────────────────── */

function setState(next) {
    if (next === viewerState) return;
    viewerState = next;
    renderState();
    managePoll();
}

function renderState() {
    offlineBanner.style.display = 'none';
    passwordPrompt.style.display = 'none';
    statusEl.classList.remove('error');

    switch (viewerState) {
        case 'offline':
            offlineBanner.style.display = 'block';
            offlineBanner.classList.remove('live');
            offlineText.textContent = 'No broadcast right now';
            statusEl.textContent = 'Offline';
            viewerCountEl.textContent = '';
            qualitySelect.disabled = true;
            disableChat();
            break;
        case 'need_password':
            passwordPrompt.style.display = 'block';
            statusEl.textContent = 'Password required';
            qualitySelect.disabled = true;
            disableChat();
            break;
        case 'connecting':
            statusEl.textContent = 'Connecting...';
            qualitySelect.disabled = true;
            break;
        case 'live':
            statusEl.textContent = 'Live';
            qualitySelect.disabled = false;
            enableChat();
            break;
        case 'room_full':
            offlineBanner.style.display = 'block';
            offlineBanner.classList.remove('live');
            offlineText.textContent = 'Room is full — retrying...';
            statusEl.textContent = 'Waiting';
            qualitySelect.disabled = true;
            disableChat();
            break;
        case 'rate_limited':
            offlineBanner.style.display = 'block';
            offlineBanner.classList.remove('live');
            offlineText.textContent = 'Too many requests — retrying...';
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
        pollInterval = setInterval(function () { connectWHEP(); }, 5000);
    } else if (viewerState !== 'init' && viewerState !== 'connecting') {
        pollInterval = setInterval(pollActive, 5000);
    }
}

async function pollActive() {
    try {
        if (roomIdFromURL && roomId) {
            var infoResp = await fetch('/api/room_info/' + roomId);
            if (!infoResp.ok) return;
            var info = await infoResp.json();

            if (viewerState === 'live') {
                if (!info.is_live) {
                    teardownConnection();
                    setState('offline');
                } else if (info.has_password && !roomPassword) {
                    teardownConnection();
                    setState('need_password');
                } else {
                    viewerCountEl.textContent = info.viewer_count + ' watching';
                }
                return;
            }

            if (!info.is_live) {
                setState('offline');
                return;
            }
            if (info.has_password && !roomPassword) {
                setState('need_password');
            } else {
                connectWHEP();
            }
            return;
        }

        var resp = await fetch('/api/active');
        if (!resp.ok) return;
        var data = await resp.json();

        if (!data.room_id) {
            if (viewerState === 'live') { teardownConnection(); }
            setState('offline');
            return;
        }

        if (viewerState === 'live') {
            if (data.room_id !== roomId) {
                teardownConnection();
                chatDisconnect();
                roomId = data.room_id;
                roomPassword = '';
                passwordInput.value = '';
            } else {
                await checkRoomAlive();
                return;
            }
        }

        roomId = data.room_id;

        if (data.has_password && !roomPassword) {
            setState('need_password');
        } else {
            if (!data.has_password) { roomPassword = ''; passwordInput.value = ''; }
            connectWHEP();
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

async function checkRoomAlive() {
    if (!roomId) return true;
    try {
        var resp = await fetch('/api/room_info/' + roomId);
        if (!resp.ok) return true;
        var info = await resp.json();
        if (!info.is_live) {
            teardownConnection();
            setState('offline');
            return false;
        }
        viewerCountEl.textContent = info.viewer_count + ' watching';

        if (info.has_password && !roomPassword) {
            teardownConnection();
            setState('need_password');
            return false;
        } else if (!info.has_password && roomPassword) {
            roomPassword = '';
            passwordInput.value = '';
        }

        return true;
    } catch (e) { return true; }
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

/* ── WebRTC Lifecycle ───────────────────────────────────── */

function teardownConnection() {
    clearPollTimer();
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
    video.srcObject = null;
    video.style.aspectRatio = '';
    if (audioElement) {
        audioElement.srcObject = null;
        audioElement.remove();
        audioElement = null;
    }
    sessionId = null;
    lastBytesReceived = 0;
    stallCount = 0;
    qualitySelect.value = '';
}

function onPeerStateChange() {
    if (!pc) return;
    var s = pc.iceConnectionState;
    if (s === 'connected' || s === 'completed') {
        if (connectTimeout) { clearTimeout(connectTimeout); connectTimeout = null; }
        setState('live');
        checkRoomAlive();
        startStatsLoop();
    } else if (s === 'disconnected' || s === 'failed' || s === 'closed') {
        teardownConnection();
        setState('offline');
    }
}

async function connectWHEP() {
    if (!roomId) return;
    if (viewerState === 'connecting') return;

    teardownConnection();
    setState('connecting');

    var config = await fetchICEConfig();

    pc = new RTCPeerConnection({
        iceServers: config.iceServers || []
    });

    var receivers = [];
    pc.ontrack = function (event) {
        var track = event.track;
        var recv = event.receiver;
        if (typeof recv.jitterBufferTarget !== 'undefined') {
            receivers.push(recv);
            recv.jitterBufferTarget = 0.15;
        }
        if (track.kind === 'video') {
            video.srcObject = new MediaStream([track]);
            video.play().catch(function () {
                video.muted = true;
                video.play().catch(function () {});
            });
        } else if (track.kind === 'audio') {
            if (audioElement) {
                audioElement.srcObject = null;
                audioElement.remove();
            }
            audioElement = document.createElement('audio');
            audioElement.autoplay = true;
            audioElement.style.display = 'none';
            document.body.appendChild(audioElement);
            audioElement.srcObject = new MediaStream([track]);
            audioElement.play().catch(function () {});
        }
    };
    pc._aqReceivers = receivers;

    pc.oniceconnectionstatechange = onPeerStateChange;
    pc.onconnectionstatechange = onPeerStateChange;

    pc.addTransceiver('video', { direction: 'recvonly' });
    pc.addTransceiver('audio', { direction: 'recvonly' });

    try {
        var offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        var headers = { 'Content-Type': 'application/sdp' };
        if (roomPassword) {
            headers['X-Room-Password'] = roomPassword;
        }

        var response = await fetch('/api/whep/' + roomId, {
            method: 'POST',
            headers: headers,
            body: pc.localDescription.sdp
        });

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
            setState('room_full');
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
    connectWHEP();
};

passwordInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') btnPasswordSubmit.click();
});

/* ── Unified Stats Loop ─────────────────────────────────── */
/*
 * Single interval collects stats once per second. Feeds:
 *   - Media watchdog (stall detection)
 *   - Auto-quality adaptation (every other tick)
 *   - Debug overlay (when ?debug=1)
 * This avoids 3 competing getStats() calls.
 */

var statsInterval = null;
var statsTick = 0;

var debugEnabled = /[?&]debug=1/.test(window.location.search);
var debugOverlay = document.getElementById('debug-overlay');
var debugContent = document.getElementById('debug-content');
if (debugEnabled && debugOverlay) debugOverlay.classList.add('visible');

var degradeBanner = document.getElementById('degrade-banner');
var degradeText = document.getElementById('degrade-text');
var hlsBanner = document.getElementById('hls-banner');

var qualityLevels = ['h', 'm', 'l'];
var currentQualityIdx = -1;
var aqManualOverride = false;
var aqBadStreak = 0;
var aqGoodStreak = 0;
var lastQualityChangeTs = 0;
var QUALITY_COOLDOWN_MS = 15000;
var simulcastDisabled = false;
var resBeforeSwitch = '';
var resCheckPending = false;

var prevVideoBytes = 0;
var prevAudioBytes = 0;
var prevTs = 0;
var prevPackets = 0;
var prevLost = 0;

var currentJBTarget = 0.15;
var JB_MIN = 0.15;
var JB_MAX = 1.0;

qualitySelect.addEventListener('change', function () {
    aqManualOverride = true;
    aqBadStreak = 0;
    aqGoodStreak = 0;
});

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
    aqBadStreak = 0;
    aqGoodStreak = 0;
    aqManualOverride = false;
    currentQualityIdx = -1;
    simulcastDisabled = false;
    resCheckPending = false;
    currentJBTarget = JB_MIN;
    hideDegradeBanner();

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
        } else {
            stallCount++;
            if (stallCount >= 5) {
                teardownConnection();
                setState('offline');
                return;
            }
        }

        /* ── Parse all stats once ── */
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

        /* ── Simulcast detection ── */
        if (resCheckPending && d.videoRes) {
            if (d.videoRes === resBeforeSwitch) {
                simulcastDisabled = true;
            }
            resCheckPending = false;
        }

        /* ── Auto quality (every 2s) ── */
        if (statsTick % 2 === 0 && viewerState === 'live' && !aqManualOverride && !simulcastDisabled) {
            autoQualityTick(d);
        }

        /* ── Jitter buffer tuning (every tick when bad) ── */
        var isBurst = d.videoFps > 60;
        if (isBurst || d.videoLossPct > 5) {
            tuneJitterBuffer(d.videoLossPct, isBurst);
        }

        /* ── Debug overlay ── */
        if (debugEnabled) renderDebug(d);
    }, 1000);
}

function stopStatsLoop() {
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
    hideDegradeBanner();
}

/* ── Auto Quality ───────────────────────────────────────── */

function autoQualityTick(d) {
    if (prevTs === 0) return;

    var isBurst = d.videoFps > 60;
    var isBad = d.videoLossPct > 5 || d.videoFps < 10 || isBurst;
    var isGood = d.videoLossPct < 1 && d.videoFps > 20 && d.videoFps <= 60 && d.videoBitrateKbps > 200;

    if (isBad) {
        aqGoodStreak = 0;
        aqBadStreak++;
        if (aqBadStreak >= 3 && canChangeQuality()) {
            downgradeQuality(d.videoRes);
            aqBadStreak = 0;
        }
    } else if (isGood) {
        aqBadStreak = 0;
        aqGoodStreak++;
        if (aqGoodStreak >= 10 && canChangeQuality()) {
            upgradeQuality(d.videoRes);
            aqGoodStreak = 0;
            tightenJitterBuffer();
        }
    } else {
        aqBadStreak = Math.max(0, aqBadStreak - 1);
        aqGoodStreak = 0;
    }
}

function canChangeQuality() {
    return Date.now() - lastQualityChangeTs >= QUALITY_COOLDOWN_MS;
}

function downgradeQuality(currentRes) {
    var nextIdx = currentQualityIdx + 1;
    if (nextIdx >= qualityLevels.length) {
        showDegradeBanner();
        return;
    }
    currentQualityIdx = nextIdx;
    resBeforeSwitch = currentRes || '';
    resCheckPending = true;
    lastQualityChangeTs = Date.now();
    var rid = qualityLevels[currentQualityIdx];
    qualitySelect.value = rid;
    setQuality(rid);
    showDegradeBanner();
}

function upgradeQuality(currentRes) {
    if (currentQualityIdx <= 0) {
        currentQualityIdx = -1;
        lastQualityChangeTs = Date.now();
        qualitySelect.value = '';
        setQuality(null);
        hideDegradeBanner();
        return;
    }
    currentQualityIdx--;
    resBeforeSwitch = currentRes || '';
    resCheckPending = true;
    lastQualityChangeTs = Date.now();
    var rid = qualityLevels[currentQualityIdx];
    qualitySelect.value = rid;
    setQuality(rid);
}

function showDegradeBanner() {
    if (!degradeBanner) return;
    var atLowest = currentQualityIdx >= qualityLevels.length - 1;
    degradeBanner.style.display = 'flex';
    if (atLowest || simulcastDisabled) {
        degradeText.textContent = 'Your connection is unstable — playback may be choppy.';
        checkHLSAvailable();
    } else {
        degradeText.textContent = 'Connection unstable — quality lowered automatically.';
        if (hlsBanner) hlsBanner.style.display = 'none';
    }
}

function hideDegradeBanner() {
    if (degradeBanner) degradeBanner.style.display = 'none';
    if (hlsBanner) hlsBanner.style.display = 'none';
}

/* ── Jitter Buffer Tuning ───────────────────────────────── */

function tuneJitterBuffer(lossPct, isBurst) {
    var target = currentJBTarget;
    if (isBurst) {
        target = Math.min(target + 0.15, JB_MAX);
    } else if (lossPct > 10) {
        target = Math.min(target + 0.1, JB_MAX);
    } else if (lossPct > 5) {
        target = Math.min(target + 0.05, JB_MAX);
    }
    if (target !== currentJBTarget) {
        currentJBTarget = target;
        applyJitterBuffer(target);
    }
}

function tightenJitterBuffer() {
    if (currentJBTarget <= JB_MIN) return;
    currentJBTarget = Math.max(currentJBTarget - 0.05, JB_MIN);
    applyJitterBuffer(currentJBTarget);
}

function applyJitterBuffer(target) {
    if (!pc || !pc._aqReceivers) return;
    for (var i = 0; i < pc._aqReceivers.length; i++) {
        try { pc._aqReceivers[i].jitterBufferTarget = target; } catch (e) {}
    }
}

/* ── HLS Fallback ───────────────────────────────────────── */

var hlsPlayer = null;
var hlsActive = false;

function checkHLSAvailable() {
    if (!roomId || !hlsBanner) return;
    fetch('/hls/' + roomId + '/master.m3u8', { method: 'HEAD' })
        .then(function (r) {
            if (r.ok) hlsBanner.style.display = 'block';
        })
        .catch(function () {});
}

function switchToHLS() {
    if (!roomId) return;
    var hlsUrl = '/hls/' + roomId + '/master.m3u8';
    teardownConnection();
    hlsActive = true;
    qualitySelect.disabled = true;

    if (video.canPlayType('application/vnd.apple.mpegurl')) {
        video.src = hlsUrl;
        video.play().catch(function () {});
        onHLSPlaying();
    } else if (typeof Hls !== 'undefined' && Hls.isSupported()) {
        hlsPlayer = new Hls({ enableWorker: true, lowLatencyMode: true });
        hlsPlayer.loadSource(hlsUrl);
        hlsPlayer.attachMedia(video);
        hlsPlayer.on(Hls.Events.MANIFEST_PARSED, function () {
            video.play().catch(function () {});
        });
        onHLSPlaying();
    } else {
        statusEl.textContent = 'HLS not supported in this browser';
        statusEl.classList.add('error');
    }
}

function onHLSPlaying() {
    viewerState = 'live';
    statusEl.textContent = 'Live (HLS)';
    statusEl.classList.remove('error');
    if (degradeBanner) {
        degradeText.textContent = 'Switched to stable playback (HLS). Latency is higher (~5s).';
        if (hlsBanner) hlsBanner.style.display = 'none';
    }
}

function switchToWebRTC() {
    if (hlsPlayer) { hlsPlayer.destroy(); hlsPlayer = null; }
    video.removeAttribute('src');
    video.srcObject = null;
    hlsActive = false;
    hideDegradeBanner();
    connectWHEP();
}

/* ── Debug Overlay (?debug=1) ───────────────────────────── */

function renderDebug(d) {
    if (!debugContent) return;
    var html = '';

    var aqStatus = simulcastDisabled ? 'no simulcast' : aqManualOverride ? 'manual' : 'auto';
    html += section('STATE', [
        row('Viewer', d.state || '—'),
        row('ICE', d.iceState || '—', colorIce(d.iceState)),
        row('Stall count', d.stallCount != null ? d.stallCount : '—'),
        row('Quality', aqStatus + (currentQualityIdx >= 0 ? ' (' + qualityLevels[currentQualityIdx] + ')' : ' (auto)')),
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
            row('Jitter buf', d.jitterBufferMs ? d.jitterBufferMs.toFixed(0) + ' ms' : '—'),
            row('JB target', (currentJBTarget * 1000).toFixed(0) + ' ms', currentJBTarget > 0.3 ? 'warn' : '')
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

    debugContent.innerHTML = html;
}

function section(label, rows) {
    return '<div class="debug-section"><div class="debug-section-label">' + label + '</div>' + rows.join('') + '</div>';
}

function row(key, val, cls) {
    return '<div class="debug-row"><span class="debug-key">' + key + '</span><span class="debug-val' + (cls ? ' ' + cls : '') + '">' + val + '</span></div>';
}

function colorIce(state) {
    if (state === 'connected' || state === 'completed') return 'good';
    if (state === 'checking' || state === 'new') return 'warn';
    if (state === 'disconnected' || state === 'failed' || state === 'closed') return 'bad';
    return '';
}
