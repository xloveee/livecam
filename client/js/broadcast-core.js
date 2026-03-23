/* broadcast-core.js — settings UI, devices, WebRTC publish, health indicator */

var preview = document.getElementById('preview');
var btnStart = document.getElementById('btn-start');
var btnStop = document.getElementById('btn-stop');
var statusEl = document.getElementById('status');
var statsEl = document.getElementById('stats');
var liveBadge = document.getElementById('live-badge');
var streamKeyInput = document.getElementById('stream-key');
var resolutionSelect = document.getElementById('resolution');
var cameraSelect = document.getElementById('camera-select');
var micSelect = document.getElementById('mic-select');
var maxViewersInput = document.getElementById('max-viewers');
var viewerCountEl = document.getElementById('viewer-count');
var roomPasswordInput = document.getElementById('room-password');
var bitrateSelect = document.getElementById('bitrate');

var pc = null;
var localStream = null;
var statsInterval = null;

var activeStreamKey = null;
var authenticatedKey = '';

/** Firefox: recoverable `disconnected` ICE; publish path uses addTrack + VP8 prefs instead of simulcast transceiver. */
function isFirefoxBrowser() {
    if (typeof navigator === 'undefined') {
        return false;
    }
    var ua = navigator.userAgent || '';
    return /Firefox\//.test(ua) || /FxiOS\//.test(ua);
}

var broadcastLiveStarted = false;
var iceDisconnectTimer = null;

function clearIceDisconnectTimer() {
    if (iceDisconnectTimer) {
        clearTimeout(iceDisconnectTimer);
        iceDisconnectTimer = null;
    }
}

/* ── Settings UI ─────────────────────────────────────────── */

function toggleSettings() {
    var overlay = document.getElementById('settings-overlay');
    var tog = document.getElementById('settings-toggle');
    overlay.classList.toggle('visible');
    tog.classList.toggle('open');
}

function closeSettings() {
    document.getElementById('settings-overlay').classList.remove('visible');
    document.getElementById('settings-toggle').classList.remove('open');
}

function switchSettingsTab(page, btn) {
    document.querySelectorAll('.settings-page').forEach(function (el) {
        el.classList.remove('active');
    });
    document.querySelectorAll('.settings-tab').forEach(function (el) {
        el.classList.remove('active');
    });
    document.getElementById('settings-' + page).classList.add('active');
    btn.classList.add('active');
}

/* ── Device Enumeration & Preview ────────────────────────── */

async function enumerateDevices() {
    try {
        await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
    } catch (e) {
        statusEl.textContent = 'Camera/mic permission denied';
        statusEl.classList.add('error');
        btnStart.disabled = true;
        return;
    }

    var devices = await navigator.mediaDevices.enumerateDevices();

    cameraSelect.innerHTML = '';
    micSelect.innerHTML = '';

    var cameras = devices.filter(function (d) { return d.kind === 'videoinput'; });
    var mics = devices.filter(function (d) { return d.kind === 'audioinput'; });

    if (cameras.length === 0) {
        cameraSelect.innerHTML = '<option value="">No camera found</option>';
    } else {
        cameras.forEach(function (cam, i) {
            var opt = document.createElement('option');
            opt.value = cam.deviceId;
            opt.textContent = cam.label || ('Camera ' + (i + 1));
            cameraSelect.appendChild(opt);
        });
    }

    if (mics.length === 0) {
        micSelect.innerHTML = '<option value="">No microphone found</option>';
    } else {
        mics.forEach(function (mic, i) {
            var opt = document.createElement('option');
            opt.value = mic.deviceId;
            opt.textContent = mic.label || ('Mic ' + (i + 1));
            micSelect.appendChild(opt);
        });
    }

    await startPreview();
}

async function startPreview() {
    if (localStream) {
        localStream.getTracks().forEach(function (t) { t.stop(); });
    }

    var parts = resolutionSelect.value.split('x').map(Number);
    var w = parts[0];
    var h = parts[1];
    var constraints = {
        video: {
            deviceId: cameraSelect.value ? { exact: cameraSelect.value } : undefined,
            width: { ideal: w },
            height: { ideal: h },
            frameRate: { ideal: 30 }
        },
        audio: {
            deviceId: micSelect.value ? { exact: micSelect.value } : undefined,
            channelCount: 1,
            sampleRate: 48000,
            echoCancellation: false,
            noiseSuppression: false,
            autoGainControl: false
        }
    };

    try {
        localStream = await navigator.mediaDevices.getUserMedia(constraints);
        preview.srcObject = localStream;
        preview.playsInline = true;
        preview.play().catch(function () {});
    } catch (e) {
        statusEl.textContent = 'Failed to access camera: ' + e.message;
        statusEl.classList.add('error');
    }
}

cameraSelect.onchange = startPreview;
micSelect.onchange = startPreview;
resolutionSelect.onchange = startPreview;

preview.addEventListener('resize', function () {
    if (preview.videoWidth && preview.videoHeight) {
        preview.style.aspectRatio = preview.videoWidth + '/' + preview.videoHeight;
    }
});

/* ── Bitrate Cap ─────────────────────────────────────────── */

var SIMULCAST_DEFAULTS = [2500, 1000, 400];

async function applyBitrateCap() {
    if (!pc) return;
    var maxKbps = parseInt(bitrateSelect.value, 10);
    var senders = pc.getSenders();
    for (var i = 0; i < senders.length; i++) {
        var sender = senders[i];
        if (!sender.track || sender.track.kind !== 'video') continue;
        var params = sender.getParameters();
        if (!params.encodings || params.encodings.length === 0) continue;
        for (var j = 0; j < params.encodings.length; j++) {
            if (maxKbps > 0) {
                var layerDefault = SIMULCAST_DEFAULTS[j] || SIMULCAST_DEFAULTS[SIMULCAST_DEFAULTS.length - 1];
                params.encodings[j].maxBitrate = Math.min(maxKbps, layerDefault) * 1000;
            } else {
                var restore = SIMULCAST_DEFAULTS[j];
                params.encodings[j].maxBitrate = restore ? restore * 1000 : undefined;
            }
        }
        try { await sender.setParameters(params); } catch (e) { /* ignore */ }
    }
}

bitrateSelect.onchange = applyBitrateCap;

/* ── Room Settings API ───────────────────────────────────── */

async function setViewerLimit(streamKey, max) {
    try {
        await fetch('/api/viewer_limit/' + streamKey, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ max_viewers: parseInt(max, 10) || 0 })
        });
    } catch (e) { /* ignore */ }
}

async function setRoomPassword(streamKey, password) {
    try {
        await fetch('/api/room_password/' + streamKey, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: password || '' })
        });
    } catch (e) { /* ignore */ }
}

window.onRoomState = function (state) {
    if (!activeStreamKey) return;
    if (state.viewer_count !== undefined && state.viewer_count !== null) {
        var max = parseInt(maxViewersInput.value, 10) || 0;
        viewerCountEl.textContent = state.viewer_count + ' watching' + (max > 0 ? ' / ' + max + ' max' : '');
    }
};

maxViewersInput.onchange = function () {
    if (activeStreamKey) setViewerLimit(activeStreamKey, maxViewersInput.value);
};

var passwordDebounce = null;
roomPasswordInput.oninput = function () {
    clearTimeout(passwordDebounce);
    passwordDebounce = setTimeout(function () {
        if (activeStreamKey) setRoomPassword(activeStreamKey, roomPasswordInput.value.trim());
    }, 500);
};

/* ── ICE & WebRTC Publish ────────────────────────────────── */

async function fetchICEConfig() {
    try {
        var resp = await fetch('/api/config');
        if (!resp.ok) return {};
        return await resp.json();
    } catch (e) {
        return { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
    }
}

/** Match watch-core: pre-gather ICE before offer; Firefox can fail without pool on some networks. */
function createBroadcastPeerConnection(iceServers) {
    var base = {
        iceServers: iceServers || [],
        bundlePolicy: 'max-bundle',
        rtcpMuxPolicy: 'require'
    };
    try {
        return new RTCPeerConnection(Object.assign({}, base, { iceCandidatePoolSize: 10 }));
    } catch (e) {
        try {
            return new RTCPeerConnection(base);
        } catch (e2) {
            throw e2;
        }
    }
}

/** Baseline (0x42) before Main (0x4D) before High (0x64) — WebKit mobile decode. */
function h264ProfileRank(codec) {
    var line = codec.sdpFmtpLine || '';
    var m = /profile-level-id=([0-9a-fA-F]{6})/i.exec(line);
    if (!m) return 50;
    var p = parseInt(m[1].substring(0, 2), 16);
    if (p === 0x42) return 0;
    if (p === 0x4D) return 1;
    if (p === 0x64) return 2;
    return 25;
}

function sortH264ForCompat(codecs) {
    return codecs.slice().sort(function (a, b) {
        return h264ProfileRank(a) - h264ProfileRank(b);
    });
}

/** VP8-only when available — desktop otherwise negotiates H.264 Main/High; iPhone viewers often cannot decode it. */
function applyBroadcastVideoCodecPreferences(pc) {
    try {
        if (typeof RTCRtpSender === 'undefined' || !RTCRtpSender.getCapabilities) return;
        var caps = RTCRtpSender.getCapabilities('video');
        var h264 = sortH264ForCompat(caps.codecs.filter(function (c) {
            return c.mimeType.toLowerCase() === 'video/h264';
        }));
        var vp8 = caps.codecs.filter(function (c) { return c.mimeType.toLowerCase() === 'video/vp8'; });
        var rest = caps.codecs.filter(function (c) {
            var m = c.mimeType.toLowerCase();
            return m !== 'video/h264' && m !== 'video/vp8';
        });
        var transceivers = pc.getTransceivers();
        for (var i = 0; i < transceivers.length; i++) {
            var tr = transceivers[i];
            if (tr.sender && tr.sender.track && tr.sender.track.kind === 'video') {
                if (vp8.length) {
                    tr.setCodecPreferences(vp8.concat(rest));
                } else if (h264.length) {
                    tr.setCodecPreferences(h264.concat(rest));
                }
                break;
            }
        }
    } catch (e) { /* ignore */ }
}

btnStart.onclick = async function () {
    var streamKey = authenticatedKey;
    if (!streamKey) {
        statusEl.textContent = 'Not authenticated';
        statusEl.classList.add('error');
        return;
    }
    if (!localStream) {
        statusEl.textContent = 'No camera stream available';
        statusEl.classList.add('error');
        return;
    }

    statusEl.textContent = 'Connecting...';
    statusEl.classList.remove('error', 'connected');
    btnStart.style.display = 'none';
    btnStop.style.display = 'inline-block';

    broadcastLiveStarted = false;
    clearIceDisconnectTimer();

    var config = await fetchICEConfig();

    pc = createBroadcastPeerConnection(config.iceServers || []);

    localStream.getTracks().forEach(function (track) {
        if (track.kind === 'video') {
            /* Firefox: addTransceiver+sendEncodings caused ICE/SDP churn with WHIP; same MediaStream as audio. */
            if (isFirefoxBrowser()) {
                pc.addTrack(track, localStream);
            } else {
                pc.addTransceiver(track, {
                    direction: 'sendonly',
                    sendEncodings: [
                        { rid: 'h', maxBitrate: 2500000 },
                        { rid: 'm', maxBitrate: 1000000, scaleResolutionDownBy: 2.0 },
                        { rid: 'l', maxBitrate: 400000, scaleResolutionDownBy: 4.0 }
                    ]
                });
            }
        } else {
            pc.addTrack(track, localStream);
        }
    });

    applyBroadcastVideoCodecPreferences(pc);

    function onBroadcastPcStateChange() {
        if (!pc) {
            return;
        }
        var ice = pc.iceConnectionState;
        var conn = pc.connectionState;
        if (ice === 'connected' || ice === 'completed' || conn === 'connected') {
            clearIceDisconnectTimer();
            if (!broadcastLiveStarted) {
                broadcastLiveStarted = true;
                statusEl.textContent = 'Live';
                statusEl.classList.add('connected');
                statusEl.classList.remove('error');
                liveBadge.classList.add('visible');
                startStats();
                applyBitrateCap();
                activeStreamKey = streamKey;
                setViewerLimit(streamKey, maxViewersInput.value);
                setRoomPassword(streamKey, roomPasswordInput.value.trim());
            }
            return;
        }
        if (ice === 'failed' || ice === 'closed' || conn === 'failed' || conn === 'closed') {
            clearIceDisconnectTimer();
            var iceFailed = (ice === 'failed' || conn === 'failed');
            stopBroadcast();
            /* Firefox often logs "ICE failed, add a TURN server" — STUN-only is not enough on some networks. */
            statusEl.textContent = iceFailed
                ? 'Disconnected — ICE failed. This network likely needs TURN (relay). Set TURN_URL + TURN_USERNAME + TURN_CREDENTIAL on the Go proxy and open UDP/TCP to coturn.'
                : 'Disconnected';
            statusEl.classList.add('error');
            return;
        }
        /* disconnected is often transient (esp. Firefox); only tear down if it persists */
        if (ice === 'disconnected') {
            clearIceDisconnectTimer();
            iceDisconnectTimer = setTimeout(function () {
                if (!pc) {
                    return;
                }
                var i2 = pc.iceConnectionState;
                var c2 = pc.connectionState;
                if (i2 !== 'disconnected') {
                    return;
                }
                if (c2 === 'connected' || c2 === 'connecting') {
                    return;
                }
                stopBroadcast();
                statusEl.textContent = 'Disconnected';
                statusEl.classList.add('error');
            }, 5000);
        }
    }

    pc.oniceconnectionstatechange = onBroadcastPcStateChange;
    pc.onconnectionstatechange = onBroadcastPcStateChange;

    try {
        var offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        var response = await fetch('/api/whip/' + streamKey, {
            method: 'POST',
            headers: { 'Content-Type': 'application/sdp' },
            body: pc.localDescription.sdp
        });

        if (!response.ok) {
            var errText = await response.text();
            throw new Error(errText || ('Server returned ' + response.status));
        }

        var answerSdp = await response.text();
        await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp });

    } catch (err) {
        broadcastLiveStarted = false;
        clearIceDisconnectTimer();
        statusEl.textContent = 'Failed: ' + err.message;
        statusEl.classList.add('error');
        btnStart.style.display = '';
        btnStart.disabled = false;
        btnStop.style.display = 'none';
        if (pc) { pc.close(); pc = null; }
    }
};

btnStop.onclick = function () {
    stopBroadcast();
    statusEl.textContent = 'Stopped';
    statusEl.classList.remove('connected', 'error');
};

function stopBroadcast() {
    clearIceDisconnectTimer();
    broadcastLiveStarted = false;
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
    if (pc) { pc.close(); pc = null; }
    activeStreamKey = null;
    liveBadge.classList.remove('visible');
    btnStart.style.display = '';
    btnStart.disabled = false;
    btnStop.style.display = 'none';
    statsEl.textContent = '';
    viewerCountEl.textContent = '';
    healthIndicator.classList.remove('visible');
}

/* ── Health Indicator ────────────────────────────────────── */

var healthIndicator = document.getElementById('health-indicator');
var healthDot = document.getElementById('health-dot');
var healthLabel = document.getElementById('health-label');
var healthDetail = document.getElementById('health-detail');
var healthTooltip = document.getElementById('health-tooltip');
var prevVideoBytes = 0;
var prevVideoTimestamp = 0;
var prevPacketsSent = 0;
var prevNackCount = 0;

function startStats() {
    if (statsInterval) clearInterval(statsInterval);
    prevVideoBytes = 0;
    prevVideoTimestamp = 0;
    prevPacketsSent = 0;
    prevNackCount = 0;
    healthIndicator.classList.add('visible');

    statsInterval = setInterval(async function () {
        if (!pc) return;
        var stats;
        try { stats = await pc.getStats(); } catch (e) { return; }

        var resolution = '';
        var fps = 0;
        var bitrateKbps = 0;
        var rttMs = 0;
        var packetLossPct = 0;
        var qualityLimit = '';
        var nackRate = 0;

        stats.forEach(function (report) {
            if (report.type === 'outbound-rtp' && report.kind === 'video') {
                if (prevVideoTimestamp > 0) {
                    var dt = (report.timestamp - prevVideoTimestamp) / 1000;
                    if (dt > 0) {
                        bitrateKbps = ((report.bytesSent - prevVideoBytes) * 8) / dt / 1000;
                    }
                    var sentDelta = (report.packetsSent || 0) - prevPacketsSent;
                    var nackDelta = (report.nackCount || 0) - prevNackCount;
                    if (sentDelta > 0) {
                        nackRate = nackDelta / sentDelta;
                    }
                }
                prevVideoBytes = report.bytesSent;
                prevVideoTimestamp = report.timestamp;
                prevPacketsSent = report.packetsSent || 0;
                prevNackCount = report.nackCount || 0;

                if (report.frameWidth) resolution = report.frameWidth + 'x' + report.frameHeight;
                fps = report.framesPerSecond || 0;
                qualityLimit = report.qualityLimitationReason || 'none';
            }

            if (report.type === 'remote-inbound-rtp' && report.kind === 'video') {
                rttMs = (report.roundTripTime || 0) * 1000;
                if (typeof report.fractionLost === 'number') {
                    packetLossPct = report.fractionLost * 100;
                }
            }

            if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                if (report.currentRoundTripTime) {
                    rttMs = report.currentRoundTripTime * 1000;
                }
            }
        });

        var score = computeHealthScore(bitrateKbps, fps, rttMs, packetLossPct, nackRate, qualityLimit);
        updateHealthUI(score, bitrateKbps, fps, rttMs, packetLossPct, qualityLimit, resolution);

        var overlayParts = [resolution, fps ? fps.toFixed(0) + ' fps' : '', bitrateKbps ? bitrateKbps.toFixed(0) + ' kbps' : ''].filter(Boolean);
        statsEl.textContent = overlayParts.length > 0 ? overlayParts.join(' · ') : '';
    }, 3000);
}

function computeHealthScore(bitrateKbps, fps, rttMs, lossPercent, nackRate, qualityLimit) {
    var score = 100;

    if (bitrateKbps < 500) score -= 30;
    else if (bitrateKbps < 1000) score -= 15;
    else if (bitrateKbps < 1500) score -= 5;

    if (fps < 10) score -= 30;
    else if (fps < 20) score -= 15;
    else if (fps < 25) score -= 5;

    if (rttMs > 300) score -= 25;
    else if (rttMs > 150) score -= 12;
    else if (rttMs > 80) score -= 5;

    if (lossPercent > 5) score -= 25;
    else if (lossPercent > 2) score -= 12;
    else if (lossPercent > 0.5) score -= 5;

    if (nackRate > 0.05) score -= 10;

    if (qualityLimit === 'bandwidth') score -= 10;
    else if (qualityLimit === 'cpu') score -= 15;

    return Math.max(0, Math.min(100, score));
}

function updateHealthUI(score, bitrateKbps, fps, rttMs, lossPct, qualityLimit, resolution) {
    var level, label;
    if (score >= 80) { level = 'excellent'; label = 'Excellent'; }
    else if (score >= 60) { level = 'good'; label = 'Good'; }
    else if (score >= 35) { level = 'fair'; label = 'Unstable'; }
    else { level = 'poor'; label = 'Poor'; }

    healthDot.className = 'health-dot ' + level;
    healthLabel.textContent = label;
    healthLabel.style.color = level === 'excellent' ? '#4caf50' : level === 'good' ? '#8bc34a' : level === 'fair' ? '#ffb300' : '#ff5722';

    healthDetail.textContent = bitrateKbps ? bitrateKbps.toFixed(0) + ' kbps' : '';

    var lines = [];
    lines.push('Bitrate: ' + (bitrateKbps ? bitrateKbps.toFixed(0) + ' kbps' : '—'));
    lines.push('Framerate: ' + (fps ? fps.toFixed(0) + ' fps' : '—'));
    lines.push('Resolution: ' + (resolution || '—'));
    lines.push('RTT: ' + (rttMs ? rttMs.toFixed(0) + ' ms' : '—'));
    lines.push('Packet loss: ' + (lossPct > 0 ? lossPct.toFixed(1) + '%' : '0%'));
    if (qualityLimit && qualityLimit !== 'none') {
        lines.push('Limited by: ' + qualityLimit);
    }
    lines.push('Score: ' + score + '/100');
    healthTooltip.innerHTML = lines.join('<br>');
}
