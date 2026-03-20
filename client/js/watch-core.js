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
var mediaWatchdogInterval = null;
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
    if (mediaWatchdogInterval) { clearInterval(mediaWatchdogInterval); mediaWatchdogInterval = null; }
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

function startMediaWatchdog() {
    lastBytesReceived = 0;
    stallCount = 0;
    mediaWatchdogInterval = setInterval(async function () {
        if (!pc) return;
        try {
            var stats = await pc.getStats();
            var totalBytes = 0;
            stats.forEach(function (report) {
                if (report.type === 'inbound-rtp') {
                    totalBytes += report.bytesReceived || 0;
                }
            });
            if (totalBytes > lastBytesReceived) {
                lastBytesReceived = totalBytes;
                stallCount = 0;
            } else {
                stallCount++;
                if (stallCount >= 5) {
                    teardownConnection();
                    setState('offline');
                }
            }
        } catch (e) { /* pc may have closed mid-check */ }
    }, 1000);
}

function onPeerStateChange() {
    if (!pc) return;
    var s = pc.iceConnectionState;
    if (s === 'connected' || s === 'completed') {
        if (connectTimeout) { clearTimeout(connectTimeout); connectTimeout = null; }
        setState('live');
        checkRoomAlive();
        startMediaWatchdog();
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

    pc.ontrack = function (event) {
        var track = event.track;
        if (track.kind === 'video') {
            video.srcObject = new MediaStream([track]);
            video.play().catch(function () {
                video.muted = true;
                video.play().catch(function () {});
            });
            if (typeof event.receiver.jitterBufferTarget !== 'undefined') {
                event.receiver.jitterBufferTarget = 0.15;
            }
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
            if (typeof event.receiver.jitterBufferTarget !== 'undefined') {
                event.receiver.jitterBufferTarget = 0.15;
            }
        }
    };

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
