/* broadcast-scene.js — studio layers + local preview mix.
 * WHIP: native camera, or native getDisplayMedia. A visible full-bleed
 * type==='screen' stream is ALWAYS the publish source (+ mic). After the last
 * type==='screen' layer is gone, WHIP stays on the native camera MediaStreamTrack
 * (same track as the dual-cam camera sender). Never mixCanvas.captureStream()
 * / MediaStreamTrackGenerator / rAF recapture for screen or camera-only.
 * Local preview may still draw facecam/overlays (throttled; not the WHIP source). */

var studioLayers = [];
var mixCanvas = document.getElementById('mix-canvas');
var mixCtx = mixCanvas ? mixCanvas.getContext('2d', { alpha: false, desynchronized: true }) : null;
var previewMirror = document.getElementById('preview-mirror');
var fileSource = document.getElementById('file-source');
var useVideoFile = document.getElementById('use-video-file');
function isFileSource() {
    return !!(useVideoFile && useVideoFile.checked);
}
if (mixCanvas) mixCanvas.style.visibility = 'hidden';
var sceneOffscreen = document.getElementById('scene-offscreen');
var donationToastEl = document.getElementById('donation-toast');
var sceneHandles = document.getElementById('scene-handles');
var sceneRaf = 0;
var lastMixTs = 0;
var sceneToast = null;
var mixCaptureStream = null;
var selectedLayerId = null;
var sceneDrag = null;
var handleRo = null;
var SCENE_GRID = 0.05;
var SNAP_STORAGE_KEY = 'livecam-scene-snap';
var HIDE_GUI_STORAGE_KEY = 'livecam-hide-gui';
var DOCK_STORAGE_KEY = 'livecam-studio-dock';
var sceneSnapEnabled = readSceneSnapPref();
var hideGuiEnabled = readHideGuiPref();
var studioDockOpen = readStudioDockPref();
var lastLivePublishKind = null;
var lastLivePublishSig = null;
/* User Remove of camera-face: do not upsert it again until they pick a camera. */
var cameraFaceWanted = true;
var fileMainWanted = true;

function isCameraFaceWanted() {
    return cameraFaceWanted !== false;
}

function setCameraFaceWanted(on) {
    cameraFaceWanted = !!on;
}

function dismissMainCameraFace() {
    cameraFaceWanted = false;
    /* Layer stack is source of truth. Remaining camera-face/extra owns the
     * dropdown — never inject Camera off while a camera layer exists. */
    if (studioHasCameraLayer()) {
        syncDeviceDropdownsToSelectedLayer();
        return;
    }
    if (typeof cameraSelect === 'undefined' || !cameraSelect) return;
    withSelectSilent(cameraSelect, function () {
        ensureCameraOffOption();
        cameraSelect.value = '';
    });
}

function stopDismissedCameraVideo() {
    if (cameraFaceWanted) return;
    if (findLayer('camera-face')) return;
    if (typeof localStream === 'undefined' || !localStream || !localStream.getVideoTracks) return;
    localStream.getVideoTracks().forEach(function (t) {
        try { t.stop(); } catch (e) { /* already ended */ }
        try { localStream.removeTrack(t); } catch (e2) { /* ignore */ }
    });
}

function audioOnlyPublishStream() {
    var out = null;
    if (typeof MediaStream === 'function') {
        try { out = new MediaStream(); } catch (e) { out = null; }
    }
    if (!out) return null;
    return withPublishAudio(out);
}
var PROGRAM_FPS_CAMERA = 30;
var PROGRAM_FPS_SCREEN = 24;
var MIX_SCREEN_MAX_W = 1280;
var MIX_SCREEN_MAX_H = 720;
var PREVIEW_FPS = 8;
var previewLoopOn = false;

function switchStudioTab(page, btn) {
    document.querySelectorAll('.settings-page').forEach(function (el) {
        el.classList.remove('active');
    });
    document.querySelectorAll('.dock-tab').forEach(function (el) {
        el.classList.remove('active');
    });
    var pane = document.getElementById('settings-' + page);
    if (pane) pane.classList.add('active');
    document.querySelectorAll('[data-tab="' + page + '"]').forEach(function (el) {
        el.classList.add('active');
    });
    if (btn) btn.classList.add('active');
}

function readStudioDockPref() {
    try {
        if (typeof sessionStorage === 'undefined' || !sessionStorage) return true;
        var v = sessionStorage.getItem(DOCK_STORAGE_KEY);
        if (v === '0' || v === 'off' || v === 'false' || v === 'closed') return false;
        if (v === '1' || v === 'on' || v === 'true' || v === 'open') return true;
    } catch (e) { /* private mode */ }
    return true;
}

function isStudioDockOpen() {
    return !!studioDockOpen;
}

function syncStudioDockUi() {
    var dock = document.getElementById('studio-dock');
    var panel = dock && dock.querySelector ? dock.querySelector('.dock-panel') : null;
    var preview = document.querySelector('.studio-preview');
    var btn = document.getElementById('btn-dock-toggle');
    if (dock) {
        dock.classList.toggle('dock-closed', !studioDockOpen);
        if (studioDockOpen) dock.removeAttribute('hidden');
        else dock.setAttribute('hidden', '');
    }
    if (panel) panel.classList.toggle('dock-closed', !studioDockOpen);
    if (preview) preview.classList.toggle('dock-closed', !studioDockOpen);
    if (btn) {
        btn.setAttribute('aria-expanded', studioDockOpen ? 'true' : 'false');
        btn.classList.toggle('active', studioDockOpen);
    }
}

function setStudioDockOpen(on) {
    studioDockOpen = !!on;
    try {
        if (typeof sessionStorage !== 'undefined' && sessionStorage) {
            sessionStorage.setItem(DOCK_STORAGE_KEY, studioDockOpen ? '1' : '0');
        }
    } catch (e) { /* private mode */ }
    syncStudioDockUi();
}

function openStudioDock(page, btn) {
    setStudioDockOpen(true);
    switchStudioTab(page || 'sources', btn || document.querySelector('.dock-tab[data-tab="' + (page || 'sources') + '"]'));
}

function closeStudioDock() {
    setStudioDockOpen(false);
}

function toggleStudioDock() {
    if (studioDockOpen) closeStudioDock();
    else openStudioDock();
}

function toggleSettings() {
    toggleStudioDock();
}
function closeSettings() {
    closeStudioDock();
}
function switchSettingsTab(page, btn) {
    var map = { stream: 'stream', room: 'room', donations: 'donations', panels: 'room' };
    openStudioDock(map[page] || page, btn || document.querySelector('.dock-tab[data-tab="' + (map[page] || page) + '"]'));
}

function bindMaxViewersBar() {
    var bar = document.getElementById('max-viewers-bar');
    if (!bar || typeof maxViewersInput === 'undefined' || !maxViewersInput) return;
    bar.value = maxViewersInput.value || '0';
    bar.addEventListener('change', function () {
        maxViewersInput.value = bar.value;
        if (typeof maxViewersInput.onchange === 'function') maxViewersInput.onchange();
    });
    maxViewersInput.addEventListener('change', function () {
        bar.value = maxViewersInput.value;
    });
    maxViewersInput.addEventListener('input', function () {
        bar.value = maxViewersInput.value;
    });
}

function readSceneSnapPref() {
    try {
        if (typeof localStorage === 'undefined' || !localStorage) return true;
        var v = localStorage.getItem(SNAP_STORAGE_KEY);
        if (v === '0' || v === 'off' || v === 'false') return false;
        if (v === '1' || v === 'on' || v === 'true') return true;
    } catch (e) { /* private mode */ }
    return true;
}

function readHideGuiPref() {
    try {
        if (typeof sessionStorage === 'undefined' || !sessionStorage) return false;
        var v = sessionStorage.getItem(HIDE_GUI_STORAGE_KEY);
        if (v === '1' || v === 'on' || v === 'true') return true;
        if (v === '0' || v === 'off' || v === 'false') return false;
    } catch (e) { /* private mode */ }
    return false;
}

function isSceneSnapEnabled() {
    return !!sceneSnapEnabled;
}

function syncSnapToggleUi() {
    var btn = document.getElementById('btn-snap-toggle');
    if (!btn) return;
    btn.setAttribute('aria-pressed', sceneSnapEnabled ? 'true' : 'false');
    btn.classList.toggle('active', sceneSnapEnabled);
}

function setSceneSnapEnabled(on) {
    sceneSnapEnabled = !!on;
    try {
        if (typeof localStorage !== 'undefined' && localStorage) {
            localStorage.setItem(SNAP_STORAGE_KEY, sceneSnapEnabled ? '1' : '0');
        }
    } catch (e) { /* private mode */ }
    syncSnapToggleUi();
}

function toggleSceneSnap() {
    setSceneSnapEnabled(!sceneSnapEnabled);
}

function isHideGuiEnabled() {
    return !!hideGuiEnabled;
}

function syncHideGuiUi() {
    var btn = document.getElementById('btn-hide-gui');
    if (btn) {
        btn.setAttribute('aria-pressed', hideGuiEnabled ? 'true' : 'false');
        btn.classList.toggle('active', hideGuiEnabled);
    }
    var root = document.getElementById('app') || document.documentElement;
    if (root && root.classList) root.classList.toggle('studio-hide-gui', hideGuiEnabled);
}

function setHideGuiEnabled(on) {
    hideGuiEnabled = !!on;
    try {
        if (typeof sessionStorage !== 'undefined' && sessionStorage) {
            sessionStorage.setItem(HIDE_GUI_STORAGE_KEY, hideGuiEnabled ? '1' : '0');
        }
    } catch (e) { /* private mode */ }
    syncHideGuiUi();
}

function toggleHideGui() {
    setHideGuiEnabled(!hideGuiEnabled);
}

/** Drag snap: toolbar toggle, Alt/Ctrl inverts (bypass when Snap is on). */
function sceneSnapForEvent(ev) {
    var bypass = !!(ev && (ev.altKey || ev.ctrlKey));
    return bypass ? !isSceneSnapEnabled() : isSceneSnapEnabled();
}

function bindStudioToolsBar() {
    var snapBtn = document.getElementById('btn-snap-toggle');
    if (snapBtn && !snapBtn._bound) {
        snapBtn._bound = true;
        snapBtn.addEventListener('click', function () { toggleSceneSnap(); });
    }
    var srcBtn = document.getElementById('btn-snap-source');
    if (srcBtn && !srcBtn._bound) {
        srcBtn._bound = true;
        srcBtn.addEventListener('click', function () { snapSelectedLayerToGrid(); });
    }
    document.querySelectorAll('.toolbar-align[data-align]').forEach(function (btn) {
        if (btn._bound) return;
        btn._bound = true;
        btn.addEventListener('click', function () {
            alignSelectedLayer(btn.getAttribute('data-align'));
        });
    });
    var hideBtn = document.getElementById('btn-hide-gui');
    if (hideBtn && !hideBtn._bound) {
        hideBtn._bound = true;
        hideBtn.addEventListener('click', function () { toggleHideGui(); });
    }
    var dockBtn = document.getElementById('btn-dock-toggle');
    if (dockBtn && !dockBtn._bound) {
        dockBtn._bound = true;
        dockBtn.addEventListener('click', function () { toggleStudioDock(); });
    }
    syncSnapToggleUi();
    syncHideGuiUi();
    syncStudioDockUi();
}

function nextLayerId() {
    return 'ly' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
}

function programFps() {
    return studioHasVisibleScreen() ? PROGRAM_FPS_SCREEN : PROGRAM_FPS_CAMERA;
}

/** Mix/WHIP composite size. Program plate may be 1080p; a visible screen forces ≤1280×720. */
function publishMixSize() {
    var size = (typeof publishOutputSize === 'function')
        ? publishOutputSize()
        : { w: 1280, h: 720 };
    var w = size.w || 1280;
    var h = size.h || 720;
    if (studioHasVisibleScreen()) {
        if (w > MIX_SCREEN_MAX_W) {
            h = Math.round(h * MIX_SCREEN_MAX_W / w);
            w = MIX_SCREEN_MAX_W;
        }
        if (h > MIX_SCREEN_MAX_H) {
            w = Math.round(w * MIX_SCREEN_MAX_H / h);
            h = MIX_SCREEN_MAX_H;
        }
    }
    return { w: w, h: h };
}

function mixPublishSignature() {
    var size = publishMixSize();
    var ids = studioLayers.filter(function (l) {
        return l && l.visible && isSourceType(l.type);
    }).map(function (l) { return l.id; }).join(',');
    return [studioPublishKind(), programFps(), size.w, size.h, ids].join(':');
}

function syncMixCanvasSize() {
    if (!mixCanvas) return;
    var size = publishMixSize();
    var w = size.w || 1280;
    var h = size.h || 720;
    if (mixCanvas.width !== w || mixCanvas.height !== h) {
        mixCanvas.width = w;
        mixCanvas.height = h;
        renderSceneHandles();
    }
}

function findLayer(id) {
    var i;
    for (i = 0; i < studioLayers.length; i++) {
        if (studioLayers[i].id === id) return studioLayers[i];
    }
    return null;
}

function isOverlayType(type) {
    return type === 'text' || type === 'image';
}

function isSourceType(type) {
    return type === 'screen' || type === 'camera-extra' || type === 'camera-face' || type === 'file';
}

function isCameraLayerType(type) {
    return type === 'camera-face' || type === 'camera-extra';
}

function isCameraLayer(l) {
    return !!(l && isCameraLayerType(l.type));
}

function studioHasCameraLayer() {
    return studioLayers.some(isCameraLayer);
}

function cameraSelectShouldIncludeOff() {
    if (typeof isFileSource === 'function' && isFileSource()) return false;
    return !studioHasCameraLayer();
}

function layerVideoDeviceId(layer) {
    if (!layer) return '';
    if (layer.deviceId) return layer.deviceId;
    var stream = layer.stream || (layer.type === 'camera-face' && typeof localStream !== 'undefined' ? localStream : null);
    var t = stream && stream.getVideoTracks && stream.getVideoTracks()[0];
    try {
        var s = t && t.getSettings && t.getSettings();
        if (s && s.deviceId) return s.deviceId;
    } catch (e) { /* ignore */ }
    return '';
}

function layerAudioDeviceId(layer) {
    if (!layer) return '';
    if (layer.audioDeviceId) return layer.audioDeviceId;
    var stream = layer.stream || (layer.type === 'camera-face' && typeof localStream !== 'undefined' ? localStream : null);
    var t = stream && stream.getAudioTracks && stream.getAudioTracks()[0];
    try {
        var s = t && t.getSettings && t.getSettings();
        if (s && s.deviceId) return s.deviceId;
    } catch (e) { /* ignore */ }
    return '';
}

function captureLayerDeviceIds(layer, stream) {
    if (!layer) return;
    var src = stream || layer.stream;
    if (!src) return;
    try {
        var vt = src.getVideoTracks && src.getVideoTracks()[0];
        var vs = vt && vt.getSettings && vt.getSettings();
        if (vs && vs.deviceId) layer.deviceId = vs.deviceId;
    } catch (e) { /* ignore */ }
    try {
        var at = src.getAudioTracks && src.getAudioTracks()[0];
        var as = at && at.getSettings && at.getSettings();
        if (as && as.deviceId) layer.audioDeviceId = as.deviceId;
    } catch (e2) { /* ignore */ }
}

function selectedCameraLayer() {
    var sel = selectedLayerId ? findLayer(selectedLayerId) : null;
    if (isCameraLayer(sel)) return sel;
    var cams = studioLayers.filter(isCameraLayer);
    if (!cams.length) return null;
    cams.sort(function (a, b) { return (b.z || 0) - (a.z || 0); });
    return cams[0];
}

function withSelectSilent(el, fn) {
    if (!el) {
        fn();
        return;
    }
    var prev = el.onchange;
    el.onchange = null;
    try { fn(); } finally { el.onchange = prev; }
}

function stripCameraOffOptions() {
    if (typeof cameraSelect === 'undefined' || !cameraSelect || !cameraSelect.options) return;
    var i;
    for (i = cameraSelect.options.length - 1; i >= 0; i--) {
        var opt = cameraSelect.options[i];
        if (!opt) continue;
        var text = String(opt.textContent || opt.text || '').replace(/\s+/g, ' ').trim();
        if (opt.value === '' || /^camera off$/i.test(text) || /^loading/i.test(text)) {
            if (typeof cameraSelect.remove === 'function') cameraSelect.remove(i);
            else if (opt.parentNode) opt.parentNode.removeChild(opt);
            else if (cameraSelect.options.splice) cameraSelect.options.splice(i, 1);
        }
    }
}

function ensureCameraOffOption() {
    if (typeof cameraSelect === 'undefined' || !cameraSelect) return;
    var i;
    if (cameraSelect.options) {
        for (i = 0; i < cameraSelect.options.length; i++) {
            var existing = cameraSelect.options[i];
            if (existing && existing.value === '') {
                existing.textContent = 'Camera off';
                return;
            }
        }
    }
    var keep = cameraSelect.value;
    var opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Camera off';
    if (cameraSelect.firstChild) cameraSelect.insertBefore(opt, cameraSelect.firstChild);
    else cameraSelect.appendChild(opt);
    if (keep) cameraSelect.value = keep;
}

function syncCameraSelectOffOption() {
    if (typeof isFileSource === 'function' && isFileSource()) return;
    if (typeof cameraSelect === 'undefined' || !cameraSelect) return;
    if (studioHasCameraLayer()) stripCameraOffOptions();
    else ensureCameraOffOption();
}

function setSelectValueSilent(el, value) {
    if (!el) return;
    withSelectSilent(el, function () {
        var has = false;
        var i;
        if (el.options) {
            for (i = 0; i < el.options.length; i++) {
                if (el.options[i].value === value) { has = true; break; }
            }
        }
        if (has || value === '') el.value = value;
    });
}

function firstNonEmptySelectValue(el) {
    if (!el || !el.options) return '';
    var i;
    for (i = 0; i < el.options.length; i++) {
        if (el.options[i] && el.options[i].value) return el.options[i].value;
    }
    return '';
}

function syncDeviceDropdownsToSelectedLayer() {
    syncCameraSelectOffOption();
    var camLayer = selectedCameraLayer();
    if (typeof cameraSelect !== 'undefined' && cameraSelect) {
        if (camLayer) {
            var vid = layerVideoDeviceId(camLayer);
            if (vid) setSelectValueSilent(cameraSelect, vid);
            else if (cameraSelect.value === '') {
                var fallback = firstNonEmptySelectValue(cameraSelect);
                if (fallback) setSelectValueSilent(cameraSelect, fallback);
            }
        }
    }
    var bind = selectedLayerId ? findLayer(selectedLayerId) : null;
    if (!isCameraLayer(bind)) bind = camLayer;
    if (typeof micSelect !== 'undefined' && micSelect && isCameraLayer(bind)) {
        var aid = layerAudioDeviceId(bind);
        if (aid) setSelectValueSilent(micSelect, aid);
    }
}

/** Routing for #camera-select. Empty value is never a global off while cameras exist. */
function cameraSelectChangeAction(deviceId) {
    if (typeof isFileSource === 'function' && isFileSource()) return { action: 'file', layer: null };
    if (!deviceId) {
        if (studioHasCameraLayer()) return { action: 'keep', layer: selectedCameraLayer() };
        return { action: 'off', layer: null };
    }
    var layer = selectedCameraLayer();
    if (layer) return { action: 'replace', layer: layer };
    return { action: 'create', layer: null };
}

function onCameraSelectChange() {
    var deviceId = (typeof cameraSelect !== 'undefined' && cameraSelect) ? cameraSelect.value : '';
    var act = cameraSelectChangeAction(deviceId);
    if (act.action === 'file') {
        if (typeof startPreview === 'function') startPreview();
        return;
    }
    if (act.action === 'keep') {
        syncDeviceDropdownsToSelectedLayer();
        return;
    }
    if (act.action === 'off') {
        setCameraFaceWanted(false);
        return;
    }
    if (act.action === 'create') {
        setCameraFaceWanted(true);
        if (typeof startPreview === 'function') startPreview();
        return;
    }
    if (act.action === 'replace' && act.layer) {
        replaceLayerVideoDevice(act.layer, deviceId);
    }
}

function onMicSelectChange() {
    if (typeof isFileSource === 'function' && isFileSource()) {
        if (typeof startPreview === 'function') startPreview();
        return;
    }
    var deviceId = (typeof micSelect !== 'undefined' && micSelect) ? micSelect.value : '';
    var sel = selectedLayerId ? findLayer(selectedLayerId) : null;
    if (isCameraLayer(sel)) {
        replaceLayerAudioDevice(sel, deviceId);
        return;
    }
    if (typeof startPreview === 'function') startPreview();
}

function cameraVideoConstraints(layer, deviceId) {
    var size = (typeof publishOutputSize === 'function')
        ? publishOutputSize()
        : { w: 1280, h: 720 };
    var face = layer && layer.type === 'camera-face';
    return {
        deviceId: deviceId ? { exact: deviceId } : undefined,
        width: { ideal: face ? (size.w || 1280) : 640 },
        height: { ideal: face ? (size.h || 720) : 360 },
        frameRate: { ideal: 30, max: 30 }
    };
}

function micAudioConstraints(deviceId) {
    var audio = {
        channelCount: 1,
        sampleRate: 48000,
        echoCancellation: false,
        noiseSuppression: false,
        autoGainControl: false
    };
    if (deviceId) audio.deviceId = { exact: deviceId };
    return audio;
}

async function replaceLayerVideoDevice(layer, deviceId) {
    if (!layer || !isCameraLayer(layer) || !deviceId) return false;
    layer.deviceId = deviceId;
    if (layer.type === 'camera-face'
        && typeof startPreview === 'function'
        && (typeof isPublishLocked !== 'function' || !isPublishLocked())) {
        setCameraFaceWanted(true);
        await startPreview();
        captureLayerDeviceIds(layer, typeof localStream !== 'undefined' ? localStream : layer.stream);
        if (typeof cameraSelect !== 'undefined' && cameraSelect && cameraSelect.selectedOptions && cameraSelect.selectedOptions[0]) {
            layer.label = cameraSelect.selectedOptions[0].textContent || layer.label;
        }
        renderLayerLists();
        return true;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return false;
    var constraints = { video: cameraVideoConstraints(layer, deviceId), audio: false };
    var micId = layer.audioDeviceId || (layer.type === 'camera-face' && typeof micSelect !== 'undefined' && micSelect ? micSelect.value : '');
    if (micId) constraints.audio = micAudioConstraints(micId);
    try {
        var stream = await navigator.mediaDevices.getUserMedia(constraints);
        if (typeof preferHardwareVideoTrack === 'function') {
            stream.getVideoTracks().forEach(preferHardwareVideoTrack);
        }
        var old = layer.stream;
        if (layer.type === 'camera-face') {
            if (typeof localStream !== 'undefined' && localStream && localStream !== stream) {
                localStream.getTracks().forEach(function (t) {
                    try { t.stop(); } catch (e) { /* ignore */ }
                });
            }
            localStream = stream;
            layer.stream = stream;
            if (preview) {
                preview.srcObject = stream;
                preview.playsInline = true;
                preview.play().catch(function () {});
            }
        } else {
            layer.stream = stream;
            if (old && old !== stream && old !== localStream) {
                try { old.getTracks().forEach(function (t) { t.stop(); }); } catch (e2) { /* ignore */ }
            }
            if (layer.video) {
                layer.video.srcObject = stream;
                layer.video.play().catch(function () {});
            }
        }
        captureLayerDeviceIds(layer, stream);
        if (typeof cameraSelect !== 'undefined' && cameraSelect && cameraSelect.selectedOptions && cameraSelect.selectedOptions[0]) {
            layer.label = cameraSelect.selectedOptions[0].textContent || layer.label;
        }
        renderLayerLists();
        renderSceneHandles();
        updateMixPresentation();
        if (typeof refreshLivePublish === 'function') refreshLivePublish();
        return true;
    } catch (e) {
        if (statusEl) {
            statusEl.textContent = 'Camera failed: ' + e.message;
            statusEl.classList.add('error');
        }
        syncDeviceDropdownsToSelectedLayer();
        return false;
    }
}

async function replaceLayerAudioDevice(layer, deviceId) {
    if (!layer || !isCameraLayer(layer)) return false;
    layer.audioDeviceId = deviceId || '';
    if (layer.type === 'camera-face'
        && typeof startPreview === 'function'
        && (typeof isPublishLocked !== 'function' || !isPublishLocked())) {
        await startPreview();
        captureLayerDeviceIds(layer, typeof localStream !== 'undefined' ? localStream : layer.stream);
        return true;
    }
    if (!layer.stream) return false;
    if (!deviceId) {
        if (layer.stream.getAudioTracks) {
            layer.stream.getAudioTracks().forEach(function (t) {
                try { t.stop(); } catch (e) { /* ignore */ }
                try { layer.stream.removeTrack(t); } catch (e2) { /* ignore */ }
            });
        }
        return true;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return false;
    try {
        var astream = await navigator.mediaDevices.getUserMedia({
            audio: micAudioConstraints(deviceId),
            video: false
        });
        var at = astream.getAudioTracks()[0];
        if (!at) return false;
        layer.stream.getAudioTracks().forEach(function (t) {
            try { t.stop(); } catch (e) { /* ignore */ }
            try { layer.stream.removeTrack(t); } catch (e2) { /* ignore */ }
        });
        layer.stream.addTrack(at);
        captureLayerDeviceIds(layer, layer.stream);
        if (typeof refreshLivePublish === 'function') refreshLivePublish();
        return true;
    } catch (e) {
        if (statusEl) {
            statusEl.textContent = 'Mic failed: ' + e.message;
            statusEl.classList.add('error');
        }
        return false;
    }
}

function isFullBleed(layer) {
    if (!layer) return false;
    var x = layer.x != null ? layer.x : 0;
    var y = layer.y != null ? layer.y : 0;
    var w = layer.w != null ? layer.w : 1;
    var h = layer.h != null ? layer.h : 1;
    return Math.abs(x) < 0.015 && Math.abs(y) < 0.015 && Math.abs(w - 1) < 0.015 && Math.abs(h - 1) < 0.015;
}

function studioMixActive() {
    var vis = studioLayers.filter(function (l) { return l.visible; });
    if (vis.some(function (l) { return isOverlayType(l.type); })) return true;
    var srcs = vis.filter(function (l) { return isSourceType(l.type); });
    if (srcs.length >= 2) return true;
    /* Extra camera PIP always mixes. A lone full-bleed screen publishes the display track. */
    if (srcs.some(function (l) { return l.type === 'camera-extra'; })) return true;
    if (srcs.some(function (l) { return !isFullBleed(l); })) return true;
    return false;
}

function studioHasVisibleScreen() {
    return studioLayers.some(function (l) { return l.visible && l.type === 'screen'; });
}

/** Single visible camera (full-bleed, no overlays) — publish that track, do not rAF-composite. */
function singleVisibleCameraStream() {
    return nativeCameraPublishStream();
}

/**
 * Native camera MediaStream for WHIP once no type=screen layer remains.
 * Same track the dual-cam camera sender uses. PIP size / overlays may still
 * draw in the local preview; they must not switch WHIP to mixCanvas.
 */
function nativeCameraPublishStream() {
    if (typeof isFileSource === 'function' && isFileSource()) return null;
    if (studioHasVisibleScreen()) return null;
    var layer = getStudioCameraLayer();
    /* Only a visible camera layer may go on WHIP. Do not fall back to
     * localStream after the user Hide/Remove'd camera-face. */
    if (!layer || !layer.visible) return null;
    var stream = layer.stream || (layer.type === 'camera-face' && typeof localStream !== 'undefined' ? localStream : null);
    if (stream && stream.getVideoTracks) {
        var t = stream.getVideoTracks()[0];
        if (t && t.readyState === 'live') return stream;
    }
    return null;
}

/** Single visible full-bleed screen (camera hidden / absent, no overlays) — preview can show this track. */
function singleVisibleScreenStream() {
    if (typeof isFileSource === 'function' && isFileSource()) return null;
    var vis = studioLayers.filter(function (l) { return l.visible; });
    if (vis.some(function (l) { return isOverlayType(l.type); })) return null;
    var srcs = vis.filter(function (l) { return isSourceType(l.type); });
    if (srcs.length !== 1) return null;
    var only = srcs[0];
    if (only.type !== 'screen') return null;
    if (!isFullBleed(only)) return null;
    return only.stream || null;
}

/**
 * Native getDisplayMedia for WHIP whenever a visible full-bleed screen exists.
 * Camera-face / extra cam / overlays may still be listed and drawn in the
 * local preview. They MUST NOT switch WHIP to mixCanvas.captureStream or
 * insertable streams. Screen-only and screen+camera publish the same display
 * track. Viewers get the native screen until a non-browser compositor exists.
 */
function fullBleedScreenStream() {
    if (typeof isFileSource === 'function' && isFileSource()) return null;
    var screens = studioLayers.filter(function (l) {
        return l.visible && l.type === 'screen' && isFullBleed(l) && l.stream;
    });
    if (!screens.length) return null;
    screens.sort(function (a, b) { return a.z - b.z; });
    return screens[0].stream;
}

function studioPublishKind() {
    if (typeof isFileSource === 'function' && isFileSource()) return 'file';
    if (fullBleedScreenStream() || nativeScreenPublishStream()) return 'screen';
    if (nativeCameraPublishStream()) return 'camera';
    if (studioMixActive()) return 'mix';
    return 'camera';
}

/** Display capture size from #screen-resolution, not the program plate. */
function screenCaptureSize() {
    var sel = document.getElementById('screen-resolution');
    var raw = (sel && sel.value) ? sel.value : '1280x720';
    if (raw === 'native' || raw === '') return null;
    var parts = raw.split('x').map(Number);
    var w = parts[0] || 1280;
    var h = parts[1] || 720;
    return { w: w, h: h };
}

function screenVideoConstraints() {
    var size = screenCaptureSize();
    var fps = PROGRAM_FPS_SCREEN;
    var video = {
        frameRate: { ideal: fps, max: fps }
    };
    if (size) {
        video.width = { ideal: size.w, max: size.w };
        video.height = { ideal: size.h, max: size.h };
        video.resizeMode = 'crop-and-scale';
    }
    return video;
}

function applyPublishVideoHint(stream) {
    if (!stream || !stream.getVideoTracks) return;
    var hint = studioHasVisibleScreen() ? 'detail' : 'motion';
    stream.getVideoTracks().forEach(function (t) {
        try { t.contentHint = hint; } catch (e) { /* older browsers */ }
    });
}

async function constrainScreenTracks(stream) {
    if (!stream) return;
    var cons = screenVideoConstraints();
    try { window.__lastScreenConstraints = cons; } catch (eLast) { /* ignore */ }
    var tracks = stream.getVideoTracks();
    var i;
    for (i = 0; i < tracks.length; i++) {
        var t = tracks[i];
        try { t.contentHint = 'detail'; } catch (eHint) { /* older browsers */ }
        try {
            await t.applyConstraints(cons);
        } catch (e2) {
            try {
                if (cons.width && cons.height) {
                    await t.applyConstraints({
                        width: { ideal: cons.width.ideal },
                        height: { ideal: cons.height.ideal },
                        frameRate: { ideal: PROGRAM_FPS_SCREEN, max: PROGRAM_FPS_SCREEN }
                    });
                } else {
                    await t.applyConstraints({ frameRate: { ideal: PROGRAM_FPS_SCREEN, max: PROGRAM_FPS_SCREEN } });
                }
            } catch (e3) { /* keep whatever the browser granted */ }
        }
    }
}

function applyLiveScreenResolution() {
    var screens = studioLayers.filter(function (l) { return l.type === 'screen' && l.stream; });
    var p = Promise.resolve();
    screens.forEach(function (l) {
        p = p.then(function () { return constrainScreenTracks(l.stream); });
    });
    return p.then(function () {
        try {
            console.log('[broadcast] screen-resolution applied', JSON.stringify({
                value: (document.getElementById('screen-resolution') || {}).value || '',
                size: screenCaptureSize(),
                screens: screens.length
            }));
        } catch (eLog) { /* ignore */ }
        return true;
    }).catch(function () { return false; });
}

function withPublishAudio(videoStream) {
    if (!videoStream) return videoStream;
    var audioSrc = (typeof localStream !== 'undefined') ? localStream : null;
    if (audioSrc) {
        audioSrc.getAudioTracks().forEach(function (t) {
            if (videoStream.getAudioTracks().length === 0) {
                videoStream.addTrack(t);
            }
        });
    }
    if (videoStream.getAudioTracks().length === 0 && typeof ensureAudioTrack === 'function') {
        return ensureAudioTrack(videoStream);
    }
    return videoStream;
}

function mixCaptureFps() {
    return programFps();
}

function resetMixPublishStream() {
    if (mixCaptureStream) {
        try {
            mixCaptureStream.getVideoTracks().forEach(function (t) { t.stop(); });
        } catch (e) { /* ignore */ }
    }
    mixCaptureStream = null;
    window.mixCaptureStream = null;
}

function studioHasVisibleCamera() {
    return studioLayers.some(function (l) {
        return l.visible && (l.type === 'camera-face' || l.type === 'camera-extra');
    });
}

/** Local program plate: composite layers (including a lone camera at its x/y/w/h).
 *  Independent of WHIP — camera-only still publishes the native camera track. */
function previewNeedsDraw() {
    if (sceneToast) return true;
    if (studioMixActive()) return true;
    return studioHasVisibleCamera();
}

function setProgramMixVisible(on) {
    if (mixCanvas) mixCanvas.style.visibility = on ? 'visible' : 'hidden';
    if (previewMirror) {
        if (on) {
            previewMirror.classList.add('program-mix', 'no-mirror');
        } else {
            previewMirror.classList.remove('program-mix');
        }
    }
}

function startPreviewLoop() {
    if (previewLoopOn) {
        paintSceneNow();
        return;
    }
    previewLoopOn = true;
    lastMixTs = 0;
    function tick(now) {
        if (!previewLoopOn) return;
        sceneRaf = requestAnimationFrame(tick);
        if (!previewNeedsDraw()) return;
        var minMs = 1000 / PREVIEW_FPS;
        if (lastMixTs && (now - lastMixTs) < minMs) return;
        lastMixTs = now;
        paintSceneNow();
    }
    if (sceneRaf) cancelAnimationFrame(sceneRaf);
    sceneRaf = requestAnimationFrame(tick);
}

function stopPreviewLoop() {
    previewLoopOn = false;
    if (sceneRaf) {
        cancelAnimationFrame(sceneRaf);
        sceneRaf = 0;
    }
}

function restoreCameraPreview() {
    if (!preview || typeof isFileSource === 'function' && isFileSource()) return;
    if (typeof localStream !== 'undefined' && localStream && preview.srcObject !== localStream) {
        preview.srcObject = localStream;
        preview.play().catch(function () {});
    }
}

function getStudioCameraLayer() {
    var cams = studioLayers.filter(function (l) {
        return l && (l.type === 'camera-face' || l.type === 'camera-extra');
    });
    if (!cams.length) return null;
    var vis = cams.filter(function (l) { return l.visible; });
    var list = vis.length ? vis : cams;
    list.sort(function (a, b) { return (b.z || 0) - (a.z || 0); });
    return list[0];
}

function getStudioCameraTrack() {
    var layer = getStudioCameraLayer();
    if (!layer || !layer.visible) return null;
    var stream = layer.stream || (layer.type === 'camera-face' && typeof localStream !== 'undefined' ? localStream : null);
    if (!stream || !stream.getVideoTracks) return null;
    var t = stream.getVideoTracks()[0];
    return t && t.readyState === 'live' ? t : null;
}

var MAX_SCENE_VIDEO_TRACKS = 4;

function layerNativeVideoTrack(layer) {
    if (!layer || !layer.visible) return null;
    var stream = layer.stream || null;
    if (!stream && layer.type === 'camera-face' && typeof localStream !== 'undefined') {
        stream = localStream;
    }
    if (!stream || !stream.getVideoTracks) return null;
    var t = stream.getVideoTracks()[0];
    return t && t.readyState === 'live' ? t : null;
}

/** Visible video sources as native tracks, screen first, then z-order. Never a canvas mix. */
function getStudioPublishVideoLayers() {
    var out = [];
    if (typeof isFileSource === 'function' && isFileSource()) {
        var fileLayer = studioLayers.filter(function (l) {
            return l.visible && l.type === 'file';
        })[0];
        var fileTrack = layerNativeVideoTrack(fileLayer);
        if (!fileTrack && typeof localStream !== 'undefined' && localStream && localStream.getVideoTracks) {
            fileTrack = localStream.getVideoTracks()[0];
            if (fileTrack && fileTrack.readyState !== 'live') fileTrack = null;
        }
        if (fileTrack) {
            out.push({
                layer: fileLayer || { id: 'file-main', type: 'file', x: 0, y: 0, w: 1, h: 1, z: 0, visible: true },
                track: fileTrack
            });
        }
        return out.slice(0, MAX_SCENE_VIDEO_TRACKS);
    }
    var vis = studioLayers.filter(function (l) { return l.visible && isSourceType(l.type); });
    vis.sort(function (a, b) { return (a.z || 0) - (b.z || 0); });
    var screens = vis.filter(function (l) { return l.type === 'screen' && layerNativeVideoTrack(l); });
    var seen = {};
    function pushLayer(layer) {
        if (!layer || seen[layer.id]) return;
        var t = layerNativeVideoTrack(layer);
        if (!t) return;
        seen[layer.id] = true;
        out.push({ layer: layer, track: t });
    }
    if (screens.length) pushLayer(screens[0]);
    vis.forEach(pushLayer);
    return out.slice(0, MAX_SCENE_VIDEO_TRACKS);
}

function nativeScreenPublishStream() {
    if (typeof isFileSource === 'function' && isFileSource()) return null;
    var screens = studioLayers.filter(function (l) {
        return l.visible && l.type === 'screen' && l.stream;
    });
    if (!screens.length) return null;
    screens.sort(function (a, b) { return (a.z || 0) - (b.z || 0); });
    return screens[0].stream;
}

function studioSceneLayout() {
    var size = (typeof publishOutputSize === 'function') ? publishOutputSize() : { w: 1280, h: 720 };
    var pubs = getStudioPublishVideoLayers();
    return {
        plate_w: size.w || 1280,
        plate_h: size.h || 720,
        layers: pubs.map(function (p, i) {
            var l = p.layer || {};
            return {
                id: l.id || ('v' + i),
                type: l.type || 'camera-face',
                x: l.x != null ? l.x : 0,
                y: l.y != null ? l.y : 0,
                w: l.w != null ? l.w : 1,
                h: l.h != null ? l.h : 1,
                visible: true,
                track: i,
                z: l.z || 0
            };
        })
    };
}

function studioCameraLayout() {
    var scene = studioSceneLayout();
    var cam = null;
    var i;
    for (i = 0; i < scene.layers.length; i++) {
        if (scene.layers[i].type === 'camera-face' || scene.layers[i].type === 'camera-extra') {
            cam = scene.layers[i];
            break;
        }
    }
    if (!cam) {
        return { x: 0.70, y: 0.64, w: 0.28, h: 0.32, visible: false };
    }
    return {
        x: cam.x,
        y: cam.y,
        w: cam.w,
        h: cam.h,
        visible: !!cam.visible
    };
}

var cameraLayoutTimer = null;
var lastCameraLayoutJSON = '';

function publishStudioCameraLayout() {
    if (typeof isPublishLocked === 'function' && !isPublishLocked()) return;
    var key = (typeof authenticatedKey !== 'undefined' && authenticatedKey) ||
        (typeof activeStreamKey !== 'undefined' && activeStreamKey) || '';
    if (!key) return;
    var scene = studioSceneLayout();
    var cam = studioCameraLayout();
    var payload = {
        plate_w: scene.plate_w,
        plate_h: scene.plate_h,
        layers: scene.layers,
        x: cam.x,
        y: cam.y,
        w: cam.w,
        h: cam.h,
        visible: cam.visible
    };
    var json = JSON.stringify(payload);
    if (json === lastCameraLayoutJSON) return;
    lastCameraLayoutJSON = json;
    fetch('/api/room_camera/' + encodeURIComponent(key), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: json
    }).catch(function () { /* ignore */ });
}

function scheduleStudioCameraLayout() {
    clearTimeout(cameraLayoutTimer);
    cameraLayoutTimer = setTimeout(function () { publishStudioCameraLayout(); }, 120);
}

function refreshLivePublish(opts) {
    opts = opts || {};
    if (typeof isPublishLocked !== 'function' || !isPublishLocked()) {
        lastLivePublishKind = null;
        return Promise.resolve(false);
    }
    if (typeof replaceLiveVideoTrack !== 'function') return Promise.resolve(false);
    var kind = studioPublishKind();
    var sig = mixPublishSignature();
    if (opts.kindChangeOnly && lastLivePublishSig && lastLivePublishSig === sig) {
        scheduleStudioCameraLayout();
        return Promise.resolve(true);
    }
    var stream = getStudioPublishStream();
    /* Drop/replace even when there is no remaining video (audio-only / null). */
    return Promise.resolve(replaceLiveVideoTrack(stream || null)).then(function (ok) {
        var camP = (typeof syncLiveCameraTrack === 'function')
            ? Promise.resolve(syncLiveCameraTrack())
            : Promise.resolve(true);
        return camP.then(function () { return ok; });
    }).then(function (ok) {
        if (ok) {
            lastLivePublishKind = kind;
            lastLivePublishSig = sig;
            if (kind !== 'mix') {
                resetMixPublishStream();
            }
            if (previewNeedsDraw()) {
                startPreviewLoop();
            }
        }
        scheduleStudioCameraLayout();
        try {
            var cam = getStudioCameraLayer();
            console.log('[broadcast] refreshLivePublish', JSON.stringify({
                ok: !!ok,
                kind: kind,
                sig: sig,
                lastKind: lastLivePublishKind,
                previewFps: PREVIEW_FPS,
                screenDirect: !!getStudioPublishStream.screenDirect,
                mixCapture: !!getStudioPublishStream.mixCapture,
                mixActive: studioMixActive(),
                cameraVisible: !!(cam && cam.visible),
                cameraTrack: !!getStudioCameraTrack()
            }));
        } catch (eLog) { /* ignore */ }
        return ok;
    }).catch(function () { return false; });
}

function ensureLayerVideo(layer) {
    if (layer.video) {
        if (layer.stream && layer.video.srcObject !== layer.stream) {
            layer.video.srcObject = layer.stream;
            layer.video.play().catch(function () {});
        }
        return layer.video;
    }
    if (layer.videoFile) return layer.videoFile;
    if (!layer.stream) return null;
    var v = document.createElement('video');
    v.autoplay = true;
    v.muted = true;
    v.playsInline = true;
    v.srcObject = layer.stream;
    v.play().catch(function () {});
    if (sceneOffscreen) sceneOffscreen.appendChild(v);
    layer.video = v;
    return v;
}

function layoutRect(layer, cw, ch) {
    var x = layer.x != null ? layer.x : 0;
    var y = layer.y != null ? layer.y : 0;
    var w = layer.w != null ? layer.w : 1;
    var h = layer.h != null ? layer.h : 1;
    return { x: x * cw, y: y * ch, w: w * cw, h: h * ch };
}

function clampLayerRect(r) {
    var minW = 0.06;
    var minH = 0.06;
    r.w = Math.max(minW, Math.min(1.6, r.w));
    r.h = Math.max(minH, Math.min(1.6, r.h));
    r.x = Math.max(-r.w + 0.04, Math.min(0.96, r.x));
    r.y = Math.max(-r.h + 0.04, Math.min(0.96, r.y));
    return r;
}

function snapGridValue(v) {
    if (typeof v !== 'number' || !isFinite(v)) return v;
    return Math.round(v / SCENE_GRID) * SCENE_GRID;
}

function snapLayerRect(r) {
    r.x = snapGridValue(r.x);
    r.y = snapGridValue(r.y);
    r.w = snapGridValue(r.w);
    r.h = snapGridValue(r.h);
    return r;
}

function alignLayerRect(r, edge) {
    r = { x: r.x, y: r.y, w: r.w, h: r.h };
    if (edge === 'left') r.x = 0;
    else if (edge === 'center') r.x = (1 - r.w) / 2;
    else if (edge === 'right') r.x = 1 - r.w;
    else if (edge === 'top') r.y = 0;
    else if (edge === 'middle') r.y = (1 - r.h) / 2;
    else if (edge === 'bottom') r.y = 1 - r.h;
    return r;
}

function snapSelectedLayerToGrid() {
    var layer = selectedLayerId ? findLayer(selectedLayerId) : null;
    if (!layer) return null;
    var r = clampLayerRect(snapLayerRect({
        x: layer.x != null ? layer.x : 0,
        y: layer.y != null ? layer.y : 0,
        w: layer.w != null ? layer.w : 1,
        h: layer.h != null ? layer.h : 1
    }));
    return setLayerRect(layer.id, r.x, r.y, r.w, r.h);
}

function alignSelectedLayer(edge) {
    var layer = selectedLayerId ? findLayer(selectedLayerId) : null;
    if (!layer) return null;
    var r = alignLayerRect({
        x: layer.x != null ? layer.x : 0,
        y: layer.y != null ? layer.y : 0,
        w: layer.w != null ? layer.w : 1,
        h: layer.h != null ? layer.h : 1
    }, edge);
    return setLayerRect(layer.id, r.x, r.y, r.w, r.h);
}

function applyFreeLayerDelta(o, dx, dy, mode) {
    var r = { x: o.x, y: o.y, w: o.w, h: o.h };
    if (mode === 'move') {
        r.x = o.x + dx;
        r.y = o.y + dy;
    } else if (mode === 'se') {
        r.w = o.w + dx;
        r.h = o.h + dy;
    } else if (mode === 'sw') {
        r.x = o.x + dx;
        r.w = o.w - dx;
        r.h = o.h + dy;
    } else if (mode === 'ne') {
        r.y = o.y + dy;
        r.w = o.w + dx;
        r.h = o.h - dy;
    } else if (mode === 'nw') {
        r.x = o.x + dx;
        r.y = o.y + dy;
        r.w = o.w - dx;
        r.h = o.h - dy;
    } else if (mode === 'n') {
        r.y = o.y + dy;
        r.h = o.h - dy;
    } else if (mode === 's') {
        r.h = o.h + dy;
    } else if (mode === 'e') {
        r.w = o.w + dx;
    } else if (mode === 'w') {
        r.x = o.x + dx;
        r.w = o.w - dx;
    }
    return r;
}

/** Keep |w|/|h| = aspect; opposite corner of orig stays put. */
function constrainLayerAspect(r, o, mode, aspect) {
    if (!(aspect > 0) || !isFinite(aspect) || mode === 'move') return r;
    aspect = Math.abs(aspect);
    var signW = r.w < 0 ? -1 : 1;
    var signH = r.h < 0 ? -1 : 1;
    var tw = Math.abs(r.w);
    var th = Math.abs(r.h);
    if (tw < 1e-9 && th < 1e-9) {
        tw = Math.abs(o.w) || 1;
        th = Math.abs(o.h) || 1;
    }
    var hFromW = tw / aspect;
    var wFromH = th * aspect;
    if (Math.abs(hFromW - th) <= Math.abs(wFromH - tw)) th = hFromW;
    else tw = wFromH;
    r.w = tw * signW;
    r.h = th * signH;
    var right = o.x + o.w;
    var bottom = o.y + o.h;
    if (mode === 'se' || mode === 'ne' || mode === 'e') r.x = o.x;
    else if (mode === 'sw' || mode === 'nw' || mode === 'w') r.x = right - r.w;
    if (mode === 'se' || mode === 'sw' || mode === 's') r.y = o.y;
    else if (mode === 'ne' || mode === 'nw' || mode === 'n') r.y = bottom - r.h;
    return r;
}

function computeLayerDragRect(o, dx, dy, mode, opts) {
    opts = opts || {};
    var r = applyFreeLayerDelta(o, dx, dy, mode);
    var lockAspect = opts.lockAspect;
    if (opts.shift && mode !== 'move') {
        if (!(lockAspect > 0) || !isFinite(lockAspect)) {
            lockAspect = (Math.abs(r.h) > 1e-9) ? (r.w / r.h) : (o.h ? o.w / o.h : 1);
            if (!(lockAspect > 0) || !isFinite(lockAspect)) lockAspect = 1;
        }
        constrainLayerAspect(r, o, mode, lockAspect);
    } else {
        lockAspect = null;
    }
    if (opts.snap) {
        if (mode === 'move') {
            r.x = snapGridValue(r.x);
            r.y = snapGridValue(r.y);
        } else {
            snapLayerRect(r);
        }
    }
    clampLayerRect(r);
    return { x: r.x, y: r.y, w: r.w, h: r.h, lockAspect: lockAspect };
}

function setLayerRect(id, x, y, w, h) {
    var layer = findLayer(id);
    if (!layer) return null;
    var r = clampLayerRect({
        x: x != null ? x : layer.x,
        y: y != null ? y : layer.y,
        w: w != null ? w : layer.w,
        h: h != null ? h : layer.h
    });
    layer.x = r.x;
    layer.y = r.y;
    layer.w = r.w;
    layer.h = r.h;
    updateMixPresentation();
    renderSceneHandles();
    refreshLivePublish({ kindChangeOnly: true });
    scheduleStudioCameraLayout();
    return layer;
}

function drawVideoInRect(ctx, video, rect) {
    if (!video || video.readyState < 2) return;
    try {
        ctx.drawImage(video, rect.x, rect.y, rect.w, rect.h);
    } catch (e) { /* decode race */ }
}

function drawLayerMedia(ctx, layer, video, rect) {
    drawVideoInRect(ctx, video, rect);
}

/** Local studio preview only. Never the WHIP source when a screen is up. */
function paintSceneNow() {
    if (!mixCtx || !mixCanvas) return;
    syncMixCanvasSize();
    var cw = mixCanvas.width;
    var ch = mixCanvas.height;
    mixCtx.fillStyle = '#111111';
    mixCtx.fillRect(0, 0, cw, ch);
    var drewVideo = false;

    var layers = studioLayers.slice().sort(function (a, b) { return a.z - b.z; });
    for (var i = 0; i < layers.length; i++) {
        var l = layers[i];
        if (!l.visible) continue;
        if (l.type === 'text') {
            var tr = layoutRect(l, cw, ch);
            var fontPx = Math.max(14, Math.round(tr.h * 0.62));
            mixCtx.font = 'bold ' + fontPx + 'px -apple-system, sans-serif';
            mixCtx.fillStyle = l.color || '#ffffff';
            mixCtx.strokeStyle = 'rgba(0,0,0,0.65)';
            mixCtx.lineWidth = Math.max(3, Math.round(fontPx * 0.12));
            mixCtx.textBaseline = 'middle';
            mixCtx.textAlign = 'left';
            var tx = tr.x + Math.max(6, tr.h * 0.08);
            var ty = tr.y + tr.h / 2;
            mixCtx.strokeText(l.text || '', tx, ty);
            mixCtx.fillText(l.text || '', tx, ty);
            continue;
        }
        if (l.type === 'image' && l.img && l.img.complete && l.img.naturalWidth) {
            var ir = layoutRect(l, cw, ch);
            mixCtx.drawImage(l.img, ir.x, ir.y, ir.w, ir.h);
            continue;
        }
        var video = null;
        if (l.type === 'file' && l.id === 'file-main' && fileSource && fileSource.readyState >= 2) {
            video = fileSource;
        } else if (l.type === 'file' && l.videoFile && l.videoFile.readyState >= 2) {
            video = l.videoFile;
        } else if (l.type === 'camera-face') {
            video = ensureLayerVideo(l);
            if ((!video || video.readyState < 2) && preview && preview.srcObject && preview.readyState >= 2 && !isFileSource()) {
                video = preview;
            }
        } else {
            video = ensureLayerVideo(l);
        }
        if (video && video.readyState >= 2) {
            drawLayerMedia(mixCtx, l, video, layoutRect(l, cw, ch));
            drewVideo = true;
        }
    }
    if (!drewVideo && preview && preview.readyState >= 2 && !(typeof isFileSource === 'function' && isFileSource())) {
        mixCtx.drawImage(preview, 0, 0, cw, ch);
        drewVideo = true;
    }
    if (mixCanvas) mixCanvas.style.visibility = drewVideo ? 'visible' : 'hidden';
    if (previewMirror) {
        if (drewVideo) {
            previewMirror.classList.add('no-mirror');
        }
    }

    if (sceneToast && Date.now() < sceneToast.until) {
        var pad = 14;
        var tw = Math.min(cw * 0.7, 520);
        var th = Math.max(48, ch * 0.1);
        var tx0 = pad;
        var ty0 = ch - th - pad;
        mixCtx.fillStyle = 'rgba(255,179,0,0.92)';
        mixCtx.fillRect(tx0, ty0, tw, th);
        mixCtx.fillStyle = '#111';
        mixCtx.font = 'bold ' + Math.max(14, Math.round(ch * 0.035)) + 'px -apple-system, sans-serif';
        mixCtx.textBaseline = 'top';
        mixCtx.textAlign = 'left';
        mixCtx.fillText(sceneToast.title || 'Donation', tx0 + 10, ty0 + 8);
        mixCtx.font = Math.max(12, Math.round(ch * 0.028)) + 'px -apple-system, sans-serif';
        mixCtx.fillText(sceneToast.body || '', tx0 + 10, ty0 + th / 2);
    }
}

function drawSceneFrame() {
    paintSceneNow();
}

function updateMixPresentation() {
    if (previewNeedsDraw()) {
        /* Keep mix + scene-handles. Never swap the plate to a raw full-bleed <video>. */
        setProgramMixVisible(true);
        startPreviewLoop();
        paintSceneNow();
        return;
    }
    var screenPub = !!fullBleedScreenStream();
    if (screenPub) {
        stopPreviewLoop();
        setProgramMixVisible(false);
        if (previewMirror) previewMirror.classList.add('no-mirror');
        var ss = fullBleedScreenStream();
        if (preview && ss && preview.srcObject !== ss) {
            preview.srcObject = ss;
            preview.play().catch(function () {});
        }
        return;
    }
    stopPreviewLoop();
    setProgramMixVisible(false);
    if (typeof isFileSource === 'function' && isFileSource()) {
        if (previewMirror) previewMirror.classList.add('no-mirror');
        return;
    }
    /* Nothing to composite: show the raw camera <video>. Hiding it here
       left a black plate when the camera-face layer was missing. */
    if (previewMirror) {
        previewMirror.classList.remove('program-mix');
        previewMirror.classList.remove('no-mirror');
    }
}

function startSceneLoop() {
    setProgramMixVisible(true);
    startPreviewLoop();
    paintSceneNow();
}

function stopSceneLoopIfIdle() {
    if (previewNeedsDraw()) {
        updateMixPresentation();
        return;
    }
    stopPreviewLoop();
    if (!isPublishLocked() || studioPublishKind() !== 'mix') {
        resetMixPublishStream();
    }
    updateMixPresentation();
}

function upsertLayer(layer) {
    var idx = -1;
    for (var i = 0; i < studioLayers.length; i++) {
        if (studioLayers[i].id === layer.id) { idx = i; break; }
    }
    if (idx >= 0) studioLayers[idx] = layer;
    else studioLayers.push(layer);
    if (!selectedLayerId) selectedLayerId = layer.id;
    renderLayerLists();
    renderSceneHandles();
    updateMixPresentation();
    if (isCameraLayer(layer)) syncDeviceDropdownsToSelectedLayer();
}

function disposeLayerMedia(l) {
    if (l.stream && l.type !== 'camera-face') {
        try {
            l.stream.getTracks().forEach(function (t) { t.stop(); });
        } catch (e) { /* already ended */ }
    }
    if (l.video && l.video.parentNode) l.video.parentNode.removeChild(l.video);
    if (l.videoFile && l.videoFile.parentNode) l.videoFile.parentNode.removeChild(l.videoFile);
    if (l.objectUrl) {
        try { URL.revokeObjectURL(l.objectUrl); } catch (e2) {}
    }
}

var layerStackPress = null;
var layerStackClickGuard = 0;

function layerStackHit(ev) {
    var t = ev && ev.target;
    if (t && t.nodeType === 3) t = t.parentNode;
    if (!t || !t.closest) return null;
    var list = t.closest('#source-layer-list, #overlay-layer-list');
    if (!list) return null;
    var btn = t.closest('[data-layer-action]');
    var row = t.closest('[data-layer]');
    var id = (btn && btn.getAttribute('data-layer')) || (row && row.getAttribute('data-layer'));
    if (!id) return null;
    return { id: id, action: btn ? btn.getAttribute('data-layer-action') : null };
}

function runLayerStackAction(id, action) {
    if (!id || !action) return false;
    if (action === 'remove') { removeLayer(id); return true; }
    if (action === 'toggle' || action === 'hide' || action === 'show') { toggleLayer(id); return true; }
    if (action === 'up') { nudgeLayerZ(id, 1); return true; }
    if (action === 'down') { nudgeLayerZ(id, -1); return true; }
    if (action === 'select') { selectLayer(id); return true; }
    return false;
}

function markSelectedLayerRows() {
    var lists = [
        document.getElementById('source-layer-list'),
        document.getElementById('overlay-layer-list')
    ];
    lists.forEach(function (list) {
        if (!list) return;
        var items = list.querySelectorAll('.layer-item[data-layer]');
        for (var i = 0; i < items.length; i++) {
            items[i].classList.toggle('selected', items[i].getAttribute('data-layer') === selectedLayerId);
        }
    });
}

function onLayerStackPointerDown(ev) {
    var hit = layerStackHit(ev);
    if (!hit || !hit.action) return;
    ev.stopPropagation();
    layerStackPress = {
        id: hit.id,
        action: hit.action,
        x: ev.clientX,
        y: ev.clientY,
        pointerId: ev.pointerId
    };
    if (ev.currentTarget && ev.pointerId != null && ev.currentTarget.setPointerCapture) {
        try { ev.currentTarget.setPointerCapture(ev.pointerId); } catch (e) { /* ignore */ }
    }
}

function onLayerStackPointerUp(ev) {
    if (!layerStackPress) return;
    if (ev.pointerId != null && layerStackPress.pointerId != null && ev.pointerId !== layerStackPress.pointerId) return;
    var press = layerStackPress;
    layerStackPress = null;
    if (ev.currentTarget && ev.pointerId != null && ev.currentTarget.releasePointerCapture) {
        try { ev.currentTarget.releasePointerCapture(ev.pointerId); } catch (e2) { /* ignore */ }
    }
    ev.stopPropagation();
    if (typeof ev.clientX === 'number' && typeof press.x === 'number') {
        var dx = ev.clientX - press.x;
        var dy = ev.clientY - press.y;
        if ((dx * dx) + (dy * dy) > 576) return;
    }
    layerStackClickGuard = Date.now();
    runLayerStackAction(press.id, press.action);
}

function onLayerStackPointerCancel(ev) {
    if (!layerStackPress) return;
    if (ev.pointerId != null && layerStackPress.pointerId != null && ev.pointerId !== layerStackPress.pointerId) return;
    layerStackPress = null;
}

function onLayerStackClick(ev) {
    if (layerStackClickGuard && (Date.now() - layerStackClickGuard) < 600) {
        ev.preventDefault();
        ev.stopPropagation();
        return;
    }
    var hit = layerStackHit(ev);
    if (!hit) return;
    if (hit.action) {
        ev.preventDefault();
        ev.stopPropagation();
        runLayerStackAction(hit.id, hit.action);
        return;
    }
    selectLayer(hit.id);
}

function bindLayerStackLists() {
    ['source-layer-list', 'overlay-layer-list'].forEach(function (id) {
        var list = document.getElementById(id);
        if (!list || list._layerStackBound) return;
        list._layerStackBound = true;
        list.addEventListener('pointerdown', onLayerStackPointerDown);
        list.addEventListener('pointerup', onLayerStackPointerUp);
        list.addEventListener('pointercancel', onLayerStackPointerCancel);
        list.addEventListener('click', onLayerStackClick);
    });
}

function applyLayerUiNow() {
    renderLayerLists();
    renderSceneHandles();
    if (previewNeedsDraw()) startSceneLoop();
    else stopSceneLoopIfIdle();
    lastCameraLayoutJSON = '';
    publishStudioCameraLayout();
}

function removeLayer(id) {
    var gone = findLayer(id);
    studioLayers = studioLayers.filter(function (l) {
        if (l.id !== id) return true;
        disposeLayerMedia(l);
        return false;
    });
    if (selectedLayerId === id) selectedLayerId = studioLayers.length ? studioLayers[studioLayers.length - 1].id : null;
    if (gone && (gone.id === 'camera-face' || gone.type === 'camera-face')) {
        cameraFaceWanted = false;
    }
    if (gone && isCameraLayer(gone) && !studioHasCameraLayer()) {
        dismissMainCameraFace();
    } else if (gone && isCameraLayer(gone)) {
        syncDeviceDropdownsToSelectedLayer();
    }
    if (gone && gone.id === 'file-main') {
        fileMainWanted = false;
    }
    /* Remaining camera keeps its x/y/w/h. Do not auto-fullscreen to 0,0,1,1.
     * UI first; WHIP replace/renegotiate follows and must not roll the row back. */
    applyLayerUiNow();
    refreshLivePublish().then(function () {
        stopDismissedCameraVideo();
        if (previewNeedsDraw()) startSceneLoop();
        else stopSceneLoopIfIdle();
    }).catch(function () {
        stopDismissedCameraVideo();
    });
}

function toggleLayer(id) {
    studioLayers.forEach(function (l) {
        if (l.id === id) l.visible = !l.visible;
    });
    applyLayerUiNow();
    refreshLivePublish().then(function () {
        if (previewNeedsDraw()) startSceneLoop();
        else stopSceneLoopIfIdle();
    }).catch(function () { /* keep local visibility */ });
}

function nudgeLayerZ(id, dir) {
    var list = studioLayers.slice().sort(function (a, b) { return a.z - b.z; });
    var i;
    for (i = 0; i < list.length; i++) {
        if (list[i].id === id) break;
    }
    if (i >= list.length) return;
    var j = i + dir;
    if (j < 0 || j >= list.length) return;
    var tmp = list[i].z;
    list[i].z = list[j].z;
    list[j].z = tmp;
    selectedLayerId = id;
    renderLayerLists();
    renderSceneHandles();
    syncDeviceDropdownsToSelectedLayer();
}

function nextZ() {
    var z = 0;
    studioLayers.forEach(function (l) { if (l.z >= z) z = l.z + 1; });
    return z;
}

function selectLayer(id) {
    selectedLayerId = id;
    markSelectedLayerRows();
    renderSceneHandles();
    syncDeviceDropdownsToSelectedLayer();
}

function renderLayerLists() {
    bindLayerStackLists();
    var srcList = document.getElementById('source-layer-list');
    var ovList = document.getElementById('overlay-layer-list');
    if (srcList) srcList.innerHTML = '';
    if (ovList) ovList.innerHTML = '';
    var ordered = studioLayers.slice().sort(function (a, b) { return b.z - a.z; });
    ordered.forEach(function (l) {
        var li = document.createElement('li');
        li.className = 'layer-item' + (l.visible ? '' : ' off') + (l.id === selectedLayerId ? ' selected' : '');
        li.setAttribute('data-layer', l.id);
        var name = document.createElement('span');
        name.className = 'layer-name';
        name.textContent = l.label;
        var actions = document.createElement('div');
        actions.className = 'layer-actions';
        function mkBtn(label, action) {
            var b = document.createElement('button');
            b.type = 'button';
            b.textContent = label;
            b.setAttribute('data-layer', l.id);
            b.setAttribute('data-layer-action', action);
            return b;
        }
        actions.appendChild(mkBtn('Up', 'up'));
        actions.appendChild(mkBtn('Down', 'down'));
        actions.appendChild(mkBtn(l.visible ? 'Hide' : 'Show', 'toggle'));
        actions.appendChild(mkBtn('Remove', 'remove'));
        li.appendChild(name);
        li.appendChild(actions);
        var overlay = isOverlayType(l.type);
        if (overlay && ovList) ovList.appendChild(li);
        else if (!overlay && srcList) srcList.appendChild(li);
    });
    syncExtraCameraRows(false);
}

function mixContentRect() {
    var host = sceneHandles || document.getElementById('scene-handles');
    if (!host) return null;
    var plate = document.getElementById('preview-viewport');
    if (plate && host.getBoundingClientRect && plate.getBoundingClientRect) {
        var hr = host.getBoundingClientRect();
        var pr = plate.getBoundingClientRect();
        if (pr.width >= 2 && pr.height >= 2 && hr.width >= 2) {
            var cw = (mixCanvas && mixCanvas.width) ? mixCanvas.width : 1280;
            return {
                x: pr.left - hr.left,
                y: pr.top - hr.top,
                w: pr.width,
                h: pr.height,
                scale: pr.width / cw
            };
        }
    }
    var rw = host.clientWidth;
    var rh = host.clientHeight;
    if (rw < 2 || rh < 2) return null;
    var cw2 = (mixCanvas && mixCanvas.width) ? mixCanvas.width : 1280;
    var ch2 = (mixCanvas && mixCanvas.height) ? mixCanvas.height : 720;
    var scale = Math.min(rw / cw2, rh / ch2);
    var dw = cw2 * scale;
    var dh = ch2 * scale;
    return { x: (rw - dw) / 2, y: (rh - dh) / 2, w: dw, h: dh, scale: scale };
}

function applyHandleBoxStyle(box, layer, content) {
    box.style.left = (content.x + (layer.x || 0) * content.w) + 'px';
    box.style.top = (content.y + (layer.y || 0) * content.h) + 'px';
    box.style.width = ((layer.w != null ? layer.w : 1) * content.w) + 'px';
    box.style.height = ((layer.h != null ? layer.h : 1) * content.h) + 'px';
}

function updateHandlePositions() {
    if (!sceneHandles) return;
    var content = mixContentRect();
    if (!content) return;
    var boxes = sceneHandles.querySelectorAll('.scene-layer-box');
    for (var i = 0; i < boxes.length; i++) {
        var layer = findLayer(boxes[i].getAttribute('data-layer'));
        if (layer && layer.visible) applyHandleBoxStyle(boxes[i], layer, content);
    }
}

function startLayerDrag(ev, layer, mode) {
    ev.preventDefault();
    ev.stopPropagation();
    selectLayer(layer.id);
    var orig = {
        x: layer.x != null ? layer.x : 0,
        y: layer.y != null ? layer.y : 0,
        w: layer.w != null ? layer.w : 1,
        h: layer.h != null ? layer.h : 1
    };
    var lockAspect = null;
    if (ev.shiftKey && mode !== 'move' && orig.h) lockAspect = orig.w / orig.h;
    sceneDrag = {
        id: layer.id,
        mode: mode,
        startX: ev.clientX,
        startY: ev.clientY,
        lastX: ev.clientX,
        lastY: ev.clientY,
        lockAspect: lockAspect,
        orig: orig
    };
    if (ev.currentTarget && ev.pointerId != null && ev.currentTarget.setPointerCapture) {
        try { ev.currentTarget.setPointerCapture(ev.pointerId); } catch (e) {}
    }
    if (sceneHandles) sceneHandles.classList.add('dragging');
    positionSceneGrid();
    startSceneLoop();
    if (previewMirror) previewMirror.classList.add('no-mirror');
}

function applyLayerDragFromEvent(ev) {
    if (!sceneDrag) return;
    if (ev && typeof ev.clientX === 'number' && ev.type && ev.type.indexOf('pointer') === 0) {
        sceneDrag.lastX = ev.clientX;
        sceneDrag.lastY = ev.clientY;
    }
    var shift = !!(ev && ev.shiftKey);
    if (!shift) sceneDrag.lockAspect = null;
    else if (sceneDrag.lockAspect == null && sceneDrag.mode !== 'move') {
        var cur = findLayer(sceneDrag.id);
        var cw = cur && cur.w != null ? cur.w : sceneDrag.orig.w;
        var ch = cur && cur.h != null ? cur.h : sceneDrag.orig.h;
        sceneDrag.lockAspect = ch ? cw / ch : 1;
    }
    var layer = findLayer(sceneDrag.id);
    var content = mixContentRect();
    if (!layer || !content || content.w < 1 || content.h < 1) return;
    var dx = (sceneDrag.lastX - sceneDrag.startX) / content.w;
    var dy = (sceneDrag.lastY - sceneDrag.startY) / content.h;
    var next = computeLayerDragRect(sceneDrag.orig, dx, dy, sceneDrag.mode, {
        shift: shift,
        snap: sceneSnapForEvent(ev),
        lockAspect: sceneDrag.lockAspect
    });
    if (shift) sceneDrag.lockAspect = next.lockAspect;
    layer.x = next.x;
    layer.y = next.y;
    layer.w = next.w;
    layer.h = next.h;
    updateHandlePositions();
    positionSceneGrid(content);
}

function onLayerPointerMove(ev) {
    if (!sceneDrag) return;
    applyLayerDragFromEvent(ev);
}

function onLayerModifierKey(ev) {
    if (!sceneDrag) return;
    if (!ev) return;
    var k = ev.key || '';
    if (k !== 'Shift' && k !== 'Alt' && k !== 'Control' && k !== 'Ctrl') return;
    applyLayerDragFromEvent(ev);
}

function endLayerDrag() {
    if (!sceneDrag) return;
    sceneDrag = null;
    if (sceneHandles) sceneHandles.classList.remove('dragging');
    updateMixPresentation();
    renderSceneHandles();
    refreshLivePublish({ kindChangeOnly: true });
}

function positionSceneGrid(content) {
    if (!sceneHandles) return;
    var grid = document.getElementById('scene-grid');
    if (!grid) return;
    content = content || mixContentRect();
    if (!content) {
        grid.hidden = true;
        return;
    }
    grid.style.left = content.x + 'px';
    grid.style.top = content.y + 'px';
    grid.style.width = content.w + 'px';
    grid.style.height = content.h + 'px';
    grid.hidden = !sceneDrag;
}

function ensureSceneGrid() {
    if (!sceneHandles) return null;
    var grid = document.getElementById('scene-grid');
    if (grid) return grid;
    grid = document.createElement('div');
    grid.id = 'scene-grid';
    grid.className = 'scene-grid';
    grid.setAttribute('aria-hidden', 'true');
    grid.hidden = true;
    sceneHandles.insertBefore(grid, sceneHandles.firstChild);
    return grid;
}

function renderSceneHandles() {
    if (!sceneHandles) return;
    if (sceneDrag) {
        updateHandlePositions();
        positionSceneGrid();
        return;
    }
    var content = mixContentRect();
    sceneHandles.innerHTML = '';
    ensureSceneGrid();
    if (!content) return;
    positionSceneGrid(content);
    var seen = Object.create(null);
    var ordered = studioLayers.slice().sort(function (a, b) { return a.z - b.z; });
    ordered.forEach(function (l) {
        if (!l.visible || seen[l.id]) return;
        seen[l.id] = true;
        var box = document.createElement('div');
        box.className = 'scene-layer-box' + (l.id === selectedLayerId ? ' selected' : '');
        box.setAttribute('data-layer', l.id);
        applyHandleBoxStyle(box, l, content);
        var label = document.createElement('span');
        label.className = 'scene-layer-label';
        label.textContent = l.label || l.type;
        box.appendChild(label);
        ['nw', 'ne', 'sw', 'se'].forEach(function (corner) {
            var h = document.createElement('div');
            h.className = 'scene-resize-handle ' + corner;
            h.addEventListener('pointerdown', function (ev) { startLayerDrag(ev, l, corner); });
            box.appendChild(h);
        });
        box.addEventListener('pointerdown', function (ev) {
            if (ev.target && ev.target.classList && ev.target.classList.contains('scene-resize-handle')) return;
            startLayerDrag(ev, l, 'move');
        });
        sceneHandles.appendChild(box);
    });
}

function shrinkFaceCamIfFullBleed() {
    var cam = findLayer('camera-face');
    if (!cam || !cam.visible) return;
    if (isFullBleed(cam)) {
        cam.x = 0.70;
        cam.y = 0.64;
        cam.w = 0.28;
        cam.h = 0.32;
    }
}

function syncCameraFaceLayer() {
    if (typeof isFileSource === 'function' && isFileSource()) {
        studioLayers = studioLayers.filter(function (l) {
            if (l.type !== 'camera-face') return true;
            disposeLayerMedia(l);
            return false;
        });
        renderLayerLists();
        renderSceneHandles();
        stopSceneLoopIfIdle();
        return;
    }
    if (!cameraFaceWanted) return;
    if (typeof localStream === 'undefined' || !localStream) return;
    var existing = findLayer('camera-face');
    var camLabel = 'Camera';
    var bindFace = !selectedLayerId || !findLayer(selectedLayerId) || (selectedLayerId === 'camera-face');
    var camDevice = '';
    var micDevice = '';
    if (bindFace && cameraSelect && cameraSelect.value) camDevice = cameraSelect.value;
    if (bindFace && typeof micSelect !== 'undefined' && micSelect && micSelect.value) micDevice = micSelect.value;
    if (cameraSelect && cameraSelect.selectedOptions && cameraSelect.selectedOptions[0] && cameraSelect.selectedOptions[0].textContent && bindFace) {
        camLabel = cameraSelect.selectedOptions[0].textContent;
    } else if (existing && existing.label) {
        camLabel = existing.label;
    }
    if (!existing) {
        var created = {
            id: 'camera-face',
            type: 'camera-face',
            label: camLabel,
            visible: true,
            z: nextZ(),
            stream: localStream,
            deviceId: camDevice,
            audioDeviceId: micDevice,
            x: 0, y: 0, w: 1, h: 1
        };
        upsertLayer(created);
        captureLayerDeviceIds(created, localStream);
        syncDeviceDropdownsToSelectedLayer();
        return;
    }
    existing.stream = localStream;
    if (camDevice) existing.deviceId = camDevice;
    if (micDevice) existing.audioDeviceId = micDevice;
    captureLayerDeviceIds(existing, localStream);
    var labelChanged = existing.label !== camLabel;
    existing.label = camLabel;
    if (existing.video) {
        existing.video.srcObject = localStream;
        existing.video.play().catch(function () {});
    }
    if (labelChanged) renderLayerLists();
    renderSceneHandles();
    updateMixPresentation();
    syncDeviceDropdownsToSelectedLayer();
}

function onExclusiveFileSource() {
    studioLayers = studioLayers.filter(function (l) {
        if (l.type !== 'camera-face') return true;
        disposeLayerMedia(l);
        return false;
    });
    attachFileLayer();
    renderLayerLists();
    renderSceneHandles();
    stopSceneLoopIfIdle();
}

function usedCameraDeviceIds() {
    var used = {};
    studioLayers.forEach(function (l) {
        if (!isCameraLayer(l)) return;
        var id = layerVideoDeviceId(l);
        if (id) used[id] = true;
    });
    return used;
}

function firstDeviceFromSelect(sel, used) {
    if (!sel || !sel.options) return { unused: '', first: '' };
    var unused = '';
    var first = '';
    var i, v;
    for (i = 0; i < sel.options.length; i++) {
        v = sel.options[i] && sel.options[i].value;
        if (!v) continue;
        if (!first) first = v;
        if (used && !used[v] && !unused) unused = v;
    }
    return { unused: unused, first: first };
}

function pickExtraCameraDevice() {
    var used = usedCameraDeviceIds();
    var extra = document.getElementById('extra-cam-select');
    var a = firstDeviceFromSelect(extra, used);
    if (a.unused || a.first) return a.unused || a.first;
    if (typeof cameraSelect !== 'undefined' && cameraSelect) {
        var b = firstDeviceFromSelect(cameraSelect, used);
        if (b.unused || b.first) return b.unused || b.first;
        if (cameraSelect.value) return cameraSelect.value;
    }
    return '';
}

function fillSelectFromCameraList(sel, selectedId) {
    if (!sel) return;
    var src = (typeof cameraSelect !== 'undefined' && cameraSelect)
        ? cameraSelect
        : document.getElementById('extra-cam-select');
    withSelectSilent(sel, function () {
        sel.innerHTML = '';
        var i, o, opt;
        if (src && src.options) {
            for (i = 0; i < src.options.length; i++) {
                o = src.options[i];
                if (!o || !o.value) continue;
                opt = document.createElement('option');
                opt.value = o.value;
                opt.textContent = o.textContent || o.text || o.value;
                sel.appendChild(opt);
            }
        }
        if (selectedId) sel.value = selectedId;
    });
}

function extraCamRowByLayerId(host, id) {
    if (!host || !id) return null;
    var rows = host.querySelectorAll('.source-row-cam[data-cam-layer]');
    var i;
    for (i = 0; i < rows.length; i++) {
        if (rows[i].getAttribute('data-cam-layer') === id) return rows[i];
    }
    return null;
}

function lastCameraSourceRow(host) {
    if (!host) return null;
    var rows = host.querySelectorAll('.source-row-cam');
    return rows.length ? rows[rows.length - 1] : null;
}

function onExtraLayerSelectChange(ev) {
    var sel = ev && ev.target;
    if (!sel) return;
    var id = sel.getAttribute('data-cam-layer');
    var layer = findLayer(id);
    if (!layer) return;
    selectLayer(id);
    replaceLayerVideoDevice(layer, sel.value);
}

function makeExtraCameraRow(layer) {
    var row = document.createElement('div');
    row.className = 'source-row source-row-cam';
    row.setAttribute('data-cam-layer', layer.id);

    var first = document.querySelector('#settings-sources .source-row-cam:not([data-cam-layer])');
    var icoSrc = first && first.querySelector('.source-ico');
    var ico = icoSrc ? icoSrc.cloneNode(true) : document.createElement('span');
    if (!icoSrc) {
        ico.className = 'source-ico';
        ico.setAttribute('title', 'Camera');
        ico.setAttribute('aria-hidden', 'true');
    }

    var plus = document.createElement('button');
    plus.type = 'button';
    plus.className = 'source-add source-add-plus';
    plus.title = 'Add camera';
    plus.setAttribute('aria-label', 'Add camera');
    plus.setAttribute('onclick', 'addExtraCamera()');
    var plusSvg = first && first.querySelector('.source-add-plus svg');
    if (plusSvg) plus.appendChild(plusSvg.cloneNode(true));
    else plus.textContent = '+';

    var sel = document.createElement('select');
    sel.setAttribute('data-cam-layer', layer.id);
    sel.title = 'Camera';
    sel.setAttribute('aria-label', 'Camera');
    sel.addEventListener('change', onExtraLayerSelectChange);

    row.appendChild(ico);
    row.appendChild(plus);
    row.appendChild(sel);
    fillSelectFromCameraList(sel, layerVideoDeviceId(layer));
    return row;
}

function syncExtraCameraRows(refill) {
    var host = document.querySelector('#settings-sources .source-rows');
    if (!host) return;
    var extras = studioLayers.filter(function (l) { return l.type === 'camera-extra'; });
    var have = {};
    extras.forEach(function (l) { have[l.id] = true; });
    var rows = host.querySelectorAll('.source-row-cam[data-cam-layer]');
    var i, id, row, sel, vid;
    for (i = rows.length - 1; i >= 0; i--) {
        id = rows[i].getAttribute('data-cam-layer');
        if (!have[id]) rows[i].parentNode.removeChild(rows[i]);
    }
    extras.forEach(function (layer) {
        row = extraCamRowByLayerId(host, layer.id);
        if (!row) {
            row = makeExtraCameraRow(layer);
            var last = lastCameraSourceRow(host);
            if (last && last.nextSibling) host.insertBefore(row, last.nextSibling);
            else if (last) host.appendChild(row);
            else host.insertBefore(row, host.firstChild);
            return;
        }
        sel = row.querySelector('select');
        vid = layerVideoDeviceId(layer);
        if (refill !== false || !sel || !sel.options || !sel.options.length) {
            fillSelectFromCameraList(sel, vid);
        } else if (vid) {
            setSelectValueSilent(sel, vid);
        }
    });
}

async function addExtraCamera() {
    var sel = document.getElementById('extra-cam-select');
    var deviceId = pickExtraCameraDevice();
    if (sel && deviceId) sel.value = deviceId;
    if (!deviceId) {
        if (statusEl) {
            statusEl.textContent = 'Pick an extra camera first';
            statusEl.classList.add('error');
        }
        return;
    }
    try {
        var stream = await navigator.mediaDevices.getUserMedia({
            video: { deviceId: { exact: deviceId }, width: { ideal: 640 }, height: { ideal: 360 } },
            audio: false
        });
        var label = 'Cam';
        if (sel && sel.selectedOptions && sel.selectedOptions[0]) {
            label = sel.selectedOptions[0].textContent || label;
        }
        syncCameraFaceLayer();
        var extra = {
            id: nextLayerId(),
            type: 'camera-extra',
            label: label,
            visible: true,
            z: nextZ(),
            stream: stream,
            deviceId: deviceId,
            x: 0.68, y: 0.58, w: 0.3, h: 0.36
        };
        upsertLayer(extra);
        captureLayerDeviceIds(extra, stream);
        selectLayer(extra.id);
        startSceneLoop();
        refreshLivePublish();
        if (statusEl && !isPublishLocked()) {
            statusEl.textContent = 'Extra camera armed';
            statusEl.classList.remove('error');
        }
    } catch (e) {
        if (statusEl) {
            statusEl.textContent = 'Extra camera failed: ' + e.message;
            statusEl.classList.add('error');
        }
    }
}

function addScreenStream(stream, label) {
    if (!stream) return null;
    applyPublishVideoHint(stream);
    Promise.resolve(constrainScreenTracks(stream)).then(function () {
        refreshLivePublish();
    }).catch(function () {});
    stream.getVideoTracks().forEach(function (t) {
        t.addEventListener('ended', function () {
            studioLayers.filter(function (l) { return l.stream === stream; })
                .forEach(function (l) { removeLayer(l.id); });
        });
    });
    syncCameraFaceLayer();
    var layer = {
        id: nextLayerId(),
        type: 'screen',
        label: label || 'Screenshare',
        visible: true,
        z: 0,
        stream: stream,
        x: 0, y: 0, w: 1, h: 1
    };
    upsertLayer(layer);
    var cam = findLayer('camera-face');
    if (cam) cam.z = Math.max(cam.z, nextZ());
    shrinkFaceCamIfFullBleed();
    renderLayerLists();
    renderSceneHandles();
    updateMixPresentation();
    if (previewMirror) previewMirror.classList.add('no-mirror');
    refreshLivePublish();
    return layer;
}

async function addScreenshare() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
        if (statusEl) {
            statusEl.textContent = 'Screenshare not supported';
            statusEl.classList.add('error');
        }
        return;
    }
    try {
        var stream;
        try {
            stream = await navigator.mediaDevices.getDisplayMedia({
                video: screenVideoConstraints(),
                audio: false
            });
        } catch (eCons) {
            if (eCons && (eCons.name === 'NotAllowedError' || eCons.name === 'AbortError')) {
                throw eCons;
            }
            stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
        }
        await constrainScreenTracks(stream);
        addScreenStream(stream, 'Screenshare');
        await refreshLivePublish();
        if (statusEl && !isPublishLocked()) {
            statusEl.textContent = studioMixActive()
                ? 'Screenshare + camera armed'
                : 'Screenshare armed';
            statusEl.classList.remove('error');
        } else if (statusEl) {
            statusEl.classList.remove('error');
        }
    } catch (e) {
        if (statusEl) {
            statusEl.textContent = 'Screenshare cancelled or failed';
            statusEl.classList.add('error');
        }
    }
}

function addTextOverlay() {
    var inp = document.getElementById('overlay-text');
    var text = inp ? inp.value.trim() : '';
    if (!text) text = 'Live';
    var layer = {
        id: nextLayerId(),
        type: 'text',
        label: 'Text: ' + text,
        text: text,
        visible: true,
        z: nextZ(),
        x: 0.08, y: 0.78, w: 0.46, h: 0.12,
        color: '#ffffff'
    };
    upsertLayer(layer);
    selectLayer(layer.id);
    startSceneLoop();
    refreshLivePublish();
}

function addImageOverlayFromFile(file) {
    if (!file) return;
    var url = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function () {
        var nw = img.naturalWidth || 160;
        var nh = img.naturalHeight || 160;
        var w = 0.22;
        var h = w * (nh / nw) * ((mixCanvas && mixCanvas.width && mixCanvas.height)
            ? (mixCanvas.width / mixCanvas.height) / (16 / 9)
            : 1);
        if (h > 0.4) {
            w *= 0.4 / h;
            h = 0.4;
        }
        var layer = {
            id: nextLayerId(),
            type: 'image',
            label: 'Image: ' + (file.name || 'overlay'),
            img: img,
            objectUrl: url,
            visible: true,
            z: nextZ(),
            x: 0.06, y: 0.08, w: w, h: Math.max(0.08, h)
        };
        upsertLayer(layer);
        selectLayer(layer.id);
        startSceneLoop();
        refreshLivePublish();
    };
    img.src = url;
}

function addFileLayerFromFile(file) {
    if (!file) return;
    var url = URL.createObjectURL(file);
    var v = document.createElement('video');
    v.autoplay = true;
    v.muted = true;
    v.loop = true;
    v.playsInline = true;
    v.src = url;
    v.play().catch(function () {});
    if (sceneOffscreen) sceneOffscreen.appendChild(v);
    syncCameraFaceLayer();
    var layer = {
        id: nextLayerId(),
        type: 'file',
        label: 'File: ' + (file.name || 'video'),
        visible: true,
        z: nextZ(),
        videoFile: v,
        video: v,
        objectUrl: url,
        x: 0.08, y: 0.08, w: 0.44, h: 0.44
    };
    upsertLayer(layer);
    selectLayer(layer.id);
    startSceneLoop();
    refreshLivePublish();
    if (statusEl && !isPublishLocked()) {
        statusEl.textContent = 'File layer armed';
        statusEl.classList.remove('error');
    }
}

function fillExtraCamSelect() {
    var sel = document.getElementById('extra-cam-select');
    if (!sel || !navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
    navigator.mediaDevices.enumerateDevices().then(function (devices) {
        var cams = devices.filter(function (d) { return d.kind === 'videoinput'; });
        var keep = sel.value;
        sel.innerHTML = '';
        cams.forEach(function (cam, i) {
            var opt = document.createElement('option');
            opt.value = cam.deviceId;
            opt.textContent = cam.label || ('Camera ' + (i + 1));
            sel.appendChild(opt);
        });
        if (keep && Array.prototype.some.call(sel.options, function (o) { return o.value === keep; })) {
            sel.value = keep;
        } else {
            var pick = pickExtraCameraDevice();
            if (pick) sel.value = pick;
            else if (cams.length) sel.value = cams[0].deviceId;
        }
        syncExtraCameraRows();
    }).catch(function () {});
}

function attachFileLayer() {
    var existing = studioLayers.filter(function (l) { return l.id === 'file-main'; });
    if (!isFileSource()) {
        if (existing.length) {
            existing.forEach(function (l) { disposeLayerMedia(l); });
            studioLayers = studioLayers.filter(function (l) { return l.id !== 'file-main'; });
        }
        fileMainWanted = true;
        return;
    }
    if (existing.length) return;
    if (!fileMainWanted) return;
    upsertLayer({
        id: 'file-main',
        type: 'file',
        label: 'Video file',
        visible: true,
        z: 0,
        x: 0, y: 0, w: 1, h: 1
    });
}

function showDonationToast(nick, text, amount, currency) {
    var title = (typeof formatDonationAmount === 'function')
        ? formatDonationAmount(amount, currency)
        : String(amount || '');
    var body = (nick || 'Anonymous') + (text ? ' — ' + text : '');
    sceneToast = { title: title, body: body, until: Date.now() + 7000 };
    if (donationToastEl) {
        donationToastEl.hidden = false;
        donationToastEl.textContent = title + '  ' + body;
    }
    startSceneLoop();
    setTimeout(function () {
        if (sceneToast && Date.now() >= sceneToast.until) {
            sceneToast = null;
            if (donationToastEl) donationToastEl.hidden = true;
            stopSceneLoopIfIdle();
        }
    }, 7200);
}

function getStudioPublishStream() {
    attachFileLayer();
    if (!isFileSource()) syncCameraFaceLayer();
    getStudioPublishStream.screenDirect = false;
    getStudioPublishStream.mixCapture = false;
    getStudioPublishStream.kind = studioPublishKind();
    var pubs = getStudioPublishVideoLayers();
    var primary = pubs[0];
    var screenDirect = (primary && primary.layer && primary.layer.type === 'screen')
        ? (primary.layer.stream || null)
        : (fullBleedScreenStream() || nativeScreenPublishStream());
    if (screenDirect) {
        applyPublishVideoHint(screenDirect);
        getStudioPublishStream.screenDirect = true;
        getStudioPublishStream.mixCapture = false;
        getStudioPublishStream.kind = 'screen';
        lastLivePublishKind = isPublishLocked() ? 'screen' : lastLivePublishKind;
        resetMixPublishStream();
        updateMixPresentation();
        try {
            var cam = findLayer('camera-face');
            var vt = screenDirect.getVideoTracks && screenDirect.getVideoTracks()[0];
            console.log('[broadcast] getStudioPublishStream', JSON.stringify({
                kind: 'screen',
                screenDirect: true,
                mixCapture: false,
                mixActive: studioMixActive(),
                cameraFace: !!(cam && cam.visible),
                cameraFaceListed: !!cam,
                videoLayers: pubs.length,
                trackLabel: vt ? (vt.label || '') : '',
                trackId: vt ? vt.id : null
            }));
        } catch (eLog) { /* ignore */ }
        return withPublishAudio(screenDirect);
    }
    var camDirect = (primary && primary.track && primary.layer && primary.layer.type !== 'screen')
        ? (primary.layer.stream || nativeCameraPublishStream())
        : nativeCameraPublishStream();
    if (camDirect) {
        resetMixPublishStream();
        getStudioPublishStream.screenDirect = false;
        getStudioPublishStream.mixCapture = false;
        getStudioPublishStream.kind = 'camera';
        lastLivePublishKind = (typeof isPublishLocked === 'function' && isPublishLocked()) ? 'camera' : lastLivePublishKind;
        /* WHIP is native camera track(s). Local plate still composites at scene x/y/w/h. */
        updateMixPresentation();
        return withPublishAudio(camDirect);
    }
    /* No visible camera/screen. Never fall back to localStream video — that
     * re-published a Removed or Hidden camera-face on the wire. */
    if (!pubs.length && !studioMixActive()) {
        resetMixPublishStream();
        getStudioPublishStream.kind = 'camera';
        getStudioPublishStream.mixCapture = false;
        getStudioPublishStream.screenDirect = false;
        updateMixPresentation();
        return audioOnlyPublishStream();
    }
    if (!studioMixActive()) {
        getStudioPublishStream.kind = 'camera';
        getStudioPublishStream.mixCapture = false;
        return audioOnlyPublishStream();
    }
    /* Hard rule: a visible full-bleed screen never falls through to mix capture. */
    if (fullBleedScreenStream()) {
        resetMixPublishStream();
        getStudioPublishStream.screenDirect = true;
        getStudioPublishStream.mixCapture = false;
        getStudioPublishStream.kind = 'screen';
        return withPublishAudio(fullBleedScreenStream());
    }
    /* Hard rule: camera-only (no screen) never recaptures via mixCanvas. */
    if (nativeCameraPublishStream()) {
        resetMixPublishStream();
        getStudioPublishStream.mixCapture = false;
        getStudioPublishStream.kind = 'camera';
        return withPublishAudio(nativeCameraPublishStream());
    }
    if (!mixCanvas) return localStream;
    syncMixCanvasSize();
    startSceneLoop();
    if (previewMirror) previewMirror.classList.add('no-mirror');
    var fps = mixCaptureFps();
    try {
        var mixTrack = mixCaptureStream && mixCaptureStream.getVideoTracks
            ? mixCaptureStream.getVideoTracks()[0]
            : null;
        var mixLive = !!(mixTrack && mixTrack.readyState === 'live');
        if (!mixLive || mixCaptureStream._mixFps !== fps) {
            mixCaptureStream = captureFromElement(mixCanvas, fps);
            mixCaptureStream._mixFps = fps;
        }
        window.mixCaptureStream = mixCaptureStream;
    } catch (e) {
        return localStream;
    }
    applyPublishVideoHint(mixCaptureStream);
    var audioSrc = localStream;
    if (audioSrc) {
        audioSrc.getAudioTracks().forEach(function (t) {
            if (mixCaptureStream.getAudioTracks().length === 0) {
                mixCaptureStream.addTrack(t);
            }
        });
    }
    if (mixCaptureStream.getAudioTracks().length === 0) {
        mixCaptureStream = ensureAudioTrack(mixCaptureStream);
        mixCaptureStream._mixFps = fps;
        window.mixCaptureStream = mixCaptureStream;
    }
    getStudioPublishStream.mixCapture = true;
    getStudioPublishStream.kind = 'mix';
    lastLivePublishKind = isPublishLocked() ? 'mix' : lastLivePublishKind;
    return mixCaptureStream;
}

/* ── Invite shortener UI ───────────────────────────────── */

function inviteLongPath() {
    var key = authenticatedKey || (streamKeyInput && streamKeyInput.value) || '';
    if (!key) return '';
    var pw = roomPasswordInput ? roomPasswordInput.value.trim() : '';
    var path = '/watch/' + encodeURIComponent((typeof publicSlug !== 'undefined' && publicSlug) ? publicSlug : key);
    if (pw) path += '?invite=' + encodeURIComponent(pw);
    return path;
}

function refreshInviteURL() {
    var el = document.getElementById('invite-url');
    if (!el) return;
    var path = inviteLongPath();
    el.value = path ? (location.origin + path) : '';
}

function setInviteStatus(msg, isErr) {
    var el = document.getElementById('invite-status');
    if (!el) return;
    el.textContent = msg || '';
    el.style.color = isErr ? '#ef5350' : '#888';
}

function renderShortLinks(items) {
    var list = document.getElementById('short-link-list');
    if (!list) return;
    list.innerHTML = '';
    (items || []).forEach(function (it) {
        var li = document.createElement('li');
        li.className = 'layer-item';
        var name = document.createElement('span');
        name.className = 'layer-name';
        name.textContent = it.url + ' → ' + it.target;
        var actions = document.createElement('div');
        actions.className = 'layer-actions';
        var copy = document.createElement('button');
        copy.type = 'button';
        copy.textContent = 'Copy';
        copy.onclick = function () {
            if (navigator.clipboard) navigator.clipboard.writeText(it.url).catch(function () {});
        };
        var del = document.createElement('button');
        del.type = 'button';
        del.textContent = 'Revoke';
        del.onclick = function () { revokeShortLink(it.code); };
        actions.appendChild(copy);
        actions.appendChild(del);
        li.appendChild(name);
        li.appendChild(actions);
        list.appendChild(li);
    });
}

function loadShortLinks() {
    fetch('/api/shorten', { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (items) { renderShortLinks(items); })
        .catch(function () { renderShortLinks([]); });
}

function createShortLink() {
    var pw = roomPasswordInput ? roomPasswordInput.value.trim() : '';
    fetch('/api/shorten', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invite: pw, target: inviteLongPath() })
    }).then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    }).then(function (data) {
        setInviteStatus('Short link ready', false);
        loadShortLinks();
        if (data && data.url && navigator.clipboard) {
            navigator.clipboard.writeText(data.url).catch(function () {});
        }
    }).catch(function () {
        setInviteStatus('Could not create short link', true);
    });
}

function revokeShortLink(code) {
    fetch('/api/shorten/' + encodeURIComponent(code), {
        method: 'DELETE',
        credentials: 'same-origin'
    }).then(function (r) {
        if (!r.ok) throw new Error('fail');
        loadShortLinks();
    }).catch(function () {
        setInviteStatus('Revoke failed', true);
    });
}

function studioSceneSnapshot() {
    var screen = studioLayers.filter(function (l) { return l.visible && l.type === 'screen'; })[0];
    var screenTrack = screen && screen.stream ? screen.stream.getVideoTracks()[0] : null;
    var settings = null;
    try { settings = screenTrack && screenTrack.getSettings ? screenTrack.getSettings() : null; } catch (e) {}
    return {
        mixActive: studioMixActive(),
        publishKind: studioPublishKind(),
        screenDirect: !!fullBleedScreenStream(),
        screenOnly: !!singleVisibleScreenStream(),
        fnScreenDirect: !!getStudioPublishStream.screenDirect,
        mixCapture: !!getStudioPublishStream.mixCapture,
        previewOnly: previewLoopOn,
        previewNeedsDraw: previewNeedsDraw(),
        programMix: !!(previewMirror && previewMirror.classList && previewMirror.classList.contains('program-mix')),
        screenRes: (document.getElementById('screen-resolution') || {}).value || '',
        screenCapture: screenCaptureSize(),
        screenHint: screenTrack ? (screenTrack.contentHint || '') : '',
        screenSettings: settings,
        selected: selectedLayerId,
        snapEnabled: isSceneSnapEnabled(),
        hideGui: isHideGuiEnabled(),
        canvas: mixCanvas ? { w: mixCanvas.width, h: mixCanvas.height, vis: mixCanvas.style.visibility } : null,
        cameraLayout: studioCameraLayout(),
        sceneLayout: studioSceneLayout(),
        cameraTrack: !!getStudioCameraTrack(),
        videoLayers: getStudioPublishVideoLayers().map(function (p) {
            return { id: p.layer && p.layer.id, type: p.layer && p.layer.type, trackId: p.track && p.track.id };
        }),
        layers: studioLayers.map(function (l) {
            return {
                id: l.id,
                type: l.type,
                label: l.label,
                visible: !!l.visible,
                z: l.z,
                x: l.x, y: l.y, w: l.w, h: l.h,
                deviceId: l.deviceId || layerVideoDeviceId(l) || '',
                audioDeviceId: l.audioDeviceId || '',
                hasStream: !!(l.stream || l.video || l.videoFile || (l.type === 'file' && l.id === 'file-main'))
            };
        })
    };
}

function initStudioScene() {
    fillExtraCamSelect();
    attachFileLayer();
    syncMixCanvasSize();
    var imgInp = document.getElementById('overlay-image');
    if (imgInp) {
        imgInp.addEventListener('change', function () {
            var f = imgInp.files && imgInp.files[0];
            if (f) addImageOverlayFromFile(f);
            imgInp.value = '';
        });
    }
    var layerFile = document.getElementById('layer-file-input');
    if (layerFile) {
        layerFile.addEventListener('change', function () {
            var f = layerFile.files && layerFile.files[0];
            if (f) addFileLayerFromFile(f);
            layerFile.value = '';
        });
    }
    var copyBtn = document.getElementById('btn-copy-invite');
    if (copyBtn) {
        copyBtn.onclick = function () {
            refreshInviteURL();
            var el = document.getElementById('invite-url');
            if (el && navigator.clipboard) navigator.clipboard.writeText(el.value).catch(function () {});
            setInviteStatus('Copied invite URL', false);
        };
    }
    var mk = document.getElementById('btn-create-short');
    if (mk) mk.onclick = createShortLink;
    if (roomPasswordInput) {
        roomPasswordInput.addEventListener('input', refreshInviteURL);
    }
    if (useVideoFile) {
        useVideoFile.addEventListener('change', function () {
            attachFileLayer();
            if (!useVideoFile.checked) syncCameraFaceLayer();
        });
    }
    bindMaxViewersBar();
    bindStudioToolsBar();
    bindLayerStackLists();
    var screenRes = document.getElementById('screen-resolution');
    if (screenRes && !screenRes._bound) {
        screenRes._bound = true;
        screenRes.addEventListener('change', function () {
            applyLiveScreenResolution();
        });
    }
    if (sceneHandles) {
        sceneHandles.addEventListener('pointermove', onLayerPointerMove);
        sceneHandles.addEventListener('pointerup', endLayerDrag);
        sceneHandles.addEventListener('pointercancel', endLayerDrag);
        window.addEventListener('pointerup', endLayerDrag);
        window.addEventListener('pointermove', onLayerPointerMove);
        window.addEventListener('keydown', onLayerModifierKey);
        window.addEventListener('keyup', onLayerModifierKey);
    }
    window.addEventListener('resize', function () { renderSceneHandles(); });
    var stage = document.querySelector('.preview-stage');
    if (stage && typeof ResizeObserver !== 'undefined') {
        handleRo = new ResizeObserver(function () { renderSceneHandles(); });
        handleRo.observe(stage);
    }
    if (typeof cameraSelect !== 'undefined' && cameraSelect) {
        cameraSelect.onchange = function () {
            if (typeof onCameraSelectChange === 'function') onCameraSelectChange();
            else if (typeof startPreview === 'function') startPreview();
        };
    }
    if (typeof micSelect !== 'undefined' && micSelect) {
        micSelect.onchange = function () {
            if (typeof onMicSelectChange === 'function') onMicSelectChange();
            else if (typeof startPreview === 'function') startPreview();
        };
    }
    if (localStream && !isFileSource()) syncCameraFaceLayer();
    renderSceneHandles();
    syncDeviceDropdownsToSelectedLayer();
    updateMixPresentation();
}

window.showDonationToast = showDonationToast;
window.getStudioPublishStream = getStudioPublishStream;
window.getStudioCameraTrack = getStudioCameraTrack;
window.getStudioCameraLayer = getStudioCameraLayer;
window.studioCameraLayout = studioCameraLayout;
window.studioSceneLayout = studioSceneLayout;
window.getStudioPublishVideoLayers = getStudioPublishVideoLayers;
window.MAX_SCENE_VIDEO_TRACKS = MAX_SCENE_VIDEO_TRACKS;
window.publishStudioCameraLayout = publishStudioCameraLayout;
window.nativeCameraPublishStream = nativeCameraPublishStream;
window.singleVisibleCameraStream = singleVisibleCameraStream;
window.singleVisibleScreenStream = singleVisibleScreenStream;
window.fullBleedScreenStream = fullBleedScreenStream;
window.studioHasVisibleScreen = studioHasVisibleScreen;
window.mixCaptureStream = mixCaptureStream;
window.studioMixActive = studioMixActive;
window.previewNeedsDraw = previewNeedsDraw;
window.studioHasVisibleCamera = studioHasVisibleCamera;
window.constrainScreenTracks = constrainScreenTracks;
window.screenVideoConstraints = screenVideoConstraints;
window.screenCaptureSize = screenCaptureSize;
window.applyLiveScreenResolution = applyLiveScreenResolution;
window.studioPublishKind = studioPublishKind;
window.refreshLivePublish = refreshLivePublish;
window.switchStudioTab = switchStudioTab;
window.openStudioDock = openStudioDock;
window.closeStudioDock = closeStudioDock;
window.toggleStudioDock = toggleStudioDock;
window.isStudioDockOpen = isStudioDockOpen;
window.addExtraCamera = addExtraCamera;
window.pickExtraCameraDevice = pickExtraCameraDevice;
window.syncExtraCameraRows = syncExtraCameraRows;
window.addScreenshare = addScreenshare;
window.addScreenStream = addScreenStream;
window.addTextOverlay = addTextOverlay;
window.addFileLayerFromFile = addFileLayerFromFile;
window.removeLayer = removeLayer;
window.toggleLayer = toggleLayer;
window.nudgeLayerZ = nudgeLayerZ;
window.selectLayer = selectLayer;
window.runLayerStackAction = runLayerStackAction;
window.layerStackHit = layerStackHit;
window.bindLayerStackLists = bindLayerStackLists;
window.renderLayerLists = renderLayerLists;
window.setLayerRect = setLayerRect;
window.syncCameraFaceLayer = syncCameraFaceLayer;
window.setCameraFaceWanted = setCameraFaceWanted;
window.isCameraFaceWanted = isCameraFaceWanted;
window.dismissMainCameraFace = dismissMainCameraFace;
window.isCameraLayer = isCameraLayer;
window.studioHasCameraLayer = studioHasCameraLayer;
window.cameraSelectShouldIncludeOff = cameraSelectShouldIncludeOff;
window.selectedCameraLayer = selectedCameraLayer;
window.layerVideoDeviceId = layerVideoDeviceId;
window.layerAudioDeviceId = layerAudioDeviceId;
window.syncDeviceDropdownsToSelectedLayer = syncDeviceDropdownsToSelectedLayer;
window.cameraSelectChangeAction = cameraSelectChangeAction;
window.onCameraSelectChange = onCameraSelectChange;
window.onMicSelectChange = onMicSelectChange;
window.replaceLayerVideoDevice = replaceLayerVideoDevice;
window.replaceLayerAudioDevice = replaceLayerAudioDevice;
window.onExclusiveFileSource = onExclusiveFileSource;
window.studioSceneSnapshot = studioSceneSnapshot;
window.updateMixPresentation = updateMixPresentation;
window.getStudioLayers = function () { return studioLayers; };
window.refreshInviteURL = refreshInviteURL;
window.loadShortLinks = loadShortLinks;
window.isFileSource = isFileSource;
window.initStudioScene = initStudioScene;
window.computeLayerDragRect = computeLayerDragRect;
window.constrainLayerAspect = constrainLayerAspect;
window.snapGridValue = snapGridValue;
window.snapLayerRect = snapLayerRect;
window.alignLayerRect = alignLayerRect;
window.snapSelectedLayerToGrid = snapSelectedLayerToGrid;
window.alignSelectedLayer = alignSelectedLayer;
window.isSceneSnapEnabled = isSceneSnapEnabled;
window.setSceneSnapEnabled = setSceneSnapEnabled;
window.toggleSceneSnap = toggleSceneSnap;
window.sceneSnapForEvent = sceneSnapForEvent;
window.isHideGuiEnabled = isHideGuiEnabled;
window.setHideGuiEnabled = setHideGuiEnabled;
window.toggleHideGui = toggleHideGui;
window.SCENE_GRID = SCENE_GRID;
window.createShortLink = createShortLink;
window.revokeShortLink = revokeShortLink;
