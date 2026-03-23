/* watch-split.js — resize stream vs chat: horizontal on wide viewports, vertical on phone */

(function () {
    var STORAGE_W = 'livecamWatchChatWidthPx';
    var STORAGE_H = 'livecamWatchChatHeightPx';
    var MQ_DESKTOP = '(min-width: 901px)';
    var SPLITTER = 6;
    /* Desktop: keep chat wide enough for input + Send without crunching */
    var CHAT_MIN_W = 240;
    /* Reserve enough width for video so chat cannot dominate the row */
    var STREAM_MIN_W = 300;
    /* Mobile: reserve vertical space for the stream (phone broadcasters are often 9:16) */
    var CHAT_MIN_H = 176;
    var STREAM_MIN_H = 240;
    /* Chat cannot take more than this fraction of row — stream gets the rest first */
    var CHAT_MAX_FRAC = 0.40;
    /* Default chat size as fraction of row (stream gets ~1 − this, minus splitter) */
    var DEFAULT_CHAT_FRAC = 0.28;
    /* Phone (vertical stack): default ~half row so chat height matches stream column height */
    var CHAT_MAX_FRAC_MOBILE = 0.5;
    var DEFAULT_CHAT_FRAC_MOBILE = 0.5;

    var row = document.querySelector('.watch-row');
    var splitter = document.getElementById('watch-splitter');
    var stream = document.querySelector('main.stream-column');
    var chat = document.querySelector('.chat-panel');
    if (!row || !splitter || !stream || !chat) {
        return;
    }

    var mqDesktop = window.matchMedia(MQ_DESKTOP);
    var dragging = false;
    var startX = 0;
    var startY = 0;
    var startSize = 0;

    function isDesktopLayout() {
        return mqDesktop.matches;
    }

    function clampChatWidth(w, rowW) {
        var maxC = rowW - SPLITTER - STREAM_MIN_W;
        maxC = Math.min(maxC, Math.floor(rowW * CHAT_MAX_FRAC));
        if (maxC < 1) {
            maxC = 1;
        }
        var minC = CHAT_MIN_W <= maxC ? CHAT_MIN_W : maxC;
        var x = w;
        if (x < minC) {
            x = minC;
        }
        if (x > maxC) {
            x = maxC;
        }
        return Math.round(x);
    }

    function clampChatHeight(h, rowH) {
        var maxC = rowH - SPLITTER - STREAM_MIN_H;
        maxC = Math.min(maxC, Math.floor(rowH * CHAT_MAX_FRAC_MOBILE));
        if (maxC < 1) {
            maxC = 1;
        }
        var minC = CHAT_MIN_H <= maxC ? CHAT_MIN_H : maxC;
        var x = h;
        if (x < minC) {
            x = minC;
        }
        if (x > maxC) {
            x = maxC;
        }
        return Math.round(x);
    }

    function readStoredWidth() {
        var n = parseInt(localStorage.getItem(STORAGE_W), 10);
        if (!isFinite(n) || n < CHAT_MIN_W) {
            return null;
        }
        return n;
    }

    function readStoredHeight() {
        var n = parseInt(localStorage.getItem(STORAGE_H), 10);
        if (!isFinite(n) || n < CHAT_MIN_H) {
            return null;
        }
        return n;
    }

    function clearChatSizing() {
        chat.style.flex = '';
        chat.style.width = '';
        chat.style.maxWidth = '';
        chat.style.minHeight = '';
    }

    function applyDesktop(px) {
        clearChatSizing();
        chat.style.flex = '0 0 ' + px + 'px';
        chat.style.width = px + 'px';
        chat.style.maxWidth = 'none';
        try {
            localStorage.setItem(STORAGE_W, String(px));
        } catch (e) {
            /* ignore */
        }
    }

    function applyMobile(px) {
        clearChatSizing();
        chat.style.flex = '0 0 ' + px + 'px';
        chat.style.width = '100%';
        chat.style.maxWidth = 'none';
        chat.style.minHeight = '0';
        try {
            localStorage.setItem(STORAGE_H, String(px));
        } catch (e) {
            /* ignore */
        }
    }

    function defaultHalfWidth() {
        var rw = row.getBoundingClientRect().width;
        return clampChatWidth(Math.round((rw - SPLITTER) * DEFAULT_CHAT_FRAC), rw);
    }

    function defaultHalfHeight() {
        var rh = row.getBoundingClientRect().height;
        return clampChatHeight(Math.round((rh - SPLITTER) * DEFAULT_CHAT_FRAC_MOBILE), rh);
    }

    function updateAria(size, total, desktop) {
        var pct = total > 0 ? Math.round((size / total) * 100) : 0;
        splitter.setAttribute('aria-valuenow', String(size));
        if (desktop) {
            splitter.setAttribute('aria-valuetext', pct + '% of row width');
            splitter.setAttribute('aria-valuemin', String(CHAT_MIN_W));
            splitter.setAttribute('aria-valuemax', String(clampChatWidth(999999, total)));
        } else {
            splitter.setAttribute('aria-valuetext', pct + '% of row height');
            splitter.setAttribute('aria-valuemin', String(CHAT_MIN_H));
            splitter.setAttribute('aria-valuemax', String(clampChatHeight(999999, total)));
        }
        splitter.setAttribute('aria-orientation', desktop ? 'vertical' : 'horizontal');
    }

    function sync() {
        var desktop = isDesktopLayout();
        splitter.removeAttribute('hidden');
        splitter.setAttribute('aria-hidden', 'false');
        splitter.setAttribute('tabindex', '0');
        row.classList.add('watch-row--resize');
        document.body.classList.remove('watch-split-dragging--col', 'watch-split-dragging--row');

        if (desktop) {
            row.classList.remove('watch-row--resize-mobile');
            row.classList.add('watch-row--resize-desktop');
            var rw = row.getBoundingClientRect().width;
            var stored = readStoredWidth();
            var px = stored !== null ? clampChatWidth(stored, rw) : defaultHalfWidth();
            applyDesktop(px);
            updateAria(px, rw, true);
        } else {
            row.classList.remove('watch-row--resize-desktop');
            row.classList.add('watch-row--resize-mobile');
            var rh = row.getBoundingClientRect().height;
            var storedH = readStoredHeight();
            var py = storedH !== null ? clampChatHeight(storedH, rh) : defaultHalfHeight();
            applyMobile(py);
            updateAria(py, rh, false);
        }
    }

    function onPointerDown(e) {
        if (e.button !== 0 && e.pointerType !== 'touch') {
            return;
        }
        dragging = true;
        startX = e.clientX;
        startY = e.clientY;
        var r = chat.getBoundingClientRect();
        startSize = isDesktopLayout() ? r.width : r.height;
        document.body.classList.add('watch-split-dragging');
        document.body.classList.add(isDesktopLayout() ? 'watch-split-dragging--col' : 'watch-split-dragging--row');
        try {
            splitter.setPointerCapture(e.pointerId);
        } catch (err) {
            /* ignore */
        }
        e.preventDefault();
    }

    function onPointerMove(e) {
        if (!dragging) {
            return;
        }
        /* Inverted: left / up increases chat size; right / down decreases */
        if (isDesktopLayout()) {
            var rw = row.getBoundingClientRect().width;
            var deltaX = e.clientX - startX;
            var next = clampChatWidth(startSize - deltaX, rw);
            applyDesktop(next);
            updateAria(next, rw, true);
        } else {
            var rh = row.getBoundingClientRect().height;
            var deltaY = e.clientY - startY;
            var nextH = clampChatHeight(startSize - deltaY, rh);
            applyMobile(nextH);
            updateAria(nextH, rh, false);
        }
    }

    function endDrag(e) {
        if (!dragging) {
            return;
        }
        dragging = false;
        document.body.classList.remove('watch-split-dragging', 'watch-split-dragging--col', 'watch-split-dragging--row');
        try {
            splitter.releasePointerCapture(e.pointerId);
        } catch (err) {
            /* ignore */
        }
    }

    function onResizeWindow() {
        if (isDesktopLayout()) {
            var rw = row.getBoundingClientRect().width;
            var cw = chat.getBoundingClientRect().width;
            var c = clampChatWidth(cw, rw);
            if (c !== cw) {
                applyDesktop(c);
            }
            updateAria(c, rw, true);
        } else {
            var rh = row.getBoundingClientRect().height;
            var ch = chat.getBoundingClientRect().height;
            var h = clampChatHeight(ch, rh);
            if (h !== ch) {
                applyMobile(h);
            }
            updateAria(h, rh, false);
        }
    }

    function onKeyDown(e) {
        var step = e.shiftKey ? 48 : 16;
        if (isDesktopLayout()) {
            var rw = row.getBoundingClientRect().width;
            var cw = chat.getBoundingClientRect().width;
            var n;
            if (e.key === 'ArrowLeft') {
                e.preventDefault();
                n = clampChatWidth(cw + step, rw);
                applyDesktop(n);
                updateAria(n, rw, true);
            } else if (e.key === 'ArrowRight') {
                e.preventDefault();
                n = clampChatWidth(cw - step, rw);
                applyDesktop(n);
                updateAria(n, rw, true);
            } else if (e.key === 'Home') {
                e.preventDefault();
                n = clampChatWidth(rw - SPLITTER - STREAM_MIN_W, rw);
                applyDesktop(n);
                updateAria(n, rw, true);
            } else if (e.key === 'End') {
                e.preventDefault();
                n = clampChatWidth(CHAT_MIN_W, rw);
                applyDesktop(n);
                updateAria(n, rw, true);
            }
        } else {
            var rh = row.getBoundingClientRect().height;
            var ch = chat.getBoundingClientRect().height;
            var nh;
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                nh = clampChatHeight(ch + step, rh);
                applyMobile(nh);
                updateAria(nh, rh, false);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                nh = clampChatHeight(ch - step, rh);
                applyMobile(nh);
                updateAria(nh, rh, false);
            } else if (e.key === 'Home') {
                e.preventDefault();
                nh = clampChatHeight(rh - SPLITTER - STREAM_MIN_H, rh);
                applyMobile(nh);
                updateAria(nh, rh, false);
            } else if (e.key === 'End') {
                e.preventDefault();
                nh = clampChatHeight(CHAT_MIN_H, rh);
                applyMobile(nh);
                updateAria(nh, rh, false);
            }
        }
    }

    function onDblClick(e) {
        e.preventDefault();
        if (isDesktopLayout()) {
            var rw = row.getBoundingClientRect().width;
            var half = defaultHalfWidth();
            applyDesktop(half);
            updateAria(half, rw, true);
        } else {
            var rh = row.getBoundingClientRect().height;
            var halfH = defaultHalfHeight();
            applyMobile(halfH);
            updateAria(halfH, rh, false);
        }
    }

    splitter.addEventListener('pointerdown', onPointerDown);
    splitter.addEventListener('pointermove', onPointerMove);
    splitter.addEventListener('pointerup', endDrag);
    splitter.addEventListener('pointercancel', endDrag);
    splitter.addEventListener('lostpointercapture', function () {
        dragging = false;
        document.body.classList.remove('watch-split-dragging', 'watch-split-dragging--col', 'watch-split-dragging--row');
    });
    splitter.addEventListener('keydown', onKeyDown);
    splitter.addEventListener('dblclick', onDblClick);

    var resizeTid = 0;
    window.addEventListener('resize', function () {
        if (resizeTid) {
            window.clearTimeout(resizeTid);
        }
        resizeTid = window.setTimeout(function () {
            resizeTid = 0;
            sync();
        }, 50);
    });

    if (typeof mqDesktop.addEventListener === 'function') {
        mqDesktop.addEventListener('change', sync);
    } else {
        mqDesktop.addListener(sync);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', sync);
    } else {
        sync();
    }
})();
