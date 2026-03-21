/* watch-split.js — draggable resize between stream column and chat (desktop layout only) */

(function () {
    var STORAGE_KEY = 'livecamWatchChatPx';
    var MQ = '(min-width: 901px)';
    var SPLITTER_W = 6;
    var CHAT_MIN = 180;
    /* Match main.stream-column min-width when .watch-row--resize */
    var STREAM_MIN = 160;

    var row = document.querySelector('.watch-row');
    var splitter = document.getElementById('watch-splitter');
    var stream = document.querySelector('main.stream-column');
    var chat = document.querySelector('.chat-panel');
    if (!row || !splitter || !stream || !chat) {
        return;
    }

    var mq = window.matchMedia(MQ);
    var dragging = false;
    var startX = 0;
    var startChatW = 0;

    function clampChatPx(w, rowW) {
        var maxC = rowW - SPLITTER_W - STREAM_MIN;
        if (maxC < 1) {
            maxC = 1;
        }
        var minC = CHAT_MIN <= maxC ? CHAT_MIN : maxC;
        var x = w;
        if (x < minC) {
            x = minC;
        }
        if (x > maxC) {
            x = maxC;
        }
        return Math.round(x);
    }

    function readStored() {
        var s = localStorage.getItem(STORAGE_KEY);
        var n = parseInt(s, 10);
        if (!isFinite(n) || n < CHAT_MIN) {
            return null;
        }
        return n;
    }

    function applyChatWidth(px) {
        chat.style.flex = '0 0 ' + px + 'px';
        chat.style.width = px + 'px';
        chat.style.maxWidth = 'none';
        try {
            localStorage.setItem(STORAGE_KEY, String(px));
        } catch (e) {
            /* ignore quota / private mode */
        }
    }

    function defaultHalfWidth() {
        var rw = row.getBoundingClientRect().width;
        return clampChatPx(Math.round((rw - SPLITTER_W) / 2), rw);
    }

    function updateAria(px, rowW) {
        var pct = rowW > 0 ? Math.round((px / rowW) * 100) : 0;
        splitter.setAttribute('aria-valuenow', String(px));
        splitter.setAttribute('aria-valuetext', pct + '% width');
        splitter.setAttribute('aria-valuemin', String(CHAT_MIN));
        splitter.setAttribute('aria-valuemax', String(Math.max(CHAT_MIN, rowW - SPLITTER_W - STREAM_MIN)));
    }

    function activateDesktop() {
        splitter.removeAttribute('hidden');
        splitter.setAttribute('aria-hidden', 'false');
        splitter.setAttribute('tabindex', '0');
        row.classList.add('watch-row--resize');
        var rw = row.getBoundingClientRect().width;
        var stored = readStored();
        var px = stored !== null ? clampChatPx(stored, rw) : defaultHalfWidth();
        applyChatWidth(px);
        updateAria(px, rw);
    }

    function deactivateMobile() {
        splitter.setAttribute('hidden', '');
        splitter.setAttribute('aria-hidden', 'true');
        splitter.setAttribute('tabindex', '-1');
        row.classList.remove('watch-row--resize');
        chat.style.flex = '';
        chat.style.width = '';
        chat.style.maxWidth = '';
    }

    function sync() {
        if (mq.matches) {
            activateDesktop();
        } else {
            deactivateMobile();
        }
    }

    function onPointerDown(e) {
        if (!mq.matches) {
            return;
        }
        if (e.button !== 0 && e.pointerType !== 'touch') {
            return;
        }
        dragging = true;
        startX = e.clientX;
        startChatW = chat.getBoundingClientRect().width;
        document.body.classList.add('watch-split-dragging');
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
        var rw = row.getBoundingClientRect().width;
        var delta = e.clientX - startX;
        var next = clampChatPx(startChatW + delta, rw);
        applyChatWidth(next);
        updateAria(next, rw);
    }

    function endDrag(e) {
        if (!dragging) {
            return;
        }
        dragging = false;
        document.body.classList.remove('watch-split-dragging');
        try {
            splitter.releasePointerCapture(e.pointerId);
        } catch (err) {
            /* ignore */
        }
    }

    function onResizeWindow() {
        if (!mq.matches) {
            return;
        }
        var rw = row.getBoundingClientRect().width;
        var cw = chat.getBoundingClientRect().width;
        var c = clampChatPx(cw, rw);
        if (c !== cw) {
            applyChatWidth(c);
        }
        updateAria(c, rw);
    }

    function onKeyDown(e) {
        if (!mq.matches) {
            return;
        }
        var step = e.shiftKey ? 48 : 16;
        var rw = row.getBoundingClientRect().width;
        var cw = chat.getBoundingClientRect().width;
        var n;
        if (e.key === 'ArrowLeft') {
            e.preventDefault();
            n = clampChatPx(cw - step, rw);
            applyChatWidth(n);
            updateAria(n, rw);
        } else if (e.key === 'ArrowRight') {
            e.preventDefault();
            n = clampChatPx(cw + step, rw);
            applyChatWidth(n);
            updateAria(n, rw);
        } else if (e.key === 'Home') {
            e.preventDefault();
            n = clampChatPx(CHAT_MIN, rw);
            applyChatWidth(n);
            updateAria(n, rw);
        } else if (e.key === 'End') {
            e.preventDefault();
            n = clampChatPx(rw - SPLITTER_W - STREAM_MIN, rw);
            applyChatWidth(n);
            updateAria(n, rw);
        }
    }

    splitter.addEventListener('pointerdown', onPointerDown);
    splitter.addEventListener('pointermove', onPointerMove);
    splitter.addEventListener('pointerup', endDrag);
    splitter.addEventListener('pointercancel', endDrag);
    splitter.addEventListener('lostpointercapture', function () {
        dragging = false;
        document.body.classList.remove('watch-split-dragging');
    });
    splitter.addEventListener('keydown', onKeyDown);
    splitter.addEventListener('dblclick', function () {
        if (!mq.matches) {
            return;
        }
        var rw = row.getBoundingClientRect().width;
        var half = defaultHalfWidth();
        applyChatWidth(half);
        updateAria(half, rw);
    });

    var resizeTid = 0;
    window.addEventListener('resize', function () {
        if (resizeTid) {
            window.clearTimeout(resizeTid);
        }
        resizeTid = window.setTimeout(function () {
            resizeTid = 0;
            onResizeWindow();
        }, 50);
    });

    if (typeof mq.addEventListener === 'function') {
        mq.addEventListener('change', sync);
    } else {
        mq.addListener(sync);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', sync);
    } else {
        sync();
    }
})();
