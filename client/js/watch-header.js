/* watch-header.js — header chat toggle + donate shortcut */

(function () {
    var STORAGE_CHAT_HIDDEN = 'livecamWatchChatPanelHidden';
    var btnToggle = document.getElementById('btn-toggle-chat');
    var btnDonate = document.getElementById('btn-header-donate');
    var chatPanel = document.querySelector('.chat-panel');
    if (!btnToggle) {
        return;
    }

    function applyChatHidden(hidden) {
        document.body.classList.toggle('watch-chat-hidden', hidden);
        btnToggle.setAttribute('aria-expanded', hidden ? 'false' : 'true');
        btnToggle.setAttribute('aria-label', hidden ? 'Show chat' : 'Hide chat');
        btnToggle.title = hidden ? 'Show chat' : 'Hide chat';
        /* Clear watch-split inline flex/width so collapsed bar is not stuck at a tall chat height */
        if (chatPanel) {
            if (hidden) {
                chatPanel.style.flex = '0 0 auto';
                chatPanel.style.width = '';
                chatPanel.style.maxWidth = '';
                chatPanel.style.minHeight = '';
            } else {
                chatPanel.style.flex = '';
                chatPanel.style.width = '';
                chatPanel.style.maxWidth = '';
                chatPanel.style.minHeight = '';
            }
        }
        try {
            if (hidden) {
                localStorage.setItem(STORAGE_CHAT_HIDDEN, '1');
            } else {
                localStorage.removeItem(STORAGE_CHAT_HIDDEN);
            }
        } catch (e) {
            /* ignore */
        }
        window.dispatchEvent(new Event('resize'));
    }

    function readStoredChatHidden() {
        try {
            return localStorage.getItem(STORAGE_CHAT_HIDDEN) === '1';
        } catch (e) {
            return false;
        }
    }

    btnToggle.addEventListener('click', function () {
        applyChatHidden(!document.body.classList.contains('watch-chat-hidden'));
    });

    if (readStoredChatHidden()) {
        applyChatHidden(true);
    }

    if (btnDonate) {
        btnDonate.addEventListener('click', function () {
            if (typeof openDonateModalOrFocus === 'function') {
                openDonateModalOrFocus();
            }
        });
    }
})();
