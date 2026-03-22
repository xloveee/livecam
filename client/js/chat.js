/* chat.js — WebSocket chat for viewer page */

var chatWs = null;
var chatNick = '';
var chatIsGuest = false;
var chatConnected = false;
var chatReconnectTimer = null;
var chatMessagesEl = document.getElementById('chat-messages');
var chatStatusEl = document.getElementById('chat-status');
var chatGuestBar = document.getElementById('chat-guest-bar');
var chatNickPrompt = document.getElementById('chat-nick-prompt');
var chatNickInput = document.getElementById('chat-nick');
var nickError = document.getElementById('nick-error');
var chatSendEl = document.getElementById('chat-send');
var chatNickDisplay = document.getElementById('chat-nick-display');
var chatInput = document.getElementById('chat-input');
var btnChatJoin = document.getElementById('btn-chat-join');
var btnChatSend = document.getElementById('btn-chat-send');

function chatConnect(nick) {
    if (!roomId || !nick) return;
    chatDisconnect();

    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var url = proto + '//' + location.host + '/api/chat/' + roomId + '?nick=' + encodeURIComponent(nick);
    chatWs = new WebSocket(url);
    chatStatusEl.textContent = 'Connecting...';
    chatStatusEl.className = 'chat-status';

    chatWs.onopen = function () {
        chatConnected = true;
        chatStatusEl.textContent = 'Connected';
        chatStatusEl.className = 'chat-status connected';
    };

    chatWs.onclose = function () {
        chatConnected = false;
        chatStatusEl.textContent = 'Reconnecting...';
        chatStatusEl.className = 'chat-status';
        var reconnectNick = chatNick || '_guest';
        chatReconnectTimer = setTimeout(function () {
            if (roomId) chatConnect(reconnectNick);
        }, 3000);
    };

    chatWs.onerror = function () {
        chatConnected = false;
    };

    chatWs.onmessage = function (ev) {
        try {
            var msg = JSON.parse(ev.data);
            handleChatMsg(msg);
        } catch (e) { /* ignore */ }
    };
}

function chatConnectGuest() {
    chatIsGuest = true;
    chatConnect('_guest');
}

function chatDisconnect() {
    if (chatReconnectTimer) { clearTimeout(chatReconnectTimer); chatReconnectTimer = null; }
    if (chatWs) {
        chatWs.onclose = null;
        chatWs.close();
        chatWs = null;
    }
    chatConnected = false;
    chatStatusEl.textContent = '';
    chatStatusEl.className = 'chat-status';
}

function handleChatMsg(msg) {
    switch (msg.type) {
        case 'msg':
            appendChatMessage(msg.nick, msg.text, msg.role);
            break;
        case 'donation':
            appendDonationMessage(msg.nick, msg.text, msg.amount, msg.currency);
            break;
        case 'system':
            appendChatSystem(msg.text);
            break;
        case 'clear':
            chatMessagesEl.innerHTML = '';
            appendChatSystem('Chat has been cleared.');
            break;
        case 'ban':
            appendChatSystem(msg.nick + ' has been banned.');
            break;
        case 'room_state':
            if (typeof window.onRoomState === 'function') {
                window.onRoomState(msg);
            }
            break;
        case 'error':
            appendChatSystem(msg.text);
            chatDisconnect();
            chatNick = '';
            chatIsGuest = false;
            chatSendEl.style.display = 'none';
            chatGuestBar.style.display = '';
            chatNickPrompt.classList.remove('visible');
            break;
        default:
            break;
    }
}

function appendChatMessage(nick, text, role) {
    var el = document.createElement('div');
    el.className = 'chat-msg';
    var nickSpan = document.createElement('span');
    nickSpan.className = 'nick ' + (role || 'viewer');
    nickSpan.textContent = nick + ':';
    el.appendChild(nickSpan);
    el.appendChild(document.createTextNode(' ' + text));
    chatMessagesEl.appendChild(el);
    autoScrollChat();
}

function appendChatSystem(text) {
    var el = document.createElement('div');
    el.className = 'chat-msg system';
    el.textContent = text;
    chatMessagesEl.appendChild(el);
    autoScrollChat();
}

function autoScrollChat() {
    var el = chatMessagesEl;
    var atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (atBottom) {
        el.scrollTop = el.scrollHeight;
    }
}

function showNickPrompt() {
    if (viewerState !== 'live') return;
    chatNickPrompt.classList.add('visible');
    chatNickInput.focus();
}

function enableChat() {
    if (!roomId) return;
    fetchDonateMethods();
    if (chatNick) {
        chatGuestBar.style.display = 'none';
        chatSendEl.style.display = '';
        chatConnect(chatNick);
    } else {
        chatGuestBar.style.display = '';
        chatGuestBar.style.pointerEvents = '';
        chatGuestBar.style.opacity = '';
        chatConnectGuest();
    }
}

function disableChat() {
    chatDisconnect();
    chatNickPrompt.classList.remove('visible');
    chatSendEl.style.display = 'none';
    chatGuestBar.style.display = '';
    chatGuestBar.style.pointerEvents = 'none';
    chatGuestBar.style.opacity = '0.25';
}

function chatSendMessage() {
    if (!chatWs || !chatConnected || chatIsGuest) return;
    var text = chatInput.value.trim();
    if (!text) return;
    var type = text[0] === '/' ? 'cmd' : 'msg';
    chatWs.send(JSON.stringify({ type: type, text: text }));
    chatInput.value = '';
}

btnChatJoin.onclick = function () {
    var nick = chatNickInput.value.trim();
    nickError.textContent = '';
    if (!nick) {
        nickError.textContent = 'Please enter a nickname.';
        return;
    }
    if (!/^[a-zA-Z0-9_]{1,25}$/.test(nick)) {
        nickError.textContent = '1-25 chars, letters/numbers/underscore only.';
        return;
    }
    chatNick = nick;
    chatIsGuest = false;
    chatNickDisplay.textContent = nick;
    chatNickPrompt.classList.remove('visible');
    chatGuestBar.style.display = 'none';
    chatSendEl.style.display = '';
    chatInput.focus();
    chatConnect(nick);
};

chatNickInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') btnChatJoin.click();
});

btnChatSend.onclick = chatSendMessage;

chatInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') chatSendMessage();
});
