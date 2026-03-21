/* broadcast-chat.js — broadcaster chat (WebSocket, rendering, moderation) */

var chatWs = null;
var chatNick = 'Broadcaster';
var chatConnected = false;
var chatReconnectTimer = null;
var chatErrorReceived = false;
var chatMessagesEl = document.getElementById('chat-messages');
var chatStatusEl = document.getElementById('chat-status');
var chatInput = document.getElementById('chat-input');
var btnChatSend = document.getElementById('btn-chat-send');

function chatConnect() {
    var roomId = authenticatedKey;
    if (!roomId || !chatNick) return;
    if (chatWs) { chatWs.close(); chatWs = null; }

    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var url = proto + '//' + location.host + '/api/chat/' + roomId + '?nick=' + encodeURIComponent(chatNick);
    chatWs = new WebSocket(url);
    chatStatusEl.textContent = 'Connecting...';
    chatStatusEl.className = 'chat-status';

    chatErrorReceived = false;
    chatWs.onopen = function () {
        chatConnected = true;
        chatStatusEl.textContent = 'Connected';
        chatStatusEl.className = 'chat-status connected';
    };

    chatWs.onclose = function () {
        chatConnected = false;
        chatStatusEl.textContent = 'Disconnected';
        chatStatusEl.className = 'chat-status';
        if (!chatErrorReceived) {
            chatReconnectTimer = setTimeout(function () {
                if (authenticatedKey) chatConnect();
            }, 3000);
        }
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

function chatDisconnect() {
    if (chatReconnectTimer) { clearTimeout(chatReconnectTimer); chatReconnectTimer = null; }
    if (chatWs) { chatWs.close(); chatWs = null; }
    chatConnected = false;
    chatStatusEl.textContent = 'Disconnected';
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
        case 'error':
            appendChatSystem(msg.text);
            chatErrorReceived = true;
            break;
        default:
            break;
    }
}

/* ── Donation formatting (shared with broadcast-donations.js) ── */

function formatDonationAmount(amount, currency) {
    var val = (amount / 100).toFixed(2);
    var symbols = { USD: '$', EUR: '€', GBP: '£' };
    var sym = symbols[currency] || '';
    if (sym) return sym + val;
    if (currency === 'BTC' || currency === 'ETH') {
        return (amount / 100000000).toFixed(8) + ' ' + currency;
    }
    return val + ' ' + currency;
}

function getDonationTier(amount) {
    if (amount >= 10000) return 'tier-5';
    if (amount >= 5000)  return 'tier-4';
    if (amount >= 2000)  return 'tier-3';
    if (amount >= 500)   return 'tier-2';
    return '';
}

function appendDonationMessage(nick, text, amount, currency) {
    var el = document.createElement('div');
    var tier = getDonationTier(amount);
    el.className = 'chat-msg donation' + (tier ? ' ' + tier : '');
    var badge = document.createElement('span');
    badge.className = 'donation-amount';
    badge.textContent = formatDonationAmount(amount, currency);
    el.appendChild(badge);
    var nickSpan = document.createElement('span');
    nickSpan.className = 'nick viewer';
    nickSpan.textContent = (nick || 'Anonymous') + ':';
    el.appendChild(nickSpan);
    if (text) {
        var msgSpan = document.createElement('span');
        msgSpan.className = 'donation-text';
        msgSpan.textContent = text;
        el.appendChild(msgSpan);
    }
    chatMessagesEl.appendChild(el);
    autoScrollChat();
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

function chatSendMessage() {
    if (!chatWs || !chatConnected) return;
    var text = chatInput.value.trim();
    if (!text) return;
    var type = text[0] === '/' ? 'cmd' : 'msg';
    chatWs.send(JSON.stringify({ type: type, text: text }));
    chatInput.value = '';
}

function chatModCmd(cmd) {
    if (!chatWs || !chatConnected) return;
    chatWs.send(JSON.stringify({ type: 'cmd', text: cmd }));
}

btnChatSend.onclick = chatSendMessage;

chatInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') chatSendMessage();
});
