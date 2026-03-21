/* donate.js — donation rendering, modal, and below-stream panel */

var donateOverlay = document.getElementById('donate-overlay');
var donateMethods = document.getElementById('donate-methods');
var donateAmount = document.getElementById('donate-amount');
var donateCurrency = document.getElementById('donate-currency');
var donateMessage = document.getElementById('donate-message');
var donateError = document.getElementById('donate-error');
var panelDonate = document.getElementById('panel-donate');
var availableMethods = null;
var selectedProvider = '';

/* ── Donation rendering (chat) ──────────────────────────── */

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

/* ── Below-stream panel visibility ──────────────────────── */

function fetchDonateMethods() {
    if (!roomId) return;
    fetch('/api/donations/methods/' + roomId)
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
            if (!data) { panelDonate.style.display = 'none'; return; }
            availableMethods = data;
            var hasAny = data.stripe || data.paypal || data.bank ||
                         (data.crypto && data.crypto.length > 0);
            panelDonate.style.display = hasAny ? '' : 'none';

            if (data.panels && data.panels.panels && data.panels.panels.length > 0) {
                var section = document.getElementById('panels-section');
                data.panels.panels.forEach(function(p) {
                    if (!p.image_url) return;
                    var a = document.createElement('a');
                    if (p.link_url) {
                        a.href = p.link_url;
                        a.target = '_blank';
                        a.rel = 'noopener noreferrer';
                    }
                    a.style.display = 'block';
                    a.style.marginBottom = '0.5rem';
                    var img = document.createElement('img');
                    img.src = p.image_url;
                    img.style.width = '100%';
                    img.style.borderRadius = '6px';
                    img.style.border = '1px solid #1a1a1a';
                    a.appendChild(img);
                    section.appendChild(a);
                });
            }
        })
        .catch(function () { panelDonate.style.display = 'none'; });
}

/* ── Modal ──────────────────────────────────────────────── */

function openDonateModal() {
    if (!availableMethods) return;
    donateError.textContent = '';
    donateAmount.value = '';
    donateMessage.value = '';
    selectedProvider = '';
    donateMethods.innerHTML = '';

    if (availableMethods.stripe) addMethodBtn('stripe', 'Card');
    if (availableMethods.paypal) addMethodBtn('paypal', 'PayPal');
    if (availableMethods.crypto && availableMethods.crypto.length > 0) {
        addMethodBtn('crypto', 'Crypto');
    }
    if (availableMethods.bank) addMethodBtn('bank', 'Bank Transfer');

    donateOverlay.classList.add('visible');
}

function addMethodBtn(provider, label) {
    var btn = document.createElement('button');
    btn.textContent = label;
    btn.onclick = function () {
        donateMethods.querySelectorAll('button').forEach(function (b) {
            b.classList.remove('active');
        });
        btn.classList.add('active');
        selectedProvider = provider;

        if (provider === 'crypto') {
            donateCurrency.innerHTML = '';
            (availableMethods.crypto || []).forEach(function (c) {
                var opt = document.createElement('option');
                opt.value = c; opt.textContent = c;
                donateCurrency.appendChild(opt);
            });
        } else {
            donateCurrency.innerHTML = '<option value="USD">USD</option><option value="EUR">EUR</option>';
        }
    };
    donateMethods.appendChild(btn);
}

function closeDonateModal() {
    donateOverlay.classList.remove('visible');
}

function submitDonation() {
    donateError.textContent = '';
    if (!selectedProvider) { donateError.textContent = 'Select a payment method'; return; }
    var amount = Math.round(parseFloat(donateAmount.value) * 100);
    if (!amount || amount <= 0) { donateError.textContent = 'Enter a valid amount'; return; }

    var body = {
        room_id: roomId,
        provider: selectedProvider,
        amount: amount,
        currency: donateCurrency.value || 'USD',
        message: donateMessage.value.trim(),
        viewer_nick: chatNick || 'Anonymous',
        return_url: window.location.href
    };

    fetch('/api/donations/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    })
    .then(function (r) {
        if (!r.ok) return r.text().then(function (t) { throw new Error(t); });
        return r.json();
    })
    .then(function (data) {
        closeDonateModal();
        if (data.redirect_url) {
            window.open(data.redirect_url, '_blank', 'noopener');
        }
    })
    .catch(function (err) {
        donateError.textContent = err.message || 'Failed to start donation';
    });
}

donateOverlay.addEventListener('click', function (e) {
    if (e.target === donateOverlay) closeDonateModal();
});
