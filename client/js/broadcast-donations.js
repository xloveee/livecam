/* broadcast-donations.js — donation provider config CRUD + donation history */

var donationStatusEl = document.getElementById('donation-status');

function loadDonationConfig() {
    fetch('/api/donations/setup', { method: 'GET' })
        .then(function (r) {
            if (r.status === 503) {
                donationStatusEl.textContent = 'Donations service unavailable on server';
                donationStatusEl.style.color = '#ef5350';
                return null;
            }
            if (r.status === 401) {
                donationStatusEl.textContent = 'Not authenticated — go live first';
                donationStatusEl.style.color = '#ef5350';
                return null;
            }
            return r.ok ? r.json() : [];
        })
        .then(function (configs) {
            if (!configs) return;
            configs.forEach(function (c) {
                var data = {};
                try { data = JSON.parse(c.config_data); } catch (e) {}
                switch (c.provider) {
                    case 'stripe':
                        document.getElementById('stripe-toggle').checked = c.enabled;
                        document.getElementById('stripe-key').value = data.secret_key || '';
                        break;
                    case 'paypal':
                        document.getElementById('paypal-toggle').checked = c.enabled;
                        document.getElementById('paypal-email').value = data.email || '';
                        break;
                    case 'crypto':
                        document.getElementById('crypto-toggle').checked = c.enabled;
                        document.getElementById('crypto-btc').value = data.btc_address || '';
                        document.getElementById('crypto-eth').value = data.eth_address || '';
                        break;
                    case 'bank':
                        document.getElementById('bank-toggle').checked = c.enabled;
                        document.getElementById('bank-merchant').value = data.merchant_id || '';
                        document.getElementById('bank-url').value = data.yowpay_url || '';
                        document.getElementById('bank-apikey').value = data.api_key || '';
                        break;
                    default:
                        break;
                }
            });
        })
        .catch(function () {
            donationStatusEl.textContent = 'Could not load donation config';
            donationStatusEl.style.color = '#ef5350';
        });
}

var donationSaveDebounce = {};
function saveDonationConfig(provider) {
    clearTimeout(donationSaveDebounce[provider]);
    donationSaveDebounce[provider] = setTimeout(function () { doSaveDonationConfig(provider); }, 400);
}

function doSaveDonationConfig(provider) {
    var enabled = false;
    var configData = {};
    switch (provider) {
        case 'stripe':
            enabled = document.getElementById('stripe-toggle').checked;
            configData = { secret_key: document.getElementById('stripe-key').value.trim() };
            break;
        case 'paypal':
            enabled = document.getElementById('paypal-toggle').checked;
            configData = { email: document.getElementById('paypal-email').value.trim() };
            break;
        case 'crypto':
            enabled = document.getElementById('crypto-toggle').checked;
            var btc = document.getElementById('crypto-btc').value.trim();
            var eth = document.getElementById('crypto-eth').value.trim();
            var currencies = [];
            if (btc) currencies.push('BTC');
            if (eth) currencies.push('ETH');
            configData = { btc_address: btc, eth_address: eth, currencies: currencies };
            break;
        case 'bank':
            enabled = document.getElementById('bank-toggle').checked;
            configData = {
                merchant_id: document.getElementById('bank-merchant').value.trim(),
                yowpay_url: document.getElementById('bank-url').value.trim(),
                api_key: document.getElementById('bank-apikey').value.trim()
            };
            break;
        default:
            break;
    }
    fetch('/api/donations/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: provider, config_data: JSON.stringify(configData), enabled: enabled })
    })
    .then(function (r) {
        if (r.ok) {
            donationStatusEl.style.color = '#4caf50';
            donationStatusEl.textContent = 'Saved';
        } else if (r.status === 503) {
            donationStatusEl.style.color = '#ef5350';
            donationStatusEl.textContent = 'Donations service unavailable on server';
        } else if (r.status === 401) {
            donationStatusEl.style.color = '#ef5350';
            donationStatusEl.textContent = 'Not authenticated — go live first';
        } else {
            donationStatusEl.style.color = '#ef5350';
            donationStatusEl.textContent = 'Save failed (server error)';
        }
        setTimeout(function () { donationStatusEl.textContent = ''; donationStatusEl.style.color = ''; }, 3000);
    })
    .catch(function () {
        donationStatusEl.style.color = '#ef5350';
        donationStatusEl.textContent = 'Network error — could not reach server';
    });
}

['stripe-key', 'paypal-email', 'crypto-btc', 'crypto-eth', 'bank-merchant', 'bank-url', 'bank-apikey'].forEach(function (id) {
    document.getElementById(id).addEventListener('input', function () {
        var provider = id.split('-')[0];
        saveDonationConfig(provider);
    });
});

/* ── Donation History ────────────────────────────────────── */

var donationHistoryEl = document.getElementById('donation-history');
var donationHistoryList = document.getElementById('donation-history-list');
var donationHistoryVisible = false;

function toggleDonationHistory() {
    donationHistoryVisible = !donationHistoryVisible;
    donationHistoryEl.style.display = donationHistoryVisible ? '' : 'none';
    if (donationHistoryVisible) loadDonationHistory();
}

function loadDonationHistory() {
    fetch('/api/donations/history', { method: 'GET' })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (records) {
            donationHistoryList.innerHTML = '';
            if (records.length === 0) {
                donationHistoryList.textContent = 'No donations yet.';
                return;
            }
            records.forEach(function (rec) {
                var el = document.createElement('div');
                el.style.cssText = 'padding:0.15rem 0;border-bottom:1px solid #111;';
                var amount = formatDonationAmount(rec.amount, rec.currency);
                var date = new Date(rec.created_at * 1000).toLocaleString();
                var status = rec.status === 'confirmed' ? '\u2713' : rec.status;
                el.textContent = amount + ' from ' + (rec.viewer_nick || 'Anonymous') +
                    ' \u2014 ' + status + ' \u2014 ' + date;
                if (rec.message) {
                    var msg = document.createElement('div');
                    msg.style.cssText = 'color:#aaa;font-style:italic;padding-left:0.5rem;';
                    msg.textContent = '"' + rec.message + '"';
                    el.appendChild(msg);
                }
                donationHistoryList.appendChild(el);
            });
        })
        .catch(function () {
            donationHistoryList.textContent = 'Failed to load history.';
        });
}
