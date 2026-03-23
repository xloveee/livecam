/* sponsor-footer.js — optional line from GET /api/config (LIVECAM_SPONSOR_FOOTER_* env) */

function livecamSponsorConfigFetchUrl() {
    var m = document.querySelector('meta[name="livecam-api-root"]');
    var root = '';
    if (m) {
        root = (m.getAttribute('content') || '').trim().replace(/\/$/, '');
    }
    return root + '/api/config';
}

function applySponsorFooterFromConfig(cfg) {
    var el = document.getElementById('livecam-sponsor-footer');
    if (!el) {
        return;
    }
    var text = (cfg && cfg.sponsor_footer_text != null) ? String(cfg.sponsor_footer_text).trim() : '';
    var urlRaw = (cfg && cfg.sponsor_footer_url != null) ? String(cfg.sponsor_footer_url).trim() : '';
    if (!text) {
        el.hidden = true;
        el.textContent = '';
        el.removeAttribute('aria-label');
        return;
    }
    el.hidden = false;
    el.setAttribute('aria-label', text);
    while (el.firstChild) {
        el.removeChild(el.firstChild);
    }
    if (urlRaw) {
        var a = document.createElement('a');
        a.href = urlRaw;
        a.rel = 'noopener noreferrer';
        a.target = '_blank';
        a.textContent = text;
        el.appendChild(a);
    } else {
        el.textContent = text;
    }
}

async function loadLivecamSponsorFooter() {
    try {
        var resp = await fetch(livecamSponsorConfigFetchUrl(), { credentials: 'same-origin', cache: 'no-store' });
        if (!resp.ok) {
            return;
        }
        applySponsorFooterFromConfig(await resp.json());
    } catch (e) { /* ignore */ }
}
