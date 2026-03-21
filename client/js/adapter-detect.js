/* adapter-detect.js — Browser detection and adapter instantiation
 *
 * Runs immediately on load. Sniffs the user agent to select the correct
 * WatchAdapter subclass and stores it as window.watchAdapter for
 * watch-core.js to consume.
 *
 * Detection order matters:
 *   1. DuckDuckGo (check first — it contains "DuckDuckGo" in UA)
 *      - iOS variant: WebKit without "Chrome/" → WebKitAdapter
 *      - Android variant: Chromium with "Chrome/" → DuckDuckGoAdapter
 *   2. WebKit-only (Safari, other iOS browsers) → WebKitAdapter
 *   3. Everything else (Chrome, Edge, Brave, Opera) → WatchAdapter (base)
 */

(function () {
    var video = document.getElementById('player');
    var ua = navigator.userAgent;

    var isDDG = /DuckDuckGo/i.test(ua);
    var hasChrome = /Chrome\//.test(ua);
    var isWebKit = /AppleWebKit/.test(ua) && !hasChrome;

    var adapter;

    if (isDDG && isWebKit) {
        adapter = new WebKitAdapter(video);
    } else if (isDDG) {
        adapter = new DuckDuckGoAdapter(video);
    } else if (isWebKit) {
        adapter = new WebKitAdapter(video);
    } else {
        adapter = new WatchAdapter(video);
    }

    window.watchAdapter = adapter;
})();
