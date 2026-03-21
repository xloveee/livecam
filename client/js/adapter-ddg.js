/* adapter-ddg.js — DuckDuckGo Android adapter
 *
 * DDG Android runs Chromium but has privacy features that may restrict
 * ICE candidate gathering to prevent IP leaking. When a TURN server is
 * configured, this adapter forces relay-only ICE to respect DDG's privacy
 * stance while still allowing WebRTC to function. Without TURN, it falls
 * back to 'all' candidates so the connection can still attempt direct.
 */

function DuckDuckGoAdapter(videoEl) {
    WatchAdapter.call(this, videoEl);
}

DuckDuckGoAdapter.prototype = Object.create(WatchAdapter.prototype);
DuckDuckGoAdapter.prototype.constructor = DuckDuckGoAdapter;
DuckDuckGoAdapter.prototype.name = 'duckduckgo';

DuckDuckGoAdapter.prototype.createPC = function (iceServers) {
    var hasTurn = iceServers.some(function (s) {
        var urls = s.urls || s.url || '';
        if (typeof urls === 'string') return urls.indexOf('turn:') === 0;
        return urls.some(function (u) { return u.indexOf('turn:') === 0; });
    });
    return new RTCPeerConnection({
        iceServers: iceServers,
        iceTransportPolicy: hasTurn ? 'relay' : 'all'
    });
};
