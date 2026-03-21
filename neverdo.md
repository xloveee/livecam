# Never Do Again

Hard-won lessons from debugging a client-side black screen that turned out to be a symptom of architectural drift, not a code bug.

## The Mistake

We duplicated server-enforced logic in the client layer. The Rust SFU already controlled codecs, quality, and session lifecycle — but the JavaScript grew its own parallel implementations of the same responsibilities. When a playback bug appeared on one browser, we kept adding more client-side workarounds on top of an already-redundant stack. Each fix introduced new state, new edge cases, and new failure modes.

## What Went Wrong, Specifically

1. **Re-deriving server knowledge on the client.** The SFU had per-viewer RTCP stats (loss, NACKs, RTT). We ignored them and built a second quality-adaptation engine in JavaScript that polled `getStats()` and re-derived the same metrics. Two systems, one truth.

2. **Per-browser adapter sprawl.** Instead of asking "why does the universal path not work?", we created browser-specific adapter files with speculative workarounds (codec preferences, `video.load()` hacks, transport policy overrides). None of them addressed the actual issue. Each one added surface area for new regressions.

3. **Fixing symptoms instead of diagnosing root causes.** The black screen showed `Decoded: 0` with healthy bitrate — the browser received packets but never decoded them. Instead of isolating whether this was a WebRTC/WKWebView limitation, we layered on client-side codec negotiation, play-timeout auto-fallbacks, and debounced play logic. Every workaround complicated the next debugging session.

4. **Polling for state the server already tracks.** Viewers polled HTTP endpoints every 5 seconds for room liveness, viewer counts, and password changes — while an idle WebSocket to the same room was already open.

## Rules Going Forward

### The server is the authority

- If the Rust SFU enforces a codec whitelist, the client does not set codec preferences.
- If the SFU has per-viewer connection stats, quality adaptation lives in the SFU — not in JavaScript.
- If the Go proxy knows room state, it pushes changes over an existing channel — the client does not poll.

### The client is a thin rendering layer

- The client's job: call browser APIs (`RTCPeerConnection`, `video.play()`, DOM updates), display what the server tells it, and detect local-only conditions (stall watchdog, autoplay policy).
- Every line of client-side logic that duplicates a server-side decision is a future bug.
- Before adding any "smart" client logic, ask: does the server already know this? Can the server decide this?

### Do not create browser-specific code paths without evidence

- A debug snapshot showing the problem on one browser is not evidence that the browser needs special handling. It might mean the universal path has a bug.
- Before creating a browser adapter: reproduce on two browsers first, read the spec, and check if the server's SDP answer is correct.
- If the universal WebRTC path fails on a specific browser, the first investigation should be: "is this a known browser limitation?" — not "what client workaround can I add?"

### Do not layer workarounds

- If a fix doesn't solve the problem, revert it before trying the next one.
- If you've added three workarounds and the issue persists, stop. The problem is not where you think it is.
- Workaround stacking is a signal to step back and re-read the architecture document.

### Keep the client measurably small

- The production stats loop should do one thing: detect stalled media. All detailed stats parsing belongs behind the debug flag.
- Every HTTP request the client makes during steady-state playback is a design smell. The `live` state should make zero HTTP requests — the WebSocket push handles it.
- One JS file, one responsibility boundary. If you can't explain what a file does in one sentence, it's doing too much.
