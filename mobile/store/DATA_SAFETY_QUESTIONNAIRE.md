# Google Play — Data safety form (copy into Play Console)

## Does your app collect or share user data?

**Yes** — data is processed on-device and sent to **user-configured servers** (not a central developer backend).

## Data types

| Type | Collected | Shared | Purpose | Optional |
|------|-----------|--------|---------|----------|
| Photos and videos | Yes (when broadcasting) | Yes → user's server | App functionality | Yes (only when live) |
| Audio | Yes (when broadcasting) | Yes → user's server | App functionality | Yes |
| Messages (chat text) | Yes (when chatting) | Yes → user's server | App functionality | Yes |
| App activity (server URLs, keys) | Stored on device | No to developer | App functionality | Required for use |

## Security practices

- Data encrypted in transit: **Yes** (HTTPS, WSS, DTLS/SRTP via WebRTC)
- Users can request deletion: **Uninstall app** clears local profiles; server data governed by server operator
- Committed to Play Families Policy: **No** (live UGC streaming)

## Privacy policy

https://indep.stream/privacy
