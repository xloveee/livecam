#!/usr/bin/env bash
# Verify livecam server APIs required by the mobile app.
set -euo pipefail

BASE_URL="${1:-https://indep.stream}"
BROADCAST_PASSWORD="${2:-}"
STREAM_KEY="${3:-}"

echo "Server: $BASE_URL"
echo ""

fail=0
check() {
  local name="$1"
  local code="$2"
  local expect="$3"
  if [[ "$code" == "$expect" ]]; then
    echo "OK   $name ($code)"
  else
    echo "FAIL $name (got $code, want $expect)"
    fail=1
  fi
}

health_code=$(curl -sS -o /tmp/livecam_health.json -w "%{http_code}" "$BASE_URL/api/health" || echo "000")
check "GET /api/health" "$health_code" "200"
cat /tmp/livecam_health.json
echo ""

config_code=$(curl -sS -o /tmp/livecam_config.json -w "%{http_code}" "$BASE_URL/api/config" || echo "000")
check "GET /api/config" "$config_code" "200"
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import json
with open("/tmp/livecam_config.json") as f:
    d = json.load(f)
servers = d.get("iceServers") or []
print(f"  iceServers: {len(servers)} entries")
for s in servers:
    urls = s.get("urls")
    has_turn = bool(s.get("username"))
    print(f"    - {urls} {'(TURN)' if has_turn else ''}")
PY
fi
echo ""

if [[ -n "$STREAM_KEY" ]]; then
  auth_body=$(printf '{"password":"%s","stream_key":"%s"}' "$BROADCAST_PASSWORD" "$STREAM_KEY")
  auth_code=$(curl -sS -o /tmp/livecam_auth.json -w "%{http_code}" \
    -X POST "$BASE_URL/api/auth/broadcast" \
    -H 'Content-Type: application/json' \
    -d "$auth_body" || echo "000")
  check "POST /api/auth/broadcast" "$auth_code" "200"
  if [[ "$auth_code" == "200" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      python3 - <<'PY'
import json
with open("/tmp/livecam_auth.json") as f:
    d = json.load(f)
assert d.get("token"), "missing token field — deploy app branch Go proxy"
assert d.get("stream_key"), "missing stream_key"
print(f"  token length: {len(d['token'])}")
print("  Bearer auth ready for mobile WHIP")
PY
    else
      grep -q '"token"' /tmp/livecam_auth.json && echo "  token present" || { echo "  missing token"; fail=1; }
    fi
  fi
  echo ""
  room_code=$(curl -sS -o /tmp/livecam_room.json -w "%{http_code}" \
    "$BASE_URL/api/room_info/$STREAM_KEY" || echo "000")
  check "GET /api/room_info/{key}" "$room_code" "200"
else
  echo "SKIP POST /api/auth/broadcast (pass broadcast password + 32-char stream key as args 2 and 3)"
fi

echo ""
if [[ "$fail" -eq 0 ]]; then
  echo "All checks passed."
else
  echo "Some checks failed."
  exit 1
fi
