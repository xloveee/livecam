package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// publicIceServers builds the ICE list for GET /api/config (H6).
// Static TURN_USERNAME / TURN_CREDENTIAL are never returned.
// When TURN_SECRET (or TURN_REST_SECRET) is set with TURN_URL, mint
// coturn-style time-limited REST credentials instead.
func publicIceServers() []map[string]interface{} {
	var out []map[string]interface{}

	stunURL := os.Getenv("STUN_URL")
	switch stunURL {
	case "none", "off", "-":
		// no STUN
	default:
		if stunURL == "" {
			stunURL = "stun:stun.l.google.com:19302"
		}
		out = append(out, map[string]interface{}{"urls": stunURL})
	}

	turnURL := strings.TrimSpace(os.Getenv("TURN_URL"))
	if turnURL == "" {
		return out
	}
	turnParts := strings.Split(turnURL, ",")
	for i := range turnParts {
		turnParts[i] = strings.TrimSpace(turnParts[i])
	}
	var turnURLs interface{} = turnParts[0]
	if len(turnParts) > 1 {
		turnURLs = turnParts
	}

	secret := strings.TrimSpace(os.Getenv("TURN_SECRET"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("TURN_REST_SECRET"))
	}
	if secret != "" {
		user, cred := mintTurnREST(secret, turnCredentialTTL())
		out = append(out, map[string]interface{}{
			"urls":       turnURLs,
			"username":   user,
			"credential": cred,
		})
		return out
	}

	// H6: withhold long-lived static TURN creds from the public config.
	if os.Getenv("TURN_USERNAME") != "" || os.Getenv("TURN_CREDENTIAL") != "" {
		log.Printf("H6: TURN_URL set with static creds — withheld from /api/config (set TURN_SECRET for REST)")
	}
	return out
}

func turnCredentialTTL() time.Duration {
	sec := 24 * 3600
	if v := strings.TrimSpace(os.Getenv("TURN_CREDENTIAL_TTL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 7*24*3600 {
			sec = n
		}
	}
	return time.Duration(sec) * time.Second
}

func mintTurnREST(secret string, ttl time.Duration) (username, credential string) {
	exp := time.Now().Add(ttl).Unix()
	username = strconv.FormatInt(exp, 10)
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write([]byte(username))
	credential = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return username, credential
}

func writePublicICEConfig(w http.ResponseWriter) {
	resp := map[string]interface{}{
		"iceServers": publicIceServers(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
