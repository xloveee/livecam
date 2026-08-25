package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicIceServersWithholdsStaticTURN(t *testing.T) {
	t.Setenv("STUN_URL", "stun:stun.example:3478")
	t.Setenv("TURN_URL", "turn:turn.example:3478")
	t.Setenv("TURN_USERNAME", "static-user")
	t.Setenv("TURN_CREDENTIAL", "static-secret-value")
	t.Setenv("TURN_SECRET", "")
	t.Setenv("TURN_REST_SECRET", "")

	servers := publicIceServers()
	raw, _ := json.Marshal(servers)
	if containsCred(servers, "static-user") || containsCred(servers, "static-secret-value") {
		t.Fatalf("static TURN leaked: %s", raw)
	}
	if len(servers) != 1 {
		t.Fatalf("expected STUN only, got %#v", servers)
	}
}

func TestPublicIceServersMintsREST(t *testing.T) {
	t.Setenv("STUN_URL", "none")
	t.Setenv("TURN_URL", "turn:turn.example:3478")
	t.Setenv("TURN_SECRET", "shared-turn-secret")
	t.Setenv("TURN_USERNAME", "static-user")
	t.Setenv("TURN_CREDENTIAL", "static-secret-value")

	servers := publicIceServers()
	if len(servers) != 1 {
		t.Fatalf("got %#v", servers)
	}
	u, _ := servers[0]["username"].(string)
	c, _ := servers[0]["credential"].(string)
	if u == "" || c == "" {
		t.Fatal("missing REST creds")
	}
	if u == "static-user" || c == "static-secret-value" {
		t.Fatal("must not use static creds")
	}
}

func TestConfigHandlerNoStaticTURN(t *testing.T) {
	t.Setenv("STUN_URL", "stun:stun.example:3478")
	t.Setenv("TURN_URL", "turn:turn.example:3478")
	t.Setenv("TURN_USERNAME", "static-user")
	t.Setenv("TURN_CREDENTIAL", "static-secret-value")
	t.Setenv("TURN_SECRET", "")
	t.Setenv("TURN_REST_SECRET", "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	configHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "static-user") || strings.Contains(body, "static-secret-value") {
		t.Fatalf("leaked: %s", body)
	}
}

func containsCred(servers []map[string]interface{}, want string) bool {
	for _, s := range servers {
		for _, k := range []string{"username", "credential"} {
			if v, ok := s[k].(string); ok && v == want {
				return true
			}
		}
	}
	return false
}
