package chat

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckChatOriginAllowlist(t *testing.T) {
	t.Setenv("PUBLIC_BASE_URL", "")
	t.Setenv("PUBLIC_DOMAIN", "")
	t.Setenv("CHAT_ALLOWED_ORIGINS", "")

	req := httptest.NewRequest(http.MethodGet, "https://live.example/api/chat/x", nil)
	req.Host = "live.example"
	req.TLS = &tls.ConnectionState{}
	if !checkChatOrigin(req) {
		t.Fatal("missing Origin must allow (native)")
	}

	req.Header.Set("Origin", "https://evil.example")
	if checkChatOrigin(req) {
		t.Fatal("cross-site Origin must deny")
	}

	req.Header.Set("Origin", "https://live.example")
	if !checkChatOrigin(req) {
		t.Fatal("same host Origin must allow")
	}

	t.Setenv("PUBLIC_BASE_URL", "https://cdn.example")
	req.Header.Set("Origin", "https://cdn.example")
	if !checkChatOrigin(req) {
		t.Fatal("PUBLIC_BASE_URL must allow")
	}
	req.Header.Set("Origin", "https://live.example")
	// still allowed via request host
	if !checkChatOrigin(req) {
		t.Fatal("request host still allowed")
	}

	t.Setenv("CHAT_ALLOWED_ORIGINS", "https://extra.example, https://other.example/")
	req.Header.Set("Origin", "https://extra.example")
	if !checkChatOrigin(req) {
		t.Fatal("CHAT_ALLOWED_ORIGINS must allow")
	}
}
