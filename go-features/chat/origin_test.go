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

func TestCheckChatOriginIgnoresForwardedHost(t *testing.T) {
	t.Setenv("PUBLIC_BASE_URL", "")
	t.Setenv("PUBLIC_DOMAIN", "")
	t.Setenv("CHAT_ALLOWED_ORIGINS", "")
	req := httptest.NewRequest(http.MethodGet, "https://live.example/api/chat/x", nil)
	req.Host = "live.example"
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	if checkChatOrigin(req) {
		t.Fatal("X-Forwarded-Host must not allow cross-site Origin (H27)")
	}
}

func TestCheckChatOriginTrustedProxyProto(t *testing.T) {
	t.Setenv("PUBLIC_BASE_URL", "")
	t.Setenv("PUBLIC_DOMAIN", "")
	t.Setenv("CHAT_ALLOWED_ORIGINS", "")

	req := httptest.NewRequest(http.MethodGet, "http://live.example/api/chat/x", nil)
	req.Host = "live.example"
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://live.example")
	if !checkChatOrigin(req) {
		t.Fatal("L11: loopback X-Forwarded-Proto=https must allow https Origin")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://live.example/api/chat/x", nil)
	req2.Host = "live.example"
	req2.RemoteAddr = "8.8.8.8:443"
	req2.Header.Set("X-Forwarded-Proto", "https")
	req2.Header.Set("Origin", "https://live.example")
	if checkChatOrigin(req2) {
		t.Fatal("L11: client-spoofed X-Forwarded-Proto must not mint https Host fallback")
	}

	req3 := httptest.NewRequest(http.MethodGet, "http://live.example/api/chat/x", nil)
	req3.Host = "live.example"
	req3.RemoteAddr = "127.0.0.1:1"
	req3.Header.Set("X-Forwarded-Proto", "https")
	req3.Header.Set("X-Forwarded-Host", "evil.example")
	req3.Header.Set("Origin", "https://evil.example")
	if checkChatOrigin(req3) {
		t.Fatal("H27: X-Forwarded-Host still ignored when proto is trusted")
	}
}
