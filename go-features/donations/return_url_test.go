package donations

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"livecam/chat"
)

func TestAllowReturnURL(t *testing.T) {
	t.Setenv("PUBLIC_DOMAIN", "live.example")
	t.Setenv("PUBLIC_BASE_URL", "")
	t.Setenv("DONATION_RETURN_HOSTS", "")

	req := httptest.NewRequest(http.MethodPost, "https://live.example/api/donations/initiate", nil)
	req.Host = "live.example"

	if !allowReturnURL("", req) {
		t.Fatal("empty ok")
	}
	if !allowReturnURL("https://live.example/thanks", req) {
		t.Fatal("public domain")
	}
	if !allowReturnURL("https://cdn.live.example/x", req) {
		t.Fatal("subdomain")
	}
	if allowReturnURL("https://evil.example/phish", req) {
		t.Fatal("evil host")
	}
	if allowReturnURL("javascript:alert(1)", req) {
		t.Fatal("js")
	}
	if allowReturnURL("http://live.example/x", req) {
		t.Fatal("http non-local")
	}
	if !allowReturnURL("http://127.0.0.1:8443/x", req) {
		t.Fatal("loopback http")
	}
}

func TestDonationRateLimitKeyIgnoresUntrustedXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example/api/donations/initiate", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	ip := chat.ClientIP(req)
	if ip == "1.2.3.4" {
		t.Fatal("untrusted XFF must not win")
	}
	if ip != "8.8.8.8" {
		t.Fatalf("got %q", ip)
	}
}
