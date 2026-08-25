package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNginxHTTPBootstrapIsACMEOnly(t *testing.T) {
	candidates := []string{
		filepath.Join("..", "..", "deploy", "templates", "nginx-http.conf"),
		filepath.Join("deploy", "templates", "nginx-http.conf"),
	}
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("nginx-http.conf: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, "/.well-known/acme-challenge/") {
		t.Fatal("missing ACME location")
	}
	if strings.Contains(s, "proxy_pass") {
		t.Fatal("HTTP bootstrap still proxies the app (H19)")
	}
	if strings.Contains(s, "location /api") || strings.Contains(s, "/broadcast") {
		t.Fatal("HTTP bootstrap still exposes app paths")
	}
}
