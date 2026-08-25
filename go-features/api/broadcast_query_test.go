package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBroadcastQueryKeyDoesNotMintSession(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broadcast_login.html"), []byte("LOGIN"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broadcast.html"), []byte("STUDIO"), 0644); err != nil {
		t.Fatal(err)
	}
	prev := clientDir
	clientDir = dir
	defer func() { clientDir = prev }()

	if err := applySessionSecret(testSecret); err != nil {
		t.Fatal(err)
	}
	if err := applyPublishPolicy(testKey, "studio-password", false); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/broadcast?stream_key="+testKey, nil)
	rec := httptest.NewRecorder()
	broadcastHandler(rec, req)
	res := rec.Result()
	for _, c := range res.Cookies() {
		if c.Name == "broadcaster_session" && c.Value != "" {
			t.Fatal("query stream_key minted a session cookie (H17 still open)")
		}
	}
	if !strings.Contains(rec.Body.String(), "LOGIN") {
		t.Fatalf("want login page, got %q", rec.Body.String())
	}
}

func TestBroadcastExistingSessionServesStudio(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broadcast_login.html"), []byte("LOGIN"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broadcast.html"), []byte("STUDIO"), 0644); err != nil {
		t.Fatal(err)
	}
	prev := clientDir
	clientDir = dir
	defer func() { clientDir = prev }()

	if err := applySessionSecret(testSecret); err != nil {
		t.Fatal(err)
	}
	if err := applyPublishPolicy(testKey, "studio-password", false); err != nil {
		t.Fatal(err)
	}
	tok := generateSessionToken(testKey)
	if tok == "" {
		t.Fatal("no token")
	}

	req := httptest.NewRequest(http.MethodGet, "/broadcast", nil)
	req.AddCookie(&http.Cookie{Name: "broadcaster_session", Value: tok})
	rec := httptest.NewRecorder()
	broadcastHandler(rec, req)
	if !strings.Contains(rec.Body.String(), "STUDIO") {
		t.Fatalf("want studio, got %q", rec.Body.String())
	}
}
