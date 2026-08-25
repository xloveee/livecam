package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBroadcastIgnoresStreamKeyQuery(t *testing.T) {
	dir := t.TempDir()
	login := filepath.Join(dir, "broadcast_login.html")
	if err := os.WriteFile(login, []byte("login"), 0o644); err != nil {
		t.Fatal(err)
	}
	studio := filepath.Join(dir, "broadcast.html")
	if err := os.WriteFile(studio, []byte("studio"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := clientDir
	clientDir = dir
	t.Cleanup(func() { clientDir = old })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/broadcast?stream_key=abcdefghijklmnopqrstuvwxyz012345", nil)
	broadcastHandler(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if body := rr.Body.String(); body != "login" {
		t.Fatalf("wanted login page, got %q", body)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == "broadcaster_session" {
			t.Fatal("must not set session from query")
		}
	}
}
