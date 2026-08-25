package main

import "testing"

func TestListenAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv("GO_LISTEN_ADDR", "")
	t.Setenv("GO_LISTEN_PORT", "")
	if got := listenAddr(); got != "127.0.0.1:8443" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("GO_LISTEN_PORT", "9000")
	if got := listenAddr(); got != "127.0.0.1:9000" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("GO_LISTEN_ADDR", "0.0.0.0:8443")
	if got := listenAddr(); got != "0.0.0.0:8443" {
		t.Fatalf("explicit %q", got)
	}
}
