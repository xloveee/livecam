package main

import (
	"net"
	"os"
	"strings"
)

// listenAddr is M1: default to loopback so a missed reverse-proxy does not
// expose the plaintext API. Override with GO_LISTEN_ADDR (host:port) or
// legacy GO_LISTEN_PORT (still loopback).
func listenAddr() string {
	if full := strings.TrimSpace(os.Getenv("GO_LISTEN_ADDR")); full != "" {
		if _, _, err := net.SplitHostPort(full); err == nil {
			return full
		}
		// host only — pair with default port
		port := strings.TrimSpace(os.Getenv("GO_LISTEN_PORT"))
		if port == "" {
			port = "8443"
		}
		return net.JoinHostPort(full, port)
	}
	port := strings.TrimSpace(os.Getenv("GO_LISTEN_PORT"))
	if port == "" {
		port = "8443"
	}
	return net.JoinHostPort("127.0.0.1", port)
}
