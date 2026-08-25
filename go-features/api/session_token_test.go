package main

import (
	"encoding/hex"
	"testing"
)

const testKey = "abcdefghijklmnopqrstuvwxyz012345"
const testSecret = "sixteen-byte-key!!"

func xorInvertFirst32(tokenHex, secret string) string {
	if len(tokenHex) < 64 {
		return ""
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b, err := hex.DecodeString(tokenHex[i*2 : i*2+2])
		if err != nil || len(b) != 1 {
			return ""
		}
		digest := b[0]
		s := secret[i%len(secret)]
		add := byte(i*7 + 0x3B)
		out[i] = (digest - add) ^ s
	}
	return string(out)
}

func TestHMACSessionTokenRoundTrip(t *testing.T) {
	initStreamKeyWhitelist("")
	initSessionSecret(testSecret)
	tok := generateSessionToken(testKey)
	if len(tok) != sessionTokenHexLen() {
		t.Fatalf("token len %d want %d", len(tok), sessionTokenHexLen())
	}
	got, ok := extractStreamKey(tok)
	if !ok || got != testKey {
		t.Fatalf("extract got %q ok=%v", got, ok)
	}
	if !validateSessionTokenForKey(tok, testKey) {
		t.Fatal("validate_session_token_for_key failed")
	}
}

func TestHMACSessionTokenNotXORReversible(t *testing.T) {
	initStreamKeyWhitelist("")
	initSessionSecret(testSecret)
	tok := generateSessionToken(testKey)
	if xorInvertFirst32(tok, testSecret) == testKey {
		t.Fatal("first 32 token bytes still invert to the stream key (C1 still open)")
	}
}

func TestHMACSessionTokenRejectsWrongSecret(t *testing.T) {
	initStreamKeyWhitelist("")
	initSessionSecret(testSecret)
	tok := generateSessionToken(testKey)
	initSessionSecret("sixteen-byte-KEY!!")
	if _, ok := extractStreamKey(tok); ok {
		t.Fatal("extract succeeded under the wrong secret")
	}
}

func TestHMACSessionTokenCannotMintWithoutSecret(t *testing.T) {
	initStreamKeyWhitelist("")
	initSessionSecret("")
	if tok := generateSessionToken(testKey); tok != "" {
		t.Fatal("generate minted a token with no secret")
	}
}

func TestHMACSessionTokenWhitelistGate(t *testing.T) {
	initSessionSecret(testSecret)
	other := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	initStreamKeyWhitelist(other)
	tok := generateSessionToken(testKey)
	if _, ok := extractStreamKey(tok); ok {
		t.Fatal("extract accepted a key outside the whitelist")
	}
	initStreamKeyWhitelist(testKey)
	got, ok := extractStreamKey(tok)
	if !ok || got != testKey {
		t.Fatal("extract rejected a whitelisted key")
	}
	initStreamKeyWhitelist("")
}

func TestApplySessionSecretRejectsEmptyAndShort(t *testing.T) {
	if err := applySessionSecret(""); err != errSessionSecretRequired {
		t.Fatalf("empty: %v", err)
	}
	if err := applySessionSecret("short-secret"); err != errSessionSecretTooWeak {
		t.Fatalf("short: %v", err)
	}
	if err := applySessionSecret(testSecret); err != nil {
		t.Fatalf("ok: %v", err)
	}
}
