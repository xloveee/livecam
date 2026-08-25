package main

import (
	"encoding/hex"
	"strings"
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

func TestApplyPublishPolicyFailClosed(t *testing.T) {
	if err := applyPublishPolicy("", "", false); err != errOpenPublish {
		t.Fatalf("empty keys: %v", err)
	}
	if err := applyPublishPolicy(testKey, "", false); err != errOpenBroadcast {
		t.Fatalf("empty password: %v", err)
	}
	if err := applyPublishPolicy("not-a-32-char-key", "pw", false); err != errWhitelistParse {
		t.Fatalf("bad key: %v", err)
	}
	if err := applyPublishPolicy(testKey, "studio-password", false); err != nil {
		t.Fatalf("ok: %v", err)
	}
	if err := applyPublishPolicy("", "", true); err != nil {
		t.Fatalf("allow open: %v", err)
	}
}

func TestPublicSlugNotPublishSecret(t *testing.T) {
	slug := publicSlug(testKey)
	if len(slug) != 32 {
		t.Fatalf("slug len %d", len(slug))
	}
	if slug == testKey {
		t.Fatal("public slug equals publish secret (C4 still open)")
	}
	for _, c := range slug {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("slug not hex: %q", slug)
		}
	}
	if publicSlug(testKey) != slug {
		t.Fatal("slug not stable")
	}
	other := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	if publicSlug(other) == slug {
		t.Fatal("distinct keys share a slug")
	}
	if publisherOwnsRoom(testKey, other) {
		t.Fatal("publisherOwnsRoom accepted a foreign key")
	}
	if !publisherOwnsRoom(testKey, slug) || !publisherOwnsRoom(testKey, testKey) {
		t.Fatal("publisherOwnsRoom rejected own slug/key")
	}
}

func TestApplySfuInternalSecret(t *testing.T) {
	if err := applySfuInternalSecret(""); err != errSfuInternalRequired {
		t.Fatalf("empty: %v", err)
	}
	if err := applySfuInternalSecret("short"); err != errSfuInternalTooWeak {
		t.Fatalf("short: %v", err)
	}
	if err := applySfuInternalSecret("sixteen-byte-sfu!"); err != nil {
		t.Fatalf("ok: %v", err)
	}
}

func TestWhitelistTrimAndFailClosed(t *testing.T) {
	padded := "  " + testKey + "  "
	n := initStreamKeyWhitelist(padded)
	if n != 1 {
		t.Fatalf("trim load count %d want 1", n)
	}
	initSessionSecret(testSecret)
	tok := generateSessionToken(testKey)
	if _, ok := extractStreamKey(tok); !ok {
		t.Fatal("trimmed whitelist should accept the key")
	}

	if err := applyPublishPolicy("not-a-32-char-key", "studio-password", false); err != errWhitelistParse {
		t.Fatalf("bad key: %v want errWhitelistParse", err)
	}
	if err := applyPublishPolicy("   ", "studio-password", false); err != errOpenPublish {
		t.Fatalf("whitespace-only: %v want errOpenPublish", err)
	}
	if err := applyPublishPolicy(testKey, "studio-password", false); err != nil {
		t.Fatalf("ok: %v", err)
	}
}

func TestBroadcastPasswordTooLongFailsClosed(t *testing.T) {
	long := strings.Repeat("x", 129)
	if err := applyPublishPolicy(testKey, long, false); err != errBroadcastPasswordTooLong {
		t.Fatalf("got %v want errBroadcastPasswordTooLong", err)
	}
	if err := applyPublishPolicy(testKey, long, true); err != errBroadcastPasswordTooLong {
		t.Fatalf("allowOpen still: %v", err)
	}
	if err := applyPublishPolicy(testKey, "studio-password", false); err != nil {
		t.Fatalf("ok: %v", err)
	}
	if !initBroadcastPasswordOK() {
		t.Fatal("password should be set after ok init")
	}
}
