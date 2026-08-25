package main

/*
#cgo CFLAGS: -I${SRCDIR}/c_src
#include <stdlib.h>
#include "c_src/core_logic.h"
*/
import "C"
import (
	"errors"
	"os"
	"strings"
	"unsafe"
)

func initSessionSecret(secret string) bool {
	cs := C.CString(secret)
	ok := C.init_session_secret(cs) == 1
	C.free(unsafe.Pointer(cs))
	return ok
}

// M35/C2: refuse short SESSION_SECRET; C never falls back to 0x5A mix.
func applySessionSecret(secret string) error {
	if secret == "" {
		return errSessionSecretRequired
	}
	if !initSessionSecret(secret) {
		return errSessionSecretTooWeak
	}
	return nil
}

func initBroadcastPassword(password string) error {
	cs := C.CString(password)
	ok := C.init_broadcast_password(cs) == 1
	C.free(unsafe.Pointer(cs))
	if !ok {
		return errBroadcastPasswordTooLong
	}
	return nil
}

func initStreamKeyWhitelist(csv string) int {
	cs := C.CString(csv)
	n := int(C.init_stream_key_whitelist(cs))
	C.free(unsafe.Pointer(cs))
	return n
}

func applyPublishPolicy(keys, password string, allowOpen bool) error {
	n := initStreamKeyWhitelist(keys)
	if err := initBroadcastPassword(password); err != nil {
		return err
	}
	if allowOpen {
		return nil
	}
	if strings.TrimSpace(keys) != "" && n <= 0 {
		return errWhitelistParse
	}
	if n <= 0 {
		return errOpenPublish
	}
	if C.broadcast_password_is_set() != 1 {
		return errOpenBroadcast
	}
	return nil
}

func envAllowOpenPublish() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ALLOW_OPEN_PUBLISH"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func publicSlug(streamKey string) string {
	ck := C.CString(streamKey)
	defer C.free(unsafe.Pointer(ck))
	var buf [C.STREAM_KEY_EXACT_LEN + 1]C.char
	C.public_slug_from_key(ck, &buf[0])
	return C.GoString(&buf[0])
}

func publisherOwnsRoom(streamKey, roomID string) bool {
	if streamKey == "" || roomID == "" {
		return false
	}
	slug := publicSlug(streamKey)
	return roomID == slug || roomID == streamKey
}

func generateSessionToken(streamKey string) string {
	ck := C.CString(streamKey)
	defer C.free(unsafe.Pointer(ck))
	var buf [C.SESSION_TOKEN_HEX_LEN + 1]C.char
	C.generate_session_token(ck, &buf[0])
	return C.GoString(&buf[0])
}

func extractStreamKey(token string) (string, bool) {
	return streamKeyFromSessionToken(token)
}

func validateSessionTokenForKey(token, streamKey string) bool {
	return validateBearerForStreamKey(token, streamKey)
}

func sessionTokenHexLen() int { return int(C.SESSION_TOKEN_HEX_LEN) }

func initBroadcastPasswordOK() bool {
	return C.broadcast_password_is_set() == 1
}

var (
	errSessionSecretRequired    = errors.New("SESSION_SECRET is required")
	errSessionSecretTooWeak     = errors.New("SESSION_SECRET must be at least 16 bytes")
	errOpenPublish              = errors.New("ALLOWED_STREAM_KEYS is required (set ALLOW_OPEN_PUBLISH=1 only for local open mode)")
	errOpenBroadcast            = errors.New("BROADCAST_PASSWORD is required (set ALLOW_OPEN_PUBLISH=1 only for local open mode)")
	errWhitelistParse           = errors.New("ALLOWED_STREAM_KEYS is non-empty but no valid 32-char keys loaded")
	errBroadcastPasswordTooLong = errors.New("BROADCAST_PASSWORD must be 1..128 bytes")
)
