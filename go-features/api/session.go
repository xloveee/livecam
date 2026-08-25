package main

/*
#cgo CFLAGS: -I${SRCDIR}/c_src
#include <stdlib.h>
#include "c_src/core_logic.h"
*/
import "C"
import "unsafe"

func initSessionSecret(secret string) {
	cs := C.CString(secret)
	C.init_session_secret(cs)
	C.free(unsafe.Pointer(cs))
}

func initStreamKeyWhitelist(csv string) {
	cs := C.CString(csv)
	C.init_stream_key_whitelist(cs)
	C.free(unsafe.Pointer(cs))
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
