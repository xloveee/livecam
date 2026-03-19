package chat

/*
#cgo CFLAGS: -I${SRCDIR}/c_src
#include <stdlib.h>
#include "c_src/chat_logic.h"
*/
import "C"
import "unsafe"

const (
	CmdNone        = 0
	CmdBan         = 1
	CmdUnban       = 2
	CmdTimeout     = 3
	CmdSlow        = 4
	CmdSubscribers = 5
	CmdClear       = 6
	CmdMod         = 7
	CmdUnmod       = 8
)

type ChatCommand struct {
	Type int
	Arg1 string
	Arg2 int
}

func ValidateNickname(nick string) bool {
	cNick := C.CString(nick)
	defer C.free(unsafe.Pointer(cNick))
	return C.is_nickname_valid(cNick) == 1
}

func ParseCommand(text string) (ChatCommand, bool) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var out C.chat_command_t
	ok := C.parse_chat_command(cText, &out)
	if ok == 0 {
		return ChatCommand{}, false
	}
	return ChatCommand{
		Type: int(out._type),
		Arg1: C.GoString(&out.arg1[0]),
		Arg2: int(out.arg2),
	}, true
}

func CheckRateLimit(lastMsgSec, nowSec int64, slowSec int) bool {
	return C.check_chat_rate_limit(
		C.int64_t(lastMsgSec),
		C.int64_t(nowSec),
		C.int32_t(slowSec),
	) == 1
}

func SanitizeMessage(text string) (string, bool) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var buf [C.CHAT_MAX_MSG_LEN + 1]C.char
	n := C.apply_moderation(cText, &buf[0], C.int32_t(C.CHAT_MAX_MSG_LEN+1))
	if n <= 0 {
		return "", false
	}
	return C.GoString(&buf[0]), true
}
