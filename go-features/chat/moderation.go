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
	CmdIPBan       = 9
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

const (
	FloodAllow  = int(C.FLOOD_ALLOW)
	FloodMuted  = int(C.FLOOD_MUTED)
	FloodStrike = int(C.FLOOD_STRIKE)
	FloodBan    = int(C.FLOOD_BAN)

	FloodWindowSec = int(C.FLOOD_WINDOW_SEC)
	FloodMaxMsgs   = int(C.FLOOD_MAX_IN_WINDOW)
	FloodDecaySec  = int(C.FLOOD_DECAY_SEC)
	FloodMuteS1    = int(C.FLOOD_MUTE_STRIKE1)
	FloodMuteS2    = int(C.FLOOD_MUTE_STRIKE2)
	FloodMuteS3    = int(C.FLOOD_MUTE_STRIKE3)
	FloodBanStrike = int(C.FLOOD_BAN_STRIKE)
)

// FloodTracker is the C sliding-window state for one IP or session.
// Layout must match chat_flood_t.
type FloodTracker struct {
	Stamps    [C.FLOOD_STAMP_CAP]int64
	Count     int32
	Strikes   int32
	MuteUntil int64
	LastSeen  int64
}

func CheckChatFlood(st *FloodTracker, nowSec int64) (action, muteLeft int) {
	if st == nil {
		return FloodAllow, 0
	}
	var left C.int32_t
	act := C.check_chat_flood((*C.chat_flood_t)(unsafe.Pointer(st)), C.int64_t(nowSec), &left)
	return int(act), int(left)
}

func floodMuteNotice(sec int) string {
	if sec <= 0 {
		return "You are muted for flooding."
	}
	if sec == 1 {
		return "You are muted for 1 second."
	}
	if sec < 60 {
		return "You are muted for " + itoa(sec) + " seconds."
	}
	if sec%60 == 0 {
		min := sec / 60
		if min == 1 {
			return "You are muted for 1 minute."
		}
		return "You are muted for " + itoa(min) + " minutes."
	}
	return "You are muted for " + itoa(sec) + " seconds."
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
