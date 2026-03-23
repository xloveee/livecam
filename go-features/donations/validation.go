package donations

/*
#cgo CFLAGS: -I${SRCDIR}/c_src
#include <stdlib.h>
#include "c_src/donation_logic.h"
*/
import "C"
import "unsafe"

func ValidateAmount(amount, minAmount, maxAmount int64) bool {
	return C.validate_donation_amount(
		C.int64_t(amount),
		C.int64_t(minAmount),
		C.int64_t(maxAmount),
	) == 1
}

func SanitizeMessage(text string) (string, bool) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var buf [C.DONATION_MSG_MAX_LEN + 1]C.char
	n := C.sanitize_donation_message(cText, &buf[0], C.int32_t(C.DONATION_MSG_MAX_LEN+1))
	if n <= 0 {
		return "", false
	}
	return C.GoString(&buf[0]), true
}

func CheckRateLimit(lastDonationSec, nowSec int64, cooldownSec int) bool {
	return C.check_donation_rate_limit(
		C.int64_t(lastDonationSec),
		C.int64_t(nowSec),
		C.int32_t(cooldownSec),
	) == 1
}

func ValidateBTCAddress(addr string) bool {
	cAddr := C.CString(addr)
	defer C.free(unsafe.Pointer(cAddr))
	return C.validate_btc_address(cAddr) == 1
}

func ValidateETHAddress(addr string) bool {
	cAddr := C.CString(addr)
	defer C.free(unsafe.Pointer(cAddr))
	return C.validate_eth_address(cAddr) == 1
}
