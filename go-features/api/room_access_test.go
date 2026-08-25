package main

import "testing"

func TestRoomAccessOKFailClosed(t *testing.T) {
	if roomAccessOK(roomInfoResult{}, false) {
		t.Fatal("zero value (rust down) must deny")
	}
	if roomAccessOK(roomInfoResult{HasPassword: false, IsLive: false}, false) {
		t.Fatal("unfetched must deny even when HasPassword is false")
	}
	if !roomAccessOK(roomInfoResult{Fetched: true}, false) {
		t.Fatal("fetched public room should allow")
	}
	// H25: unknown room looks like unfetched (rust 404) — never public by default.
	if roomAccessOK(roomInfoResult{Fetched: false, HasPassword: false}, false) {
		t.Fatal("unknown/unfetched room must deny")
	}
	if roomAccessOK(roomInfoResult{Fetched: true, HasPassword: true}, false) {
		t.Fatal("fetched password room must deny without a passing check")
	}
	if !roomAccessOK(roomInfoResult{Fetched: true, HasPassword: true}, true) {
		t.Fatal("fetched password room should allow when check passed")
	}
}


func TestParseHlsRoomAccess(t *testing.T) {
	room, file, ok := parseHlsRoom("/hls/abcdefghijklmnopqrstuvwxyz012345/master.m3u8")
	if !ok || room != "abcdefghijklmnopqrstuvwxyz012345" || file != "master.m3u8" {
		t.Fatalf("got %q %q %v", room, file, ok)
	}
	if _, _, ok := parseHlsRoom("/hls/../etc/passwd"); ok {
		t.Fatal("escape")
	}
	if _, _, ok := parseHlsRoom("/hls/room/"); ok {
		t.Fatal("dir")
	}
	if _, _, ok := parseHlsRoom("/watch/x"); ok {
		t.Fatal("not hls")
	}
}
