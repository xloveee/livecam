package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"livecam/chat"
	"livecam/donations"
)

func TestParseHlsRoom(t *testing.T) {
	cases := []struct {
		in       string
		ok       bool
		room     string
		file     string
		playlist bool
	}{
		{"/hls/room1/master.m3u8", true, "room1", "master.m3u8", true},
		{"/hls/room1/pip.m3u8", true, "room1", "pip.m3u8", true},
		{"/hls/room1/seg001.ts", true, "room1", "seg001.ts", false},
		{"/hls/room1/audio.adts", true, "room1", "audio.adts", false},
		{"/hls/room1/", false, "", "", false},
		{"/hls/room1", false, "", "", false},
		{"/hls/../etc/passwd", false, "", "", false},
		{"/hls/room1/../other/master.m3u8", false, "", "", false},
		{"/s/abc", false, "", "", false},
		{"/watch/room1", false, "", "", false},
	}
	for _, c := range cases {
		room, file, ok := parseHlsRoom(c.in)
		if ok != c.ok || room != c.room || file != c.file {
			t.Errorf("parseHlsRoom(%q) = (%q,%q,%v) want (%q,%q,%v)",
				c.in, room, file, ok, c.room, c.file, c.ok)
		}
		if ok && isHlsPlaylist(file) != c.playlist {
			t.Errorf("isHlsPlaylist(%q)=%v want %v", file, isHlsPlaylist(file), c.playlist)
		}
	}
}

func TestPasswordFromHeaderOrQuery(t *testing.T) {
	// L8: header-only — query must not supply the invite.
	req := httptest.NewRequest(http.MethodGet, "/hls/r/master.m3u8", nil)
	if passwordFromHeaderOrQuery(req) != "" {
		t.Fatal("empty request should have no password")
	}
	req.Header.Set("X-Room-Password", "from-header")
	if got := passwordFromHeaderOrQuery(req); got != "from-header" {
		t.Fatalf("header: %q", got)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/hls/r/master.m3u8?invite=from-q", nil)
	if got := passwordFromHeaderOrQuery(req2); got != "" {
		t.Fatalf("invite query must be ignored: %q", got)
	}
	req3 := httptest.NewRequest(http.MethodGet, "/hls/r/master.m3u8?password=from-pw", nil)
	if got := passwordFromHeaderOrQuery(req3); got != "" {
		t.Fatalf("password query must be ignored: %q", got)
	}
	req4 := httptest.NewRequest(http.MethodGet, "/hls/r/master.m3u8?invite=q", nil)
	req4.Header.Set("X-Room-Password", "h")
	if got := passwordFromHeaderOrQuery(req4); got != "h" {
		t.Fatalf("header: %q", got)
	}
}

func TestRoomPasswordOKFailClosed(t *testing.T) {
	// L8: rust-unreachable / unknown room must not look like "no password".
	info := roomInfoResult{Fetched: false}
	if roomPasswordOK(info, nil, "room") {
		t.Fatal("unfetched room_info must deny")
	}
	info = roomInfoResult{Fetched: true, HasPassword: true, Password: "x"}
	req := httptest.NewRequest(http.MethodGet, "/hls/room/master.m3u8", nil)
	if roomPasswordOK(info, req, "room") {
		t.Fatal("password room without header must deny")
	}
}

func TestInviteCookieRoundTrip(t *testing.T) {
	room := "abcdefghijklmnopqrstuvwxyz012345"
	tok := mintInviteCookie(room, 0)
	if !validInviteCookieValue(tok, room, 0) {
		t.Fatalf("fresh grant rejected: %s", tok)
	}
	if validInviteCookieValue(tok, "otherroom", 0) {
		t.Fatal("grant accepted for other room")
	}
	if validInviteCookieValue("not-a-cookie", room, 0) {
		t.Fatal("garbage accepted")
	}
	expired := signInviteGrant(room, 0, time.Now().Add(-time.Hour).Unix())
	if validInviteCookieValue(expired, room, 0) {
		t.Fatal("expired grant accepted")
	}
	if validInviteCookieValue(tok, room, 1) {
		t.Fatal("M40: grant must die after epoch bump")
	}
}

func TestPlaylistReady(t *testing.T) {
	dir := t.TempDir()
	room := "room1"
	if err := os.Mkdir(filepath.Join(dir, room), 0o755); err != nil {
		t.Fatal(err)
	}
	if playlistReady(dir, room, "master.m3u8") {
		t.Fatal("missing playlist must not be ready")
	}
	empty := filepath.Join(dir, room, "master.m3u8")
	if err := os.WriteFile(empty, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if playlistReady(dir, room, "master.m3u8") {
		t.Fatal("0-byte playlist must not be ready")
	}
	headerOnly := "#EXTM3U\n#EXT-X-VERSION:3\n"
	if err := os.WriteFile(empty, []byte(headerOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	if playlistReady(dir, room, "master.m3u8") {
		t.Fatal("playlist without EXTINF must not be ready")
	}
	ok := "#EXTM3U\n#EXT-X-TARGETDURATION:3\n#EXTINF:2.000,\nseg000.ts\n"
	if err := os.WriteFile(empty, []byte(ok), 0o644); err != nil {
		t.Fatal(err)
	}
	if !playlistReady(dir, room, "master.m3u8") {
		t.Fatal("playlist with EXTINF should be ready")
	}
	if playlistReady(dir, "../etc", "passwd") {
		t.Fatal("path escape must fail")
	}
}

func TestClampDistributionToPlaylists(t *testing.T) {
	dir := t.TempDir()
	room := "room1"
	if err := os.Mkdir(filepath.Join(dir, room), 0o755); err != nil {
		t.Fatal(err)
	}
	want := donations.DistributionConfig{Live: true, HLS: true, PiP: true, Default: "hls", Simulcast: true}
	got := clampDistributionToPlaylists(want, dir, room)
	if got.HLS || got.PiP {
		t.Fatalf("404 playlists still advertised: %+v", got)
	}
	if got.Default != "live" || !got.Live {
		t.Fatalf("default should fall back to live: %+v", got)
	}
	master := "#EXTM3U\n#EXTINF:2.0,\nseg000.ts\n"
	if err := os.WriteFile(filepath.Join(dir, room, "master.m3u8"), []byte(master), 0o644); err != nil {
		t.Fatal(err)
	}
	got = clampDistributionToPlaylists(want, dir, room)
	if !got.HLS || got.PiP {
		t.Fatalf("master ready should keep hls only: %+v", got)
	}
	if got.Default != "hls" {
		t.Fatalf("default hls should stay when master exists: %+v", got)
	}
	pip := "#EXTM3U\n#EXTINF:2.0,\npip000.ts\n"
	if err := os.WriteFile(filepath.Join(dir, room, "pip.m3u8"), []byte(pip), 0o644); err != nil {
		t.Fatal(err)
	}
	got = clampDistributionToPlaylists(want, dir, room)
	if !got.HLS || !got.PiP {
		t.Fatalf("both playlists ready: %+v", got)
	}
}

func TestInviteCookieNotInURL(t *testing.T) {
	// Cookie value is HMAC(room|exp|password), never the raw secret.
	tok := mintInviteCookie("room", 0)
	if tok == "super-secret-invite" {
		t.Fatal("cookie stored raw password")
	}
	u := url.URL{Path: "/hls/room/master.m3u8", RawQuery: "invite=" + url.QueryEscape("super-secret-invite")}
	if u.Query().Get("invite") != "super-secret-invite" {
		t.Fatal("query helper broken")
	}
}

func TestHlsBannedIP403(t *testing.T) {
	data := t.TempDir()
	modDir := filepath.Join(data, "chat_moderation")
	if err := os.MkdirAll(modDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "hlsbanroom.json"), []byte(`{"banned_nicks":[],"banned_ips":["198.51.100.44"],"mods":[]}`), 0640); err != nil {
		t.Fatal(err)
	}
	hub := chat.NewHubWithDir(data)
	if !hub.IsIPBanned("hlsbanroom", "198.51.100.44") {
		t.Fatal("persist did not load")
	}

	hlsDir := t.TempDir()
	roomDir := filepath.Join(hlsDir, "hlsbanroom")
	if err := os.MkdirAll(roomDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roomDir, "master.m3u8"), []byte("#EXTM3U\n#EXTINF:2.0,\nseg.ts\n"), 0644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(hlsGateHandler(hlsDir, hub))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/hls/hlsbanroom/master.m3u8", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.44")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("banned IP: status %d body %s", resp.StatusCode, body)
	}
}
