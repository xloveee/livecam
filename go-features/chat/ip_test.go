package chat

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeAndBannable(t *testing.T) {
	if got := NormalizeIP("203.0.113.9:51234"); got != "203.0.113.9" {
		t.Fatalf("host:port: %q", got)
	}
	if got := NormalizeIP("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("ipv6: %q", got)
	}
	if got := NormalizeIP("::ffff:203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("v4-mapped: %q", got)
	}
	if !IsBannableIP("203.0.113.9") || !IsBannableIP("2001:db8::1") {
		t.Fatal("public IPs should be bannable")
	}
	for _, ip := range []string{"127.0.0.1", "::1", "192.168.1.20", "10.0.0.8", "172.16.5.5", "169.254.1.1", "fe80::1", "0.0.0.0"} {
		if IsBannableIP(ip) {
			t.Fatalf("%s should not be bannable", ip)
		}
	}
}

func TestClientIPTrustsOnlyProxyXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("public peer must ignore browser XFF, got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "127.0.0.1:8443"
	req2.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.50")
	if got := ClientIP(req2); got != "203.0.113.50" {
		t.Fatalf("trusted proxy should use last XFF hop, got %q", got)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "10.0.0.2:80"
	req3.Header.Set("X-Forwarded-For", "203.0.113.8")
	if got := ClientIP(req3); got != "203.0.113.8" {
		t.Fatalf("private proxy should use XFF last hop, got %q", got)
	}
}

func TestParsePublicICECandidates(t *testing.T) {
	sdp := "v=0\r\n" +
		"a=candidate:1 1 UDP 2130706431 192.168.1.20 54321 typ host\r\n" +
		"a=candidate:2 1 UDP 1694498815 203.0.113.40 54321 typ srflx raddr 192.168.1.20 rport 54321\r\n" +
		"a=candidate:3 1 UDP 16777215 198.51.100.9 3478 typ relay\r\n" +
		"a=candidate:4 1 UDP 2130706431 127.0.0.1 9 typ host\r\n" +
		"a=candidate:5 1 UDP 2130706431 198.51.100.2 9 typ host\r\n"
	got := ParsePublicICECandidates(sdp)
	want := []string{"198.51.100.2", "203.0.113.40"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseCommandIPBan(t *testing.T) {
	cmd, ok := ParseCommand("/ipban 203.0.113.9")
	if !ok || cmd.Type != CmdIPBan || cmd.Arg1 != "203.0.113.9" {
		t.Fatalf("ipban: %+v ok=%v", cmd, ok)
	}
	cmd, ok = ParseCommand("/ban Alice")
	if !ok || cmd.Type != CmdBan || cmd.Arg1 != "Alice" {
		t.Fatalf("ban: %+v ok=%v", cmd, ok)
	}
}

func TestBanRecordsPublicIPsAndSkipsLAN(t *testing.T) {
	dir := t.TempDir()
	h := NewHubWithDir(dir)
	dropped := []string{}
	h.SetWHEPDropper(func(roomID, sessionID string) {
		dropped = append(dropped, roomID+"/"+sessionID)
	})

	host := testClient(h, "room1", "Host", RoleBroadcaster)
	if _, err := h.Join(host); err != nil {
		t.Fatal(err)
	}
	alice := testClient(h, "room1", "Alice", RoleViewer)
	alice.ip = "192.168.1.50"
	if _, err := h.Join(alice); err != nil {
		t.Fatal(err)
	}
	h.NoteWHEP("room1", "sess-lan", "192.168.1.50", []string{"203.0.113.77"})
	h.HandleCommand(host, ChatCommand{Type: CmdBan, Arg1: "Alice"})
	if !h.IsNickBanned("room1", "Alice") {
		t.Fatal("nick should be banned")
	}
	if h.IsIPBanned("room1", "192.168.1.50") {
		t.Fatal("LAN IP must not be banned")
	}
	if !h.IsIPBanned("room1", "203.0.113.77") {
		t.Fatal("public srflx from matching WHEP should be banned")
	}
	if len(dropped) != 1 || dropped[0] != "room1/sess-lan" {
		t.Fatalf("expected WHEP drop, got %v", dropped)
	}

	carol := testClient(h, "room1", "Carol", RoleViewer)
	carol.ip = "203.0.113.10"
	if _, err := h.Join(carol); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(host, ChatCommand{Type: CmdBan, Arg1: "Carol"})
	if !h.IsIPBanned("room1", "203.0.113.10") {
		t.Fatal("public chat IP should be banned")
	}

	raw, err := os.ReadFile(filepath.Join(dir, "chat_moderation", "room1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(raw), []string{`"Alice"`, `"203.0.113.77"`, `"203.0.113.10"`}) {
		t.Fatalf("persist missing bans: %s", raw)
	}

	h2 := NewHubWithDir(dir)
	if !h2.IsIPBanned("room1", "203.0.113.77") || !h2.IsNickBanned("room1", "Alice") {
		t.Fatal("restart should restore bans")
	}
	eve := testClient(h2, "room1", "Eve", RoleViewer)
	eve.ip = "203.0.113.77"
	if _, err := h2.Join(eve); err != errBanned {
		t.Fatalf("banned IP join: %v", err)
	}
}

func TestOnlyBroadcasterCanModAndPersist(t *testing.T) {
	dir := t.TempDir()
	h := NewHubWithDir(dir)
	host := testClient(h, "room1", "Host", RoleBroadcaster)
	mod := testClient(h, "room1", "Mod", RoleViewer)
	if _, err := h.Join(host); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Join(mod); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(host, ChatCommand{Type: CmdMod, Arg1: "Mod"})
	if mod.role != RoleMod {
		t.Fatalf("role %s", mod.role)
	}
	drainMsgs(mod)
	h.HandleCommand(mod, ChatCommand{Type: CmdMod, Arg1: "Eve"})
	got := drainMsgs(mod)
	if n := countSystem(got, "Only the broadcaster can grant or remove moderators."); n != 1 {
		t.Fatalf("mod should be refused, msgs=%v", got)
	}
	h2 := NewHubWithDir(dir)
	room := h2.getOrCreateRoom("room1")
	room.mu.Lock()
	ok := room.mods["Mod"]
	room.mu.Unlock()
	if !ok {
		t.Fatal("mods should persist")
	}
}

func TestIPBanCommandRejectsPrivate(t *testing.T) {
	h := NewHub()
	host := testClient(h, "r", "Host", RoleBroadcaster)
	if _, err := h.Join(host); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(host, ChatCommand{Type: CmdIPBan, Arg1: "10.1.2.3"})
	if h.IsIPBanned("r", "10.1.2.3") {
		t.Fatal("private /ipban must be ignored")
	}
	h.HandleCommand(host, ChatCommand{Type: CmdIPBan, Arg1: "198.51.100.20"})
	if !h.IsIPBanned("r", "198.51.100.20") {
		t.Fatal("public /ipban should land")
	}
	h.HandleCommand(host, ChatCommand{Type: CmdUnban, Arg1: "198.51.100.20"})
	if h.IsIPBanned("r", "198.51.100.20") {
		t.Fatal("unban IP should clear")
	}
}

func TestHandlerBannedIPHTTP403(t *testing.T) {
	h := NewHubWithDir(t.TempDir())
	host := testClient(h, "proofroom", "Host", RoleBroadcaster)
	if _, err := h.Join(host); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(host, ChatCommand{Type: CmdIPBan, Arg1: "198.51.100.30"})

	srv := httptest.NewServer(NewHandler(h, nil, nil))
	defer srv.Close()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/chat/proofroom?nick=Eve", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.30")
	// httptest server peer is loopback, so last XFF hop is trusted.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d want 403", resp.StatusCode)
	}
}

func TestWHEPBannedMatchesSDP(t *testing.T) {
	h := NewHub()
	host := testClient(h, "r", "Host", RoleBroadcaster)
	if _, err := h.Join(host); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(host, ChatCommand{Type: CmdIPBan, Arg1: "203.0.113.88"})
	sdp := "a=candidate:1 1 UDP 1 203.0.113.88 9 typ srflx\r\n"
	if !h.IsWHEPBanned("r", "198.51.100.1", sdp) {
		t.Fatal("offer leaking a banned public srflx should be rejected")
	}
	if h.IsWHEPBanned("r", "198.51.100.1", "a=candidate:1 1 UDP 1 192.168.0.8 9 typ host\r\n") {
		t.Fatal("unrelated LAN offer should pass")
	}
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
