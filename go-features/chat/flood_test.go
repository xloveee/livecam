package chat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFloodConstants(t *testing.T) {
	if FloodWindowSec != 10 || FloodMaxMsgs != 5 || FloodDecaySec != 120 {
		t.Fatalf("window=%d max=%d decay=%d", FloodWindowSec, FloodMaxMsgs, FloodDecaySec)
	}
	if FloodMuteS1 != 30 || FloodMuteS2 != 120 || FloodMuteS3 != 600 || FloodBanStrike != 4 {
		t.Fatalf("mutes=%d/%d/%d banStrike=%d", FloodMuteS1, FloodMuteS2, FloodMuteS3, FloodBanStrike)
	}
}

func floodBurst(st *FloodTracker, now int64, n int) (lastAction, lastLeft int) {
	for i := 0; i < n; i++ {
		lastAction, lastLeft = CheckChatFlood(st, now)
	}
	return lastAction, lastLeft
}

func TestCheckChatFloodFiveAllowedSixthStrikes(t *testing.T) {
	var st FloodTracker
	now := int64(1_700_000_000)
	for i := 0; i < FloodMaxMsgs; i++ {
		act, left := CheckChatFlood(&st, now+int64(i))
		if act != FloodAllow || left != 0 {
			t.Fatalf("msg %d: action=%d left=%d want ALLOW", i+1, act, left)
		}
	}
	act, left := CheckChatFlood(&st, now+int64(FloodMaxMsgs))
	if act != FloodStrike || left != FloodMuteS1 {
		t.Fatalf("6th: action=%d left=%d want STRIKE/%d", act, left, FloodMuteS1)
	}
	if st.Strikes != 1 {
		t.Fatalf("strikes=%d want 1", st.Strikes)
	}
	act, left = CheckChatFlood(&st, now+int64(FloodMaxMsgs)+1)
	if act != FloodMuted {
		t.Fatalf("during mute: action=%d", act)
	}
	if left <= 0 || left > FloodMuteS1 {
		t.Fatalf("mute left=%d", left)
	}
}

func TestCheckChatFloodLadderThenBan(t *testing.T) {
	var st FloodTracker
	now := int64(2_000_000_000)

	wantMute := []int{FloodMuteS1, FloodMuteS2, FloodMuteS3}
	for strike := 1; strike <= 3; strike++ {
		act, left := floodBurst(&st, now, FloodMaxMsgs+1)
		if act != FloodStrike || left != wantMute[strike-1] {
			t.Fatalf("strike %d: action=%d left=%d want STRIKE/%d (strikes=%d)",
				strike, act, left, wantMute[strike-1], st.Strikes)
		}
		if int(st.Strikes) != strike {
			t.Fatalf("after strike %d: tracker strikes=%d", strike, st.Strikes)
		}
		mid := now + int64(wantMute[strike-1])/2
		act, left = CheckChatFlood(&st, mid)
		if act != FloodMuted || left <= 0 {
			t.Fatalf("strike %d still muted: action=%d left=%d", strike, act, left)
		}
		now = now + int64(wantMute[strike-1]) + 1
	}

	act, left := floodBurst(&st, now, FloodMaxMsgs+1)
	if act != FloodBan {
		t.Fatalf("strike 4: action=%d left=%d want BAN", act, left)
	}
	if st.Strikes != int32(FloodBanStrike) {
		t.Fatalf("strikes=%d want %d", st.Strikes, FloodBanStrike)
	}
	act, _ = CheckChatFlood(&st, now+1)
	if act != FloodMuted && act != FloodBan {
		t.Fatalf("after ban action=%d want MUTED or BAN", act)
	}
}

func TestCheckChatFloodDecayAfterQuiet(t *testing.T) {
	var st FloodTracker
	now := int64(3_000_000_000)
	act, _ := floodBurst(&st, now, FloodMaxMsgs+1)
	if act != FloodStrike || st.Strikes != 1 {
		t.Fatalf("setup strike: action=%d strikes=%d", act, st.Strikes)
	}
	// Still inside mute + decay: strikes must stick.
	unmute := now + int64(FloodMuteS1)
	act, _ = CheckChatFlood(&st, unmute)
	if act != FloodAllow {
		t.Fatalf("first msg at unmute: action=%d", act)
	}
	if st.Strikes != 1 {
		t.Fatalf("strikes at unmute=%d want 1", st.Strikes)
	}

	// Quiet 2 minutes after mute ends, with no attempts in between.
	var st2 FloodTracker
	floodBurst(&st2, now, FloodMaxMsgs+1)
	quiet := now + int64(FloodMuteS1) + int64(FloodDecaySec)
	act, _ = CheckChatFlood(&st2, quiet)
	if act != FloodAllow {
		t.Fatalf("after quiet: action=%d", act)
	}
	if st2.Strikes != 0 {
		t.Fatalf("strikes after quiet=%d want 0", st2.Strikes)
	}

	// Strike 2 mute is also 120s; waiting out that mute must not decay.
	var st3 FloodTracker
	t0 := now
	floodBurst(&st3, t0, FloodMaxMsgs+1)
	t1 := t0 + int64(FloodMuteS1) + 1
	floodBurst(&st3, t1, FloodMaxMsgs+1)
	if st3.Strikes != 2 {
		t.Fatalf("setup strike2=%d", st3.Strikes)
	}
	act, _ = CheckChatFlood(&st3, t1+int64(FloodMuteS2))
	if act != FloodAllow {
		t.Fatalf("first msg after strike2 mute: action=%d", act)
	}
	if st3.Strikes != 2 {
		t.Fatalf("strike2 must survive its own mute, strikes=%d", st3.Strikes)
	}
}

func TestFloodMuteNotice(t *testing.T) {
	if g := floodMuteNotice(30); g != "You are muted for 30 seconds." {
		t.Fatalf("30s: %q", g)
	}
	if g := floodMuteNotice(120); g != "You are muted for 2 minutes." {
		t.Fatalf("2min: %q", g)
	}
	if g := floodMuteNotice(600); g != "You are muted for 10 minutes." {
		t.Fatalf("10min: %q", g)
	}
	if g := floodMuteNotice(1); g != "You are muted for 1 second." {
		t.Fatalf("1s: %q", g)
	}
}

func TestHandleMessageFloodDropsAndPrivateNotice(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	v := testClient(h, "r1", "Alice", RoleViewer)
	if _, err := h.Join(v); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)
	drainMsgs(v)

	for i := 0; i < FloodMaxMsgs; i++ {
		h.HandleMessage(v, "ok"+itoa(i))
	}
	got := drainMsgs(spec)
	if n := countMsgText(got, "ok4"); n != 1 {
		t.Fatalf("fifth message should land, msgs=%v", got)
	}

	h.HandleMessage(v, "too-fast")
	if n := countMsgText(drainMsgs(spec), "too-fast"); n != 0 {
		t.Fatalf("sixth message must not broadcast")
	}
	priv := drainMsgs(v)
	found := false
	for _, m := range priv {
		if m.Type == "system" && strings.HasPrefix(m.Text, "You are muted for") {
			found = true
		}
	}
	if !found {
		t.Fatalf("muted user should get a private notice, got %v", priv)
	}
	if n := countMsgText(priv, "too-fast"); n != 0 {
		t.Fatalf("muted user must not see their dropped line as a room msg")
	}
}

func TestHandleMessageFloodExemptsBroadcasterAndMod(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	bc := testClient(h, "r1", "Host", RoleBroadcaster)
	if _, err := h.Join(bc); err != nil {
		t.Fatal(err)
	}
	mod := testClient(h, "r1", "Mod", RoleViewer)
	if _, err := h.Join(mod); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(bc, ChatCommand{Type: CmdMod, Arg1: "Mod"})
	drainMsgs(spec)

	for i := 0; i < FloodMaxMsgs+3; i++ {
		h.HandleMessage(bc, "host"+itoa(i))
		h.HandleMessage(mod, "mod"+itoa(i))
	}
	got := drainMsgs(spec)
	if n := countMsgText(got, "host7"); n != 1 {
		t.Fatalf("broadcaster flood should pass, msgs=%v", got)
	}
	if n := countMsgText(got, "mod7"); n != 1 {
		t.Fatalf("mod flood should pass, msgs=%v", got)
	}
}

func TestHandleMessageSlowModeStillApplies(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	bc := testClient(h, "r1", "Host", RoleBroadcaster)
	if _, err := h.Join(bc); err != nil {
		t.Fatal(err)
	}
	v := testClient(h, "r1", "Carol", RoleViewer)
	if _, err := h.Join(v); err != nil {
		t.Fatal(err)
	}
	h.HandleCommand(bc, ChatCommand{Type: CmdSlow, Arg2: 30})
	drainMsgs(spec)
	drainMsgs(v)

	h.HandleMessage(v, "first")
	if n := countMsgText(drainMsgs(spec), "first"); n != 1 {
		t.Fatal("first slow-mode message should land")
	}
	h.HandleMessage(v, "second")
	if n := countMsgText(drainMsgs(spec), "second"); n != 0 {
		t.Fatal("slow mode must still drop the second message")
	}
	priv := drainMsgs(v)
	found := false
	for _, m := range priv {
		if m.Type == "system" && strings.Contains(m.Text, "Slow mode is active") {
			found = true
		}
	}
	if !found {
		t.Fatalf("slow mode notice missing: %v", priv)
	}
}

func TestFloodMuteSurvivesReconnect(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	v := testClient(h, "r1", "Dave", RoleViewer)
	if _, err := h.Join(v); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)
	for i := 0; i < FloodMaxMsgs+1; i++ {
		h.HandleMessage(v, "burst"+itoa(i))
	}
	drainMsgs(spec)
	h.Leave(v)

	v2 := testClient(h, "r1", "Dave", RoleViewer)
	if _, err := h.Join(v2); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)
	h.HandleMessage(v2, "after-reconnect")
	if n := countMsgText(drainMsgs(spec), "after-reconnect"); n != 0 {
		t.Fatal("mute must follow the nick after reconnect")
	}
	priv := drainMsgs(v2)
	found := false
	for _, m := range priv {
		if m.Type == "system" && strings.HasPrefix(m.Text, "You are muted for") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rejoined user should still see mute notice, got %v", priv)
	}
}

func TestFloodStrike4PersistsIPBan(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "chat_moderation"), 0750); err != nil {
		t.Fatal(err)
	}
	h := NewHubWithDir(dir)
	spec := testClient(h, "banroom", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	v := testClient(h, "banroom", "Eve", RoleViewer)
	v.ip = "203.0.113.77"
	if _, err := h.Join(v); err != nil {
		t.Fatal(err)
	}
	room := h.getOrCreateRoom("banroom")
	room.mu.Lock()
	st := room.floodTracker("Eve")
	st.Strikes = int32(FloodBanStrike - 1)
	room.mu.Unlock()

	drainMsgs(spec)
	drainMsgs(v)
	for i := 0; i < FloodMaxMsgs+1; i++ {
		h.HandleMessage(v, "spam"+itoa(i))
	}
	if !h.IsIPBanned("banroom", "203.0.113.77") {
		t.Fatal("strike 4 should persist the IP ban")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "chat_moderation", "banroom.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "203.0.113.77") {
		t.Fatalf("persist file missing IP: %s", raw)
	}
	select {
	case <-v.done:
	case <-time.After(time.Second):
		t.Fatal("flood-banned client should be closed")
	}
}

func countMsgText(msgs []OutboundMsg, text string) int {
	n := 0
	for _, m := range msgs {
		if m.Type == "msg" && m.Text == text {
			n++
		}
	}
	return n
}
