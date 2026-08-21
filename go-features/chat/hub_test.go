package chat

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testClient(h *Hub, roomID, nick, role string) *Client {
	return &Client{
		hub:    h,
		roomID: roomID,
		nick:   nick,
		role:   role,
		send:   make(chan []byte, sendBufLen),
		done:   make(chan struct{}),
	}
}

func drainMsgs(c *Client) []OutboundMsg {
	var out []OutboundMsg
	for {
		select {
		case data := <-c.send:
			var m OutboundMsg
			if json.Unmarshal(data, &m) == nil {
				out = append(out, m)
			}
		default:
			return out
		}
	}
}

func countSystem(msgs []OutboundMsg, text string) int {
	n := 0
	for _, m := range msgs {
		if m.Type == "system" && m.Text == text {
			n++
		}
	}
	return n
}

func TestBroadcasterFiveReconnectsSilent(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)

	var prev *Client
	for i := 0; i < 5; i++ {
		c := testClient(h, "r1", "Broadcaster", RoleBroadcaster)
		if _, err := h.Join(c); err != nil {
			t.Fatalf("join %d: %v", i+1, err)
		}
		if n := countSystem(drainMsgs(c), "Broadcaster joined the chat"); n != 0 {
			t.Fatalf("connect %d: broadcaster socket saw %d join lines", i+1, n)
		}
		if prev != nil {
			h.Leave(prev)
		}
		prev = c
	}

	got := drainMsgs(spec)
	if n := countSystem(got, "Broadcaster joined the chat"); n != 0 {
		t.Fatalf("spectator saw %d Broadcaster join lines, want 0; msgs=%v", n, got)
	}
	if n := countSystem(got, "Broadcaster left the chat"); n != 0 {
		t.Fatalf("spectator saw %d Broadcaster leave lines, want 0; msgs=%v", n, got)
	}
}

func TestViewerFirstJoinAnnouncedOnce(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)

	v := testClient(h, "r1", "Alice", RoleViewer)
	if _, err := h.Join(v); err != nil {
		t.Fatal(err)
	}
	got := drainMsgs(spec)
	if n := countSystem(got, "Alice joined the chat"); n != 1 {
		t.Fatalf("first viewer join: got %d lines, want 1; msgs=%v", n, got)
	}

	v2 := testClient(h, "r1", "Alice", RoleViewer)
	if _, err := h.Join(v2); err != nil {
		t.Fatal(err)
	}
	h.Leave(v)
	got = drainMsgs(spec)
	if n := countSystem(got, "Alice joined the chat"); n != 0 {
		t.Fatalf("same-nick replace should be silent, got %d; msgs=%v", n, got)
	}
	if n := countSystem(got, "Alice left the chat"); n != 0 {
		t.Fatalf("replaced client leave should be silent, got %d; msgs=%v", n, got)
	}
}

func TestViewerRejoinDebounced(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)

	v := testClient(h, "r1", "Bob", RoleViewer)
	if _, err := h.Join(v); err != nil {
		t.Fatal(err)
	}
	if n := countSystem(drainMsgs(spec), "Bob joined the chat"); n != 1 {
		t.Fatalf("first join want 1, got %d", n)
	}

	h.Leave(v)
	if n := countSystem(drainMsgs(spec), "Bob left the chat"); n != 1 {
		t.Fatalf("leave want 1, got %d", n)
	}

	v2 := testClient(h, "r1", "Bob", RoleViewer)
	if _, err := h.Join(v2); err != nil {
		t.Fatal(err)
	}
	if n := countSystem(drainMsgs(spec), "Bob joined the chat"); n != 0 {
		t.Fatalf("rejoin within 30s should be silent, got %d", n)
	}
}

func TestBanAndModStillBroadcast(t *testing.T) {
	h := NewHub()
	spec := testClient(h, "r1", "_g1", RoleGuest)
	if _, err := h.Join(spec); err != nil {
		t.Fatal(err)
	}
	mod := testClient(h, "r1", "Host", RoleBroadcaster)
	if _, err := h.Join(mod); err != nil {
		t.Fatal(err)
	}
	alice := testClient(h, "r1", "Alice", RoleViewer)
	if _, err := h.Join(alice); err != nil {
		t.Fatal(err)
	}
	bob := testClient(h, "r1", "Bob", RoleViewer)
	if _, err := h.Join(bob); err != nil {
		t.Fatal(err)
	}
	drainMsgs(spec)

	h.HandleCommand(mod, ChatCommand{Type: CmdMod, Arg1: "Bob"})
	got := drainMsgs(spec)
	if n := countSystem(got, "Bob is now a moderator."); n != 1 {
		t.Fatalf("mod announce: got %d, msgs=%v", n, got)
	}

	h.HandleCommand(mod, ChatCommand{Type: CmdBan, Arg1: "Alice"})
	got = drainMsgs(spec)
	foundBan := false
	for _, m := range got {
		if m.Type == "ban" && m.Nick == "Alice" {
			foundBan = true
		}
	}
	if !foundBan {
		t.Fatalf("expected ban broadcast, got %v", got)
	}
}

func TestHandlerBroadcasterFiveConnectsNoJoinLine(t *testing.T) {
	hub := NewHub()
	auth := AuthFunc(func(r *http.Request) (string, bool) {
		return "proofroom", true
	})
	srv := httptest.NewServer(NewHandler(hub, auth, nil))
	defer srv.Close()
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")

	spec, _, err := websocket.DefaultDialer.Dial(wsBase+"/api/chat/proofroom?nick=_guest", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Close()

	var mu sync.Mutex
	joins, lefts := 0, 0
	var all []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = spec.SetReadDeadline(time.Now().Add(4 * time.Second))
		for {
			_, data, err := spec.ReadMessage()
			if err != nil {
				return
			}
			var m OutboundMsg
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			mu.Lock()
			all = append(all, m.Type+":"+m.Text)
			if m.Type == "system" && m.Text == "Broadcaster joined the chat" {
				joins++
			}
			if m.Type == "system" && m.Text == "Broadcaster left the chat" {
				lefts++
			}
			mu.Unlock()
		}
	}()

	url := wsBase + "/api/chat/proofroom?nick=Broadcaster"
	for i := 0; i < 5; i++ {
		c, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			t.Fatalf("connect %d: %v", i+1, err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, _, _ = c.ReadMessage()
		c.Close()
		time.Sleep(40 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	_ = spec.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if joins != 0 || lefts != 0 {
		t.Fatalf("5 Broadcaster connects: join lines=%d leave lines=%d want 0/0; msgs=%v", joins, lefts, all)
	}
}

func collectUntilDeadline(c *websocket.Conn, d time.Duration) []OutboundMsg {
	var out []OutboundMsg
	_ = c.SetReadDeadline(time.Now().Add(d))
	for {
		_, data, err := c.ReadMessage()
		if err != nil {
			return out
		}
		var m OutboundMsg
		if json.Unmarshal(data, &m) == nil {
			out = append(out, m)
		}
	}
}

func TestHandlerBroadcasterFiveConnectsNoWelcome(t *testing.T) {
	hub := NewHub()
	auth := AuthFunc(func(r *http.Request) (string, bool) {
		return "proofroom", true
	})
	srv := httptest.NewServer(NewHandler(hub, auth, nil))
	defer srv.Close()
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")
	url := wsBase + "/api/chat/proofroom?nick=Broadcaster"

	welcomes := 0
	var all []string
	for i := 0; i < 5; i++ {
		c, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			t.Fatalf("connect %d: %v", i+1, err)
		}
		got := collectUntilDeadline(c, 250*time.Millisecond)
		for _, m := range got {
			all = append(all, m.Type+":"+m.Text)
			if m.Type == "system" && strings.HasPrefix(m.Text, "Welcome to the chat,") {
				welcomes++
			}
		}
		c.Close()
		time.Sleep(40 * time.Millisecond)
	}
	if welcomes != 0 {
		t.Fatalf("5 Broadcaster connects: welcome lines=%d want 0; msgs=%v", welcomes, all)
	}
}

func TestHandlerViewerWelcomeOnceThenDebounced(t *testing.T) {
	hub := NewHub()
	srv := httptest.NewServer(NewHandler(hub, nil, nil))
	defer srv.Close()
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")
	url := wsBase + "/api/chat/proofroom?nick=Alice"

	countWelcome := func(c *websocket.Conn) int {
		n := 0
		for _, m := range collectUntilDeadline(c, 250*time.Millisecond) {
			if m.Type == "system" && m.Text == "Welcome to the chat, Alice!" {
				n++
			}
		}
		return n
	}

	c1, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := countWelcome(c1); n != 1 {
		c1.Close()
		t.Fatalf("first viewer join: welcome=%d want 1", n)
	}

	c2, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		c1.Close()
		t.Fatal(err)
	}
	if n := countWelcome(c2); n != 0 {
		c2.Close()
		c1.Close()
		t.Fatalf("same-nick replace: welcome=%d want 0", n)
	}
	c1.Close()
	c2.Close()
	time.Sleep(40 * time.Millisecond)

	c3, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := countWelcome(c3); n != 0 {
		c3.Close()
		t.Fatalf("rejoin within 30s: welcome=%d want 0", n)
	}
	c3.Close()
}

func TestOnlyBroadcasterNotReplacedBySecondSocket(t *testing.T) {
	h := NewHub()
	first := testClient(h, "r1", "Broadcaster", RoleBroadcaster)
	if _, err := h.Join(first); err != nil {
		t.Fatal(err)
	}
	second := testClient(h, "r1", "Broadcaster", RoleBroadcaster)
	if _, err := h.Join(second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.done:
		t.Fatal("only Broadcaster socket must not be closed by a second Broadcaster join")
	default:
	}
	h.HandleMessage(first, "from-first")
	got := drainMsgs(second)
	found := false
	for _, m := range got {
		if m.Type == "msg" && m.Text == "from-first" {
			found = true
		}
	}
	if !found {
		t.Fatalf("second socket should still receive, msgs=%v", got)
	}
	select {
	case <-first.done:
		t.Fatal("first socket closed after send")
	default:
	}
}

func TestViewerCannotStealBroadcasterNick(t *testing.T) {
	h := NewHub()
	host := testClient(h, "r1", "Broadcaster", RoleBroadcaster)
	if _, err := h.Join(host); err != nil {
		t.Fatal(err)
	}
	thief := testClient(h, "r1", "Broadcaster", RoleViewer)
	if _, err := h.Join(thief); err != errNickTaken {
		t.Fatalf("viewer steal: %v want errNickTaken", err)
	}
	select {
	case <-host.done:
		t.Fatal("viewer must not close the Broadcaster socket")
	default:
	}
}

func TestPersistSkipsLoopbackAndRFC1918(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chat_moderation")
	if err := os.MkdirAll(path, 0750); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"banned_nicks":[],"banned_ips":["127.0.0.1","192.168.1.224","10.0.0.9","203.0.113.50"],"mods":[]}`)
	if err := os.WriteFile(filepath.Join(path, "lanroom.json"), raw, 0640); err != nil {
		t.Fatal(err)
	}
	h := NewHubWithDir(dir)
	if h.IsIPBanned("lanroom", "127.0.0.1") || h.IsIPBanned("lanroom", "192.168.1.224") {
		t.Fatal("loopback/LAN persist must not ban")
	}
	if !h.IsIPBanned("lanroom", "203.0.113.50") {
		t.Fatal("public persist IP should still ban")
	}
	room := h.getOrCreateRoom("lanroom")
	room.mu.Lock()
	if room.bannedIPs["127.0.0.1"] || room.bannedIPs["192.168.1.224"] {
		room.mu.Unlock()
		t.Fatal("applyPersist must drop loopback/RFC1918")
	}
	room.mu.Unlock()

	viewer := testClient(h, "lanroom", "Eve", RoleViewer)
	viewer.ip = "127.0.0.1"
	if _, err := h.Join(viewer); err != nil {
		t.Fatalf("loopback viewer join: %v", err)
	}
}

func TestGuestSeesRiverAndHistory(t *testing.T) {
	h := NewHub()
	guest := testClient(h, "r1", "_guest", RoleGuest)
	if _, err := h.Join(guest); err != nil {
		t.Fatal(err)
	}
	got := drainMsgs(guest)
	foundHint := false
	for _, m := range got {
		if m.Type == "system" && strings.Contains(m.Text, "guest") {
			foundHint = true
		}
	}
	if !foundHint {
		t.Fatalf("guest with empty river should get a line, got %+v", got)
	}

	bc := testClient(h, "r1", "Broadcaster", RoleBroadcaster)
	if _, err := h.Join(bc); err != nil {
		t.Fatal(err)
	}
	drainMsgs(guest)
	h.HandleMessage(bc, "hello from studio")
	got = drainMsgs(guest)
	foundMsg := false
	for _, m := range got {
		if m.Type == "msg" && m.Text == "hello from studio" {
			foundMsg = true
		}
	}
	if !foundMsg {
		t.Fatalf("guest should see broadcaster msg, got %+v", got)
	}

	g2 := testClient(h, "r1", "_guest", RoleGuest)
	if _, err := h.Join(g2); err != nil {
		t.Fatal(err)
	}
	hist := drainMsgs(g2)
	foundHist := false
	for _, m := range hist {
		if m.Type == "msg" && m.Text == "hello from studio" {
			foundHist = true
		}
	}
	if !foundHist {
		t.Fatalf("late guest should replay river, got %+v", hist)
	}
}
