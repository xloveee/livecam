package chat

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

const joinAnnounceDebounce = 30 * time.Second
const chatHistoryCap = 50

type whepSighting struct {
	remoteIP string
	sdpIPs   []string
}

type Room struct {
	mu          sync.Mutex
	id          string
	clients     map[*Client]bool
	nicks       map[string]*Client
	banned      map[string]bool
	bannedIPs   map[string]bool
	mods        map[string]bool
	nickIPs     map[string]map[string]bool
	broadcaster *Client
	slowMode    int32
	subOnly     bool
	history     [][]byte
	flood       map[string]*FloodTracker
}

type Hub struct {
	mu            sync.Mutex
	rooms         map[string]*Room
	announceMu    sync.Mutex
	lastJoinAt    map[string]time.Time
	lastWelcomeAt map[string]time.Time
	dataDir       string
	persistMu     sync.Mutex
	persist       map[string]*roomModState
	whepMu        sync.Mutex
	whep          map[string]map[string]whepSighting
	dropWHEP      func(roomID, sessionID string)
}

func NewHub() *Hub {
	return NewHubWithDir("")
}

func NewHubWithDir(dir string) *Hub {
	h := &Hub{
		rooms:         make(map[string]*Room),
		lastJoinAt:    make(map[string]time.Time),
		lastWelcomeAt: make(map[string]time.Time),
		dataDir:       dir,
		persist:       make(map[string]*roomModState),
		whep:          make(map[string]map[string]whepSighting),
	}
	h.loadAllPersist()
	return h
}

func (h *Hub) SetWHEPDropper(fn func(roomID, sessionID string)) {
	h.mu.Lock()
	h.dropWHEP = fn
	h.mu.Unlock()
}

func (h *Hub) fireWHEPDrops(roomID string, sessions []string) {
	if len(sessions) == 0 {
		return
	}
	h.mu.Lock()
	fn := h.dropWHEP
	h.mu.Unlock()
	if fn == nil {
		return
	}
	for _, sid := range sessions {
		fn(roomID, sid)
	}
}

// NoteWHEP records IPs from a WHEP request this room already accepted.
func (h *Hub) NoteWHEP(roomID, sessionID, remoteIP string, sdpIPs []string) {
	if roomID == "" || sessionID == "" {
		return
	}
	remoteIP = NormalizeIP(remoteIP)
	clean := make([]string, 0, len(sdpIPs))
	seen := map[string]bool{}
	for _, ip := range sdpIPs {
		ip = NormalizeIP(ip)
		if !IsBannableIP(ip) || seen[ip] {
			continue
		}
		seen[ip] = true
		clean = append(clean, ip)
	}
	h.whepMu.Lock()
	if h.whep[roomID] == nil {
		h.whep[roomID] = map[string]whepSighting{}
	}
	h.whep[roomID][sessionID] = whepSighting{remoteIP: remoteIP, sdpIPs: clean}
	h.whepMu.Unlock()
}

// ForgetWHEP drops a viewer session we no longer have.
func (h *Hub) ForgetWHEP(roomID, sessionID string) {
	h.whepMu.Lock()
	if m := h.whep[roomID]; m != nil {
		delete(m, sessionID)
		if len(m) == 0 {
			delete(h.whep, roomID)
		}
	}
	h.whepMu.Unlock()
}

func (h *Hub) copyWHEP(roomID string) map[string]whepSighting {
	h.whepMu.Lock()
	defer h.whepMu.Unlock()
	src := h.whep[roomID]
	out := make(map[string]whepSighting, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (room *Room) noteNickIP(nick, ip string) {
	ip = NormalizeIP(ip)
	if nick == "" || ip == "" {
		return
	}
	if room.nickIPs[nick] == nil {
		room.nickIPs[nick] = map[string]bool{}
	}
	room.nickIPs[nick][ip] = true
}

func (room *Room) floodTracker(nick string) *FloodTracker {
	if room.flood == nil {
		room.flood = make(map[string]*FloodTracker)
	}
	if nick == "" {
		nick = "?"
	}
	st := room.flood[nick]
	if st == nil {
		st = &FloodTracker{}
		room.flood[nick] = st
	}
	return st
}

func floodExempt(role string) bool {
	return role == RoleBroadcaster || role == RoleMod
}

func joinAnnounceKey(roomID, nick string) string {
	return roomID + "\x00" + nick
}

func (h *Hub) getOrCreateRoom(roomID string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[roomID]
	if !ok {
		r = &Room{
			id:        roomID,
			clients:   make(map[*Client]bool),
			nicks:     make(map[string]*Client),
			banned:    make(map[string]bool),
			bannedIPs: make(map[string]bool),
			mods:      make(map[string]bool),
			nickIPs:   make(map[string]map[string]bool),
			flood:     make(map[string]*FloodTracker),
		}
		h.applyPersist(r)
		h.rooms[roomID] = r
		log.Printf("[chat] room created: %s", roomID)
	}
	return r
}

func (h *Hub) removeRoomIfEmpty(roomID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[roomID]
	if !ok {
		return
	}
	r.mu.Lock()
	empty := len(r.clients) == 0
	r.mu.Unlock()

	if empty {
		delete(h.rooms, roomID)
		log.Printf("[chat] room destroyed: %s", roomID)
	}
}

func (h *Hub) debounceOK(store map[string]time.Time, roomID, nick string) bool {
	now := time.Now()
	for k, t := range store {
		if now.Sub(t) >= joinAnnounceDebounce {
			delete(store, k)
		}
	}
	key := joinAnnounceKey(roomID, nick)
	if last, ok := store[key]; ok && now.Sub(last) < joinAnnounceDebounce {
		return false
	}
	store[key] = now
	return true
}

func (h *Hub) shouldAnnounceJoin(roomID, nick string) bool {
	h.announceMu.Lock()
	defer h.announceMu.Unlock()
	return h.debounceOK(h.lastJoinAt, roomID, nick)
}

func (h *Hub) shouldWelcome(roomID, nick string) bool {
	h.announceMu.Lock()
	defer h.announceMu.Unlock()
	return h.debounceOK(h.lastWelcomeAt, roomID, nick)
}

func (h *Hub) Join(c *Client) (replaced bool, err error) {
	room := h.getOrCreateRoom(c.roomID)

	room.mu.Lock()
	defer room.mu.Unlock()

	c.ip = NormalizeIP(c.ip)
	if c.role != RoleBroadcaster && IsBannableIP(c.ip) && room.bannedIPs[c.ip] {
		return false, errBanned
	}

	if c.role == RoleGuest {
		room.clients[c] = true
		c.room = room
		replayChatHistoryLocked(room, c)
		if len(room.history) == 0 {
			sendToClient(c, OutboundMsg{
				Type: "system",
				Text: "You're watching as a guest. Pick a nickname to chat.",
			})
		}
		return false, nil
	}

	if c.role != RoleBroadcaster && room.banned[c.nick] {
		return false, errBanned
	}

	if old, taken := room.nicks[c.nick]; taken {
		if old.role == RoleBroadcaster && c.role != RoleBroadcaster {
			return false, errNickTaken
		}
		if old.role == RoleBroadcaster && c.role == RoleBroadcaster && onlyBroadcasterLocked(room, old) {
			// Keep the live streamer socket. Extra Broadcaster tabs share
			// the room without close+replace (that loop is the Connected flicker).
			room.clients[c] = true
			c.room = room
			room.noteNickIP(c.nick, c.ip)
			if room.broadcaster == nil {
				room.broadcaster = old
			}
			sendModerationLocked(room)
			return false, nil
		}
		old.Close()
		delete(room.clients, old)
		delete(room.nicks, old.nick)
		if room.broadcaster == old {
			room.broadcaster = nil
		}
		replaced = true
	}

	room.clients[c] = true
	room.nicks[c.nick] = c
	c.room = room
	room.noteNickIP(c.nick, c.ip)
	replayChatHistoryLocked(room, c)

	if c.role == RoleBroadcaster {
		room.broadcaster = c
	} else if room.mods[c.nick] {
		c.role = RoleMod
	}
	if c.role == RoleBroadcaster || c.role == RoleMod {
		sendModerationLocked(room)
	}

	// Streamer presence is implied by the stream; reconnects replace the socket.
	if c.role == RoleBroadcaster || replaced {
		return replaced, nil
	}

	if len(room.clients) <= 20 && h.shouldAnnounceJoin(c.roomID, c.nick) {
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: c.nick + " joined the chat",
		}, nil)
	}

	return false, nil
}

func onlyBroadcasterLocked(room *Room, incumbent *Client) bool {
	if incumbent == nil || incumbent.role != RoleBroadcaster {
		return false
	}
	for cl := range room.clients {
		if cl != incumbent && cl.role == RoleBroadcaster {
			return false
		}
	}
	return true
}

func promoteNickLocked(room *Room, nick string, except *Client) *Client {
	for cl := range room.clients {
		if cl != except && cl.nick == nick {
			return cl
		}
	}
	return nil
}

func promoteBroadcasterLocked(room *Room, except *Client) *Client {
	for cl := range room.clients {
		if cl != except && cl.role == RoleBroadcaster {
			return cl
		}
	}
	return nil
}

func (h *Hub) Leave(c *Client) {
	room := c.room
	if room == nil {
		return
	}

	room.mu.Lock()
	wasRegistered := false
	if c.role != RoleGuest {
		if current, ok := room.nicks[c.nick]; ok && current == c {
			if other := promoteNickLocked(room, c.nick, c); other != nil {
				room.nicks[c.nick] = other
			} else {
				delete(room.nicks, c.nick)
				wasRegistered = true
			}
		}
	}
	delete(room.clients, c)
	if room.broadcaster == c {
		room.broadcaster = promoteBroadcasterLocked(room, c)
	}
	empty := len(room.clients) == 0
	// Replaced sockets already dropped from nicks, so Leave is silent.
	// Broadcaster leave is never announced.
	if wasRegistered && c.role != RoleBroadcaster && len(room.clients) <= 20 {
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: c.nick + " left the chat",
		}, nil)
	}
	room.mu.Unlock()

	c.Close()

	if empty {
		h.removeRoomIfEmpty(c.roomID)
	}
}

func (h *Hub) HandleMessage(c *Client, text string) {
	room := c.room
	if room == nil {
		return
	}

	sanitized, ok := SanitizeMessage(text)
	if !ok {
		return
	}

	now := time.Now().Unix()
	var dropSessions []string
	var persist *roomModState

	room.mu.Lock()
	room.pruneFloodLocked(now)
	if !floodExempt(c.role) {
		action, left := CheckChatFlood(room.floodTracker(c.nick), now)
		switch action {
		case FloodMuted, FloodStrike:
			room.mu.Unlock()
			sendToClient(c, OutboundMsg{
				Type: "system",
				Text: floodMuteNotice(left),
			})
			return
		case FloodBan:
			dropSessions, persist = h.applyFloodIPBanLocked(room, c)
			ip := NormalizeIP(c.ip)
			closed := IsBannableIP(ip) && room.bannedIPs[ip]
			room.mu.Unlock()
			if persist != nil {
				h.writePersistFile(room.id, persist)
			}
			if !closed {
				sendToClient(c, OutboundMsg{
					Type: "system",
					Text: "You have been banned.",
				})
			}
			h.fireWHEPDrops(c.roomID, dropSessions)
			return
		}
	}

	if !CheckRateLimit(c.lastMsg, now, int(room.slowMode)) {
		room.mu.Unlock()
		sendToClient(c, OutboundMsg{
			Type: "system",
			Text: "Slow mode is active. Wait before sending another message.",
		})
		return
	}

	c.lastMsg = now
	broadcastToRoom(room, OutboundMsg{
		Type: "msg",
		Nick: c.nick,
		Text: sanitized,
		Role: c.role,
		Ts:   now,
	}, nil)
	room.mu.Unlock()
}

func (h *Hub) applyFloodIPBanLocked(room *Room, c *Client) ([]string, *roomModState) {
	ips := collectBanIPs(room, c.nick, h.copyWHEP(room.id))
	if ip := NormalizeIP(c.ip); IsBannableIP(ip) {
		ips[ip] = true
	}
	for ip := range ips {
		if !IsBannableIP(ip) {
			delete(ips, ip)
			continue
		}
		room.bannedIPs[ip] = true
	}
	if len(ips) == 0 {
		return nil, nil
	}
	closeMatchingClients(room, nil, ips)
	dropSessions := h.takeMatchingWHEP(room.id, ips, room.nickIPs[c.nick])
	st := h.stageModerationLocked(room)
	broadcastToRoom(room, OutboundMsg{
		Type: "system",
		Text: "IP ban: " + joinComma(setToSorted(ips)),
	}, nil)
	return dropSessions, st
}

func (h *Hub) HandleCommand(c *Client, cmd ChatCommand) {
	room := c.room
	if room == nil {
		return
	}

	if c.role != RoleBroadcaster && c.role != RoleMod {
		sendToClient(c, OutboundMsg{
			Type: "system",
			Text: "You don't have permission to use commands.",
		})
		return
	}

	if (cmd.Type == CmdMod || cmd.Type == CmdUnmod) && c.role != RoleBroadcaster {
		sendToClient(c, OutboundMsg{
			Type: "system",
			Text: "Only the broadcaster can grant or remove moderators.",
		})
		return
	}

	var dropSessions []string
	var persist *roomModState

	room.mu.Lock()
	switch cmd.Type {
	case CmdBan:
		nick := cmd.Arg1
		if nick == "" {
			room.mu.Unlock()
			return
		}
		if target, ok := room.nicks[nick]; ok && target.role == RoleBroadcaster {
			room.mu.Unlock()
			sendToClient(c, OutboundMsg{Type: "system", Text: "You cannot ban the broadcaster."})
			return
		}
		room.banned[nick] = true
		ips := collectBanIPs(room, nick, h.copyWHEP(room.id))
		for ip := range ips {
			room.bannedIPs[ip] = true
		}
		closeMatchingClients(room, map[string]bool{nick: true}, ips)
		dropSessions = h.takeMatchingWHEP(room.id, ips, room.nickIPs[nick])
		persist = h.stageModerationLocked(room)
		broadcastToRoom(room, OutboundMsg{Type: "ban", Nick: nick}, nil)
		if len(ips) > 0 {
			broadcastToRoom(room, OutboundMsg{
				Type: "system",
				Text: "IP ban: " + joinComma(setToSorted(ips)),
			}, nil)
		}

	case CmdIPBan:
		ip := NormalizeIP(cmd.Arg1)
		if !IsBannableIP(ip) {
			room.mu.Unlock()
			sendToClient(c, OutboundMsg{
				Type: "system",
				Text: "Not a public IP (loopback, LAN, and link-local are not banned).",
			})
			return
		}
		room.bannedIPs[ip] = true
		closeMatchingClients(room, nil, map[string]bool{ip: true})
		dropSessions = h.takeMatchingWHEP(room.id, map[string]bool{ip: true}, nil)
		persist = h.stageModerationLocked(room)
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: "IP ban: " + ip,
		}, nil)

	case CmdUnban:
		arg := cmd.Arg1
		if ip := NormalizeIP(arg); ip != "" {
			delete(room.bannedIPs, ip)
			persist = h.stageModerationLocked(room)
			broadcastToRoom(room, OutboundMsg{
				Type: "system",
				Text: ip + " has been unbanned.",
			}, nil)
		} else {
			delete(room.banned, arg)
			persist = h.stageModerationLocked(room)
			broadcastToRoom(room, OutboundMsg{
				Type: "system",
				Text: arg + " has been unbanned.",
			}, nil)
		}

	case CmdTimeout:
		if target, ok := room.nicks[cmd.Arg1]; ok {
			sendToClient(target, OutboundMsg{
				Type: "system",
				Text: "You have been timed out.",
			})
			target.Close()
		}
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: cmd.Arg1 + " has been timed out.",
		}, nil)

	case CmdSlow:
		room.slowMode = int32(cmd.Arg2)
		text := "Slow mode disabled."
		if cmd.Arg2 > 0 {
			text = "Slow mode enabled: " + itoa(cmd.Arg2) + " seconds."
		}
		broadcastToRoom(room, OutboundMsg{Type: "system", Text: text}, nil)

	case CmdSubscribers:
		room.subOnly = !room.subOnly
		text := "Subscriber-only mode disabled."
		if room.subOnly {
			text = "Subscriber-only mode enabled."
		}
		broadcastToRoom(room, OutboundMsg{Type: "system", Text: text}, nil)

	case CmdClear:
		broadcastToRoom(room, OutboundMsg{Type: "clear"}, nil)

	case CmdMod:
		nick := cmd.Arg1
		if target, ok := room.nicks[nick]; ok && target.role == RoleBroadcaster {
			room.mu.Unlock()
			sendToClient(c, OutboundMsg{Type: "system", Text: "The broadcaster is already in charge."})
			return
		}
		room.mods[nick] = true
		if target, ok := room.nicks[nick]; ok {
			target.role = RoleMod
		}
		persist = h.stageModerationLocked(room)
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: nick + " is now a moderator.",
		}, nil)

	case CmdUnmod:
		nick := cmd.Arg1
		delete(room.mods, nick)
		if target, ok := room.nicks[nick]; ok && target.role != RoleBroadcaster {
			target.role = RoleViewer
		}
		persist = h.stageModerationLocked(room)
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: nick + " is no longer a moderator.",
		}, nil)

	default:
		sendToClient(c, OutboundMsg{Type: "system", Text: "Unknown command."})
	}
	room.mu.Unlock()
	if persist != nil {
		h.writePersistFile(room.id, persist)
	}
	h.fireWHEPDrops(c.roomID, dropSessions)
}

func collectBanIPs(room *Room, nick string, whep map[string]whepSighting) map[string]bool {
	out := map[string]bool{}
	observed := map[string]bool{}
	if m := room.nickIPs[nick]; m != nil {
		for ip := range m {
			observed[ip] = true
		}
	}
	if target, ok := room.nicks[nick]; ok {
		if ip := NormalizeIP(target.ip); ip != "" {
			observed[ip] = true
		}
	}
	for ip := range observed {
		if IsBannableIP(ip) {
			out[ip] = true
		}
	}
	for _, sess := range whep {
		related := observed[sess.remoteIP]
		if !related {
			for _, p := range sess.sdpIPs {
				if observed[p] {
					related = true
					break
				}
			}
		}
		if !related {
			continue
		}
		if IsBannableIP(sess.remoteIP) {
			out[sess.remoteIP] = true
		}
		for _, p := range sess.sdpIPs {
			if IsBannableIP(p) {
				out[p] = true
			}
		}
	}
	return out
}

func closeMatchingClients(room *Room, nicks, ips map[string]bool) {
	for client := range room.clients {
		if client.role == RoleBroadcaster {
			continue
		}
		if (nicks != nil && nicks[client.nick]) || (ips != nil && ips[NormalizeIP(client.ip)]) {
			sendToClient(client, OutboundMsg{Type: "system", Text: "You have been banned."})
			client.Close()
		}
	}
}

func (h *Hub) takeMatchingWHEP(roomID string, ips, nickIPs map[string]bool) []string {
	h.whepMu.Lock()
	defer h.whepMu.Unlock()
	sessions := h.whep[roomID]
	if sessions == nil {
		return nil
	}
	var dropped []string
	for sid, sess := range sessions {
		match := (ips != nil && ips[sess.remoteIP]) || (nickIPs != nil && nickIPs[sess.remoteIP])
		if !match {
			for _, p := range sess.sdpIPs {
				if (ips != nil && ips[p]) || (nickIPs != nil && nickIPs[p]) {
					match = true
					break
				}
			}
		}
		if match {
			dropped = append(dropped, sid)
			delete(sessions, sid)
		}
	}
	if len(sessions) == 0 {
		delete(h.whep, roomID)
	}
	return dropped
}

func sendModerationLocked(room *Room) {
	msg := OutboundMsg{
		Type:        "moderation",
		BannedNicks: setToSorted(room.banned),
		BannedIPs:   setToSorted(room.bannedIPs),
		Mods:        setToSorted(room.mods),
	}
	for client := range room.clients {
		if client.role == RoleBroadcaster || client.role == RoleMod {
			sendToClient(client, msg)
		}
	}
}

func joinComma(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += ", " + parts[i]
	}
	return out
}

func rememberChatLocked(room *Room, data []byte, msg OutboundMsg) {
	if msg.Type != "msg" && msg.Type != "system" && msg.Type != "donation" {
		return
	}
	room.history = append(room.history, data)
	if extra := len(room.history) - chatHistoryCap; extra > 0 {
		copy(room.history, room.history[extra:])
		for i := chatHistoryCap; i < len(room.history); i++ {
			room.history[i] = nil
		}
		room.history = room.history[:chatHistoryCap]
	}
}

func (room *Room) pruneFloodLocked(now int64) {
	if len(room.flood) == 0 {
		return
	}
	decay := int64(FloodDecaySec)
	for nick, st := range room.flood {
		if st == nil {
			delete(room.flood, nick)
			continue
		}
		if st.MuteUntil > now || st.Strikes > 0 || st.Count > 0 {
			continue
		}
		if st.LastSeen > 0 && now-st.LastSeen >= decay {
			delete(room.flood, nick)
		}
	}
}

func replayChatHistoryLocked(room *Room, c *Client) {
	for _, data := range room.history {
		select {
		case c.send <- data:
		default:
		}
	}
}

func broadcastToRoom(room *Room, msg OutboundMsg, exclude *Client) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	rememberChatLocked(room, data, msg)
	for client := range room.clients {
		if client == exclude {
			continue
		}
		select {
		case client.send <- data:
		default:
		}
	}
}

func sendToClient(c *Client, msg OutboundMsg) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case c.send <- data:
	default:
	}
}

func (h *Hub) RoomIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.rooms))
	for id := range h.rooms {
		ids = append(ids, id)
	}
	return ids
}

func (h *Hub) BroadcastRoomState(roomID string, msg OutboundMsg) {
	h.mu.Lock()
	room, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return
	}
	room.mu.Lock()
	broadcastToRoom(room, msg, nil)
	room.mu.Unlock()
}

func (h *Hub) BroadcastDonation(roomID string, msg OutboundMsg) {
	h.mu.Lock()
	room, ok := h.rooms[roomID]
	h.mu.Unlock()
	if !ok {
		return
	}

	room.mu.Lock()
	broadcastToRoom(room, msg, nil)
	room.mu.Unlock()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
