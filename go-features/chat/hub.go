package chat

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

type Room struct {
	mu          sync.Mutex
	id          string
	clients     map[*Client]bool
	nicks       map[string]*Client
	banned      map[string]bool
	mods        map[string]bool
	broadcaster *Client
	slowMode    int32
	subOnly     bool
}

type Hub struct {
	mu    sync.Mutex
	rooms map[string]*Room
}

func NewHub() *Hub {
	return &Hub{
		rooms: make(map[string]*Room),
	}
}

func (h *Hub) getOrCreateRoom(roomID string) *Room {
	h.mu.Lock()
	defer h.mu.Unlock()

	r, ok := h.rooms[roomID]
	if !ok {
		r = &Room{
			id:      roomID,
			clients: make(map[*Client]bool),
			nicks:   make(map[string]*Client),
			banned:  make(map[string]bool),
			mods:    make(map[string]bool),
		}
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

func (h *Hub) Join(c *Client) error {
	room := h.getOrCreateRoom(c.roomID)

	room.mu.Lock()
	defer room.mu.Unlock()

	if c.role == RoleGuest {
		room.clients[c] = true
		c.room = room
		return nil
	}

	if room.banned[c.nick] {
		return errBanned
	}

	if old, taken := room.nicks[c.nick]; taken {
		old.Close()
		delete(room.clients, old)
		delete(room.nicks, old.nick)
		if room.broadcaster == old {
			room.broadcaster = nil
		}
	}

	room.clients[c] = true
	room.nicks[c.nick] = c
	c.room = room

	if c.role == RoleBroadcaster {
		room.broadcaster = c
	} else if room.mods[c.nick] {
		c.role = RoleMod
	}

	broadcastToRoom(room, OutboundMsg{
		Type: "system",
		Text: c.nick + " joined the chat",
	}, nil)

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
			delete(room.nicks, c.nick)
			wasRegistered = true
		}
	}
	delete(room.clients, c)
	if room.broadcaster == c {
		room.broadcaster = nil
	}
	empty := len(room.clients) == 0
	if wasRegistered {
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

	room.mu.Lock()
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

	room.mu.Lock()
	defer room.mu.Unlock()

	switch cmd.Type {
	case CmdBan:
		room.banned[cmd.Arg1] = true
		if target, ok := room.nicks[cmd.Arg1]; ok {
			sendToClient(target, OutboundMsg{Type: "system", Text: "You have been banned."})
			target.Close()
		}
		broadcastToRoom(room, OutboundMsg{
			Type: "ban",
			Nick: cmd.Arg1,
		}, nil)

	case CmdUnban:
		delete(room.banned, cmd.Arg1)
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: cmd.Arg1 + " has been unbanned.",
		}, nil)

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
		room.mods[cmd.Arg1] = true
		if target, ok := room.nicks[cmd.Arg1]; ok {
			target.role = RoleMod
		}
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: cmd.Arg1 + " is now a moderator.",
		}, nil)

	case CmdUnmod:
		delete(room.mods, cmd.Arg1)
		if target, ok := room.nicks[cmd.Arg1]; ok {
			target.role = RoleViewer
		}
		broadcastToRoom(room, OutboundMsg{
			Type: "system",
			Text: cmd.Arg1 + " is no longer a moderator.",
		}, nil)

	default:
		sendToClient(c, OutboundMsg{Type: "system", Text: "Unknown command."})
	}
}

func broadcastToRoom(room *Room, msg OutboundMsg, exclude *Client) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
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
