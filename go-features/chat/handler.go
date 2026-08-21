package chat

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	guestCounter uint64
)

type AuthFunc func(r *http.Request) (streamKey string, ok bool)

// RoomAccessFunc is the invite-password gate (same secret as WHEP/HLS).
// It must not open the room. Nil means no extra check (tests only).
type RoomAccessFunc func(r *http.Request, roomID string) bool

func NewHandler(hub *Hub, auth AuthFunc, access RoomAccessFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/chat/")
		roomID := strings.TrimSuffix(path, "/")
		if roomID == "" {
			http.Error(w, "missing room id", http.StatusBadRequest)
			return
		}
		if access != nil && !access(r, roomID) {
			http.Error(w, "Incorrect room password", http.StatusForbidden)
			return
		}

		nick := r.URL.Query().Get("nick")
		if nick == "" {
			http.Error(w, "missing nickname", http.StatusBadRequest)
			return
		}

		isGuest := nick == "_guest"
		if isGuest {
			nick = fmt.Sprintf("_g%d", atomic.AddUint64(&guestCounter, 1))
		} else {
			if !ValidateNickname(nick) {
				http.Error(w, "invalid nickname: 1-25 chars, alphanumeric and underscore only", http.StatusBadRequest)
				return
			}
		}

		role := RoleViewer
		if isGuest {
			role = RoleGuest
		} else if auth != nil {
			if streamKey, ok := auth(r); ok && streamKey == roomID {
				role = RoleBroadcaster
			}
		}

		ip := ClientIP(r)
		if role != RoleBroadcaster && hub.IsIPBanned(roomID, ip) {
			http.Error(w, "You are banned from this chat.", http.StatusForbidden)
			return
		}
		if role != RoleBroadcaster && !isGuest && hub.IsNickBanned(roomID, nick) {
			http.Error(w, "You are banned from this chat.", http.StatusForbidden)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[chat] upgrade failed: %v", err)
			return
		}

		client := newClient(hub, conn, roomID, nick, role, ip)

		replaced, err := hub.Join(client)
		if err != nil {
			msg := err.Error()
			if err == errBanned {
				msg = "You are banned from this chat."
			} else if err == errNickTaken {
				msg = "Nickname already taken."
			}
			conn.WriteJSON(OutboundMsg{Type: "error", Text: msg})
			conn.Close()
			return
		}

		// Streamer does not need a welcome on every socket. Reconnects and
		// blips (same nick within ~30s) must not stack "Welcome to the chat".
		if !isGuest && role != RoleBroadcaster && !replaced && hub.shouldWelcome(roomID, nick) {
			sendToClient(client, OutboundMsg{
				Type: "system",
				Text: "Welcome to the chat, " + nick + "!",
			})
		}

		go client.writePump()
		go client.readPump()
	}
}
