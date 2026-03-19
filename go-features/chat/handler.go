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

func NewHandler(hub *Hub, auth AuthFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/chat/")
		roomID := strings.TrimSuffix(path, "/")
		if roomID == "" {
			http.Error(w, "missing room id", http.StatusBadRequest)
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

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[chat] upgrade failed: %v", err)
			return
		}

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}

		client := newClient(hub, conn, roomID, nick, role, ip)

		if err := hub.Join(client); err != nil {
			msg := err.Error()
			if err == errBanned {
				msg = "You are banned from this chat."
			}
			conn.WriteJSON(OutboundMsg{Type: "error", Text: msg})
			conn.Close()
			return
		}

		if !isGuest {
			sendToClient(client, OutboundMsg{
				Type: "system",
				Text: "Welcome to the chat, " + nick + "!",
			})
		}

		go client.writePump()
		go client.readPump()
	}
}
