package chat

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/gorilla/websocket"
)

const (
	RoleBroadcaster = "broadcaster"
	RoleMod         = "mod"
	RoleViewer      = "viewer"

	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 50 * time.Second
	sendBufLen = 64
	maxMsgSize = 1024
)

var (
	errBanned    = errors.New("banned from chat")
	errNickTaken = errors.New("nickname already in use")
)

type Client struct {
	hub     *Hub
	conn    *websocket.Conn
	room    *Room
	roomID  string
	nick    string
	role    string
	ip      string
	send    chan []byte
	lastMsg int64
	done    chan struct{}
}

type InboundMsg struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type OutboundMsg struct {
	Type string `json:"type"`
	Nick string `json:"nick,omitempty"`
	Text string `json:"text,omitempty"`
	Role string `json:"role,omitempty"`
	Ts   int64  `json:"ts,omitempty"`
}

func newClient(hub *Hub, conn *websocket.Conn, roomID, nick, role, ip string) *Client {
	return &Client{
		hub:    hub,
		conn:   conn,
		roomID: roomID,
		nick:   nick,
		role:   role,
		ip:     ip,
		send:   make(chan []byte, sendBufLen),
		done:   make(chan struct{}),
	}
}

func (c *Client) Close() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.Leave(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMsgSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(
				err,
				websocket.CloseGoingAway,
				websocket.CloseNormalClosure,
			) {
				log.Printf("[chat] read error [%s/%s]: %v", c.roomID, c.nick, err)
			}
			return
		}

		var msg InboundMsg
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}

		switch msg.Type {
		case "msg":
			if msg.Text == "" {
				continue
			}
			if len(msg.Text) > 0 && msg.Text[0] == '/' {
				cmd, ok := ParseCommand(msg.Text)
				if ok {
					c.hub.HandleCommand(c, cmd)
					continue
				}
			}
			c.hub.HandleMessage(c, msg.Text)

		case "cmd":
			if msg.Text == "" {
				continue
			}
			cmd, ok := ParseCommand(msg.Text)
			if ok {
				c.hub.HandleCommand(c, cmd)
			}

		default:
			continue
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-c.done:
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}
	}
}
