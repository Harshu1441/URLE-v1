package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type WSEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

type wsClient struct {
	conn net.Conn
	mu   sync.Mutex
}

func (c *wsClient) writeText(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	n := len(data)
	var header []byte
	if n <= 125 {
		header = []byte{0x81, byte(n)}
	} else if n <= 65535 {
		header = make([]byte, 4)
		header[0] = 0x81
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(n))
	} else {
		header = make([]byte, 10)
		header[0] = 0x81
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

// WSHub manages authenticated dashboard WebSocket connections.
type WSHub struct {
	mu      sync.Mutex
	clients map[*wsClient]bool
}

func NewWSHub() *WSHub {
	return &WSHub{clients: map[*wsClient]bool{}}
}

func (h *WSHub) Broadcast(eventType string, payload any) {
	msg, err := json.Marshal(WSEvent{
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	})
	if err != nil {
		return
	}

	h.mu.Lock()
	targets := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		targets = append(targets, c)
	}
	h.mu.Unlock()

	for _, c := range targets {
		if err := c.writeText(msg); err != nil {
			h.remove(c)
		}
	}
}

func (h *WSHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket hijacking unsupported", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	client := &wsClient{conn: conn}
	h.mu.Lock()
	h.clients[client] = true
	h.mu.Unlock()

	_ = client.writeText([]byte(`{"type":"connected","payload":{"status":"ok"}}`))

	// Drain client frames (ping/close) until disconnect.
	go func(br *bufio.Reader) {
		defer h.remove(client)
		buf := make([]byte, 512)
		for {
			if _, err := br.Read(buf); err != nil {
				return
			}
		}
	}(rw.Reader)
}

func (h *WSHub) remove(c *wsClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
	_ = c.conn.Close()
}
