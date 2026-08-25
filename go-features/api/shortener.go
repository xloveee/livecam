package main

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	shortCodeBytes = 10
	maxShortPerRoom = 32
)

type shortRecord struct {
	Code      string `json:"code"`
	Room      string `json:"room"`
	Path      string `json:"path"`
	CreatedAt int64  `json:"created_at"`
}

type shortStoreFile struct {
	Codes map[string]shortRecord `json:"codes"`
}

type shortStore struct {
	mu   sync.Mutex
	path string
	data shortStoreFile
}

var shorts *shortStore

func initShortener() {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		if db := os.Getenv("DONATION_DB_PATH"); db != "" {
			dir = filepath.Dir(db)
		}
	}
	if dir == "" {
		dir = filepath.Join(clientDir, "..", "data")
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("WARNING: shortener data dir not usable (%s): %v", dir, err)
		shorts = &shortStore{path: "", data: shortStoreFile{Codes: map[string]shortRecord{}}}
		return
	}
	path := filepath.Join(dir, "short_urls.json")
	s := &shortStore{path: path, data: shortStoreFile{Codes: map[string]shortRecord{}}}
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.data); err != nil {
			log.Printf("WARNING: shortener store corrupt, starting empty: %v", err)
			s.data.Codes = map[string]shortRecord{}
		}
	}
	if s.data.Codes == nil {
		s.data.Codes = map[string]shortRecord{}
	}
	shorts = s
	log.Printf("Invite shortener: %s (%d codes)", path, len(s.data.Codes))
}

func (s *shortStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func randomShortCode() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, len(buf))
	for i := range buf {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(out), nil
}

func inviteWatchPath(room, invite string) string {
	p := "/watch/" + url.PathEscape(room)
	inv := strings.TrimSpace(invite)
	if inv == "" {
		return p
	}
	q := url.Values{}
	q.Set("invite", inv)
	return p + "?" + q.Encode()
}

func parseInviteTarget(streamKey, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", false
		}
		raw = u.RequestURI()
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host != "" || u.Scheme != "" {
		return "", false
	}
	path := u.Path
	if !strings.HasPrefix(path, "/watch/") {
		return "", false
	}
	room := strings.Trim(strings.TrimPrefix(path, "/watch/"), "/")
	dec, err := url.PathUnescape(room)
	if err != nil {
		dec = room
	}
	if dec != streamKey {
		return "", false
	}
	// Keep only invite/password query keys — never a watch bypass path.
	q := u.Query()
	out := url.Values{}
	if v := strings.TrimSpace(q.Get("invite")); v != "" {
		out.Set("invite", v)
	} else if v := strings.TrimSpace(q.Get("password")); v != "" {
		out.Set("invite", v)
	}
	target := "/watch/" + url.PathEscape(streamKey)
	if encoded := out.Encode(); encoded != "" {
		target += "?" + encoded
	}
	return target, true
}

func publicOrigin(r *http.Request) string {
	// M32: only configured public base — never trust X-Forwarded-Host.
	if base := strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")); base != "" {
		return strings.TrimRight(base, "/")
	}
	if domain := strings.TrimSpace(os.Getenv("PUBLIC_DOMAIN")); domain != "" {
		proto := "https"
		if !isSecureRequest(r) && (strings.HasPrefix(domain, "127.") || domain == "localhost") {
			proto = "http"
		}
		if strings.Contains(domain, "://") {
			return strings.TrimRight(domain, "/")
		}
		return proto + "://" + domain
	}
	return ""
}

func shortAPIHandler(w http.ResponseWriter, r *http.Request) {
	if shorts == nil {
		http.Error(w, "Shortener unavailable", http.StatusServiceUnavailable)
		return
	}
	streamKey, ok := requireBroadcasterAuth(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/shorten")
	rest = strings.Trim(rest, "/")

	switch r.Method {
	case http.MethodGet:
		if rest != "" {
			http.NotFound(w, r)
			return
		}
		listShortLinks(w, r, streamKey)
	case http.MethodPost:
		if rest != "" {
			http.NotFound(w, r)
			return
		}
		createShortLink(w, r, streamKey)
	case http.MethodDelete:
		if rest == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}
		revokeShortLink(w, streamKey, rest)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func listShortLinks(w http.ResponseWriter, r *http.Request, streamKey string) {
	shorts.mu.Lock()
	defer shorts.mu.Unlock()
	origin := publicOrigin(r)
	type item struct {
		Code      string `json:"code"`
		URL       string `json:"url"`
		Target    string `json:"target"`
		CreatedAt int64  `json:"created_at"`
	}
	out := make([]item, 0)
	for _, rec := range shorts.data.Codes {
		if rec.Room != streamKey {
			continue
		}
		out = append(out, item{
			Code:      rec.Code,
			URL:       origin + "/s/" + rec.Code,
			Target:    rec.Path,
			CreatedAt: rec.CreatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func createShortLink(w http.ResponseWriter, r *http.Request, streamKey string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Target string `json:"target"`
		Invite string `json:"invite"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
	}
	target := ""
	ok := false
	if strings.TrimSpace(req.Target) != "" {
		target, ok = parseInviteTarget(streamKey, req.Target)
	} else {
		target = inviteWatchPath(streamKey, req.Invite)
		ok = true
	}
	if !ok || target == "" {
		http.Error(w, "Target must be this room's invite watch URL", http.StatusBadRequest)
		return
	}

	shorts.mu.Lock()
	defer shorts.mu.Unlock()
	n := 0
	for _, rec := range shorts.data.Codes {
		if rec.Room == streamKey {
			n++
		}
	}
	if n >= maxShortPerRoom {
		http.Error(w, "Too many short links for this room", http.StatusBadRequest)
		return
	}
	var code string
	for i := 0; i < 8; i++ {
		c, err := randomShortCode()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if _, exists := shorts.data.Codes[c]; !exists {
			code = c
			break
		}
	}
	if code == "" {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	rec := shortRecord{
		Code:      code,
		Room:      streamKey,
		Path:      target,
		CreatedAt: time.Now().Unix(),
	}
	shorts.data.Codes[code] = rec
	if err := shorts.persistLocked(); err != nil {
		delete(shorts.data.Codes, code)
		log.Printf("shortener persist: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	origin := publicOrigin(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":       rec.Code,
		"url":        origin + "/s/" + rec.Code,
		"target":     rec.Path,
		"created_at": rec.CreatedAt,
	})
}

func revokeShortLink(w http.ResponseWriter, streamKey, code string) {
	shorts.mu.Lock()
	defer shorts.mu.Unlock()
	rec, ok := shorts.data.Codes[code]
	if !ok || rec.Room != streamKey {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	delete(shorts.data.Codes, code)
	if err := shorts.persistLocked(); err != nil {
		shorts.data.Codes[code] = rec
		log.Printf("shortener persist: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func shortRedirectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if shorts == nil {
		http.NotFound(w, r)
		return
	}
	code := strings.Trim(strings.TrimPrefix(r.URL.Path, "/s/"), "/")
	if code == "" || strings.Contains(code, "/") {
		http.NotFound(w, r)
		return
	}
	shorts.mu.Lock()
	rec, ok := shorts.data.Codes[code]
	shorts.mu.Unlock()
	if !ok || rec.Path == "" {
		http.NotFound(w, r)
		return
	}
	// 302 to the long invite watch URL on this host. Not a watch path.
	http.Redirect(w, r, rec.Path, http.StatusFound)
}
