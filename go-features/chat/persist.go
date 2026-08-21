package chat

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type roomModState struct {
	BannedNicks map[string]bool
	BannedIPs   map[string]bool
	Mods        map[string]bool
}

type roomModFile struct {
	BannedNicks []string `json:"banned_nicks"`
	BannedIPs   []string `json:"banned_ips"`
	Mods        []string `json:"mods"`
}

func safeRoomFile(roomID string) bool {
	if roomID == "" || len(roomID) > 80 {
		return false
	}
	for _, r := range roomID {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (h *Hub) persistDir() string {
	if h.dataDir == "" {
		return ""
	}
	return filepath.Join(h.dataDir, "chat_moderation")
}

func (h *Hub) persistPath(roomID string) string {
	dir := h.persistDir()
	if dir == "" || !safeRoomFile(roomID) {
		return ""
	}
	return filepath.Join(dir, roomID+".json")
}

func (h *Hub) loadAllPersist() {
	dir := h.persistDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("[chat] moderation dir %s: %v", dir, err)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("[chat] read moderation dir: %v", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		roomID := strings.TrimSuffix(e.Name(), ".json")
		if !safeRoomFile(roomID) {
			continue
		}
		st, err := readModFile(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("[chat] load %s: %v", e.Name(), err)
			continue
		}
		h.persist[roomID] = st
	}
	if len(h.persist) > 0 {
		log.Printf("[chat] loaded moderation for %d rooms from %s", len(h.persist), dir)
	}
}

func readModFile(path string) (*roomModState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f roomModFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &roomModState{
		BannedNicks: sliceToSet(f.BannedNicks),
		BannedIPs:   sliceToSet(f.BannedIPs),
		Mods:        sliceToSet(f.Mods),
	}, nil
}

func sliceToSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out[s] = true
		}
	}
	return out
}

func setToSorted(m map[string]bool) []string {
	if len(m) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(m))
	for k, ok := range m {
		if ok && k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func copyBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		if v {
			out[k] = true
		}
	}
	return out
}

func (h *Hub) applyPersist(room *Room) {
	h.persistMu.Lock()
	st := h.persist[room.id]
	h.persistMu.Unlock()
	if st == nil {
		return
	}
	for k := range st.BannedNicks {
		room.banned[k] = true
	}
	for k := range st.BannedIPs {
		if IsBannableIP(k) {
			room.bannedIPs[k] = true
		}
	}
	for k := range st.Mods {
		room.mods[k] = true
	}
}

func (h *Hub) commitModeration(room *Room) {
	for ip := range room.bannedIPs {
		if !IsBannableIP(ip) {
			delete(room.bannedIPs, ip)
		}
	}
	st := &roomModState{
		BannedNicks: copyBoolMap(room.banned),
		BannedIPs:   copyBoolMap(room.bannedIPs),
		Mods:        copyBoolMap(room.mods),
	}
	h.persistMu.Lock()
	h.persist[room.id] = st
	h.persistMu.Unlock()
	h.writePersistFile(room.id, st)
	sendModerationLocked(room)
}

func (h *Hub) writePersistFile(roomID string, st *roomModState) {
	path := h.persistPath(roomID)
	if path == "" || st == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		log.Printf("[chat] persist mkdir: %v", err)
		return
	}
	f := roomModFile{
		BannedNicks: setToSorted(st.BannedNicks),
		BannedIPs:   setToSorted(st.BannedIPs),
		Mods:        setToSorted(st.Mods),
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0640); err != nil {
		log.Printf("[chat] persist write %s: %v", roomID, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[chat] persist rename %s: %v", roomID, err)
	}
}

// IsIPBanned reports whether this public IP is on the room's persisted ban list.
func (h *Hub) IsIPBanned(roomID, ip string) bool {
	ip = NormalizeIP(ip)
	if ip == "" || !IsBannableIP(ip) {
		return false
	}
	h.persistMu.Lock()
	st := h.persist[roomID]
	h.persistMu.Unlock()
	return st != nil && st.BannedIPs[ip]
}

// IsNickBanned reports whether this nick is on the room's persisted ban list.
func (h *Hub) IsNickBanned(roomID, nick string) bool {
	if nick == "" {
		return false
	}
	h.persistMu.Lock()
	st := h.persist[roomID]
	h.persistMu.Unlock()
	return st != nil && st.BannedNicks[nick]
}

// IsWHEPBanned is true if the TCP/XFF IP or any public host/srflx in the
// offer SDP is already on this room's ban list.
func (h *Hub) IsWHEPBanned(roomID, clientIP, sdp string) bool {
	if h.IsIPBanned(roomID, clientIP) {
		return true
	}
	for _, ip := range ParsePublicICECandidates(sdp) {
		if h.IsIPBanned(roomID, ip) {
			return true
		}
	}
	return false
}
