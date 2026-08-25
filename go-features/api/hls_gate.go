package main

/*
#cgo CFLAGS: -I${SRCDIR}/c_src
#include <stdlib.h>
#include "c_src/core_logic.h"
*/
import "C"

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"livecam/chat"
	"livecam/donations"
)

const (
	hlsSessionTTL      = 45 * time.Second
	inviteCookieName   = "lc_invite"
	hlsSessionCookie   = "lc_hls"
	inviteCookieMaxAge = 12 * 3600
)

var inviteMACKey []byte

func init() {
	// L3: never fall back to a fixed MAC key — refuse invites if RNG fails.
	inviteMACKey = make([]byte, 32)
	if _, err := rand.Read(inviteMACKey); err != nil {
		inviteMACKey = nil
	}
}

func isHlsPlaylist(file string) bool {
	return strings.HasSuffix(file, ".m3u8")
}

// playlistReady is true only when the playlist exists, has bytes, and lists a segment.
func playlistReady(hlsDir, room, name string) bool {
	if hlsDir == "" || room == "" || name == "" {
		return false
	}
	if room == "." || room == ".." || strings.ContainsAny(room, `/\`) {
		return false
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return false
	}
	b, err := os.ReadFile(filepath.Join(hlsDir, room, name))
	if err != nil || len(b) == 0 {
		return false
	}
	return bytes.Contains(b, []byte("#EXTINF"))
}

// clampDistributionToPlaylists hides Compatible/Preview unless the remuxed
// playlist is actually on disk. Streamer checkboxes are intent, not proof.
func clampDistributionToPlaylists(d donations.DistributionConfig, hlsDir, roomID string) donations.DistributionConfig {
	if !playlistReady(hlsDir, roomID, "master.m3u8") {
		d.HLS = false
	}
	if !playlistReady(hlsDir, roomID, "pip.m3u8") {
		d.PiP = false
	}
	if d.Default == "hls" && !d.HLS {
		d.Default = "live"
	}
	if d.Default == "pip" && !d.PiP {
		if d.HLS {
			d.Default = "hls"
		} else {
			d.Default = "live"
		}
	}
	if !d.Live && !d.HLS && !d.PiP {
		d.Live = true
		d.Default = "live"
	}
	return d
}

// passwordFromHeaderOrQuery returns the room invite from X-Room-Password only (L8).
// Query invite/password are ignored so secrets stay out of URLs and access logs.
func passwordFromHeaderOrQuery(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-Room-Password"))
}

func checkRoomPassword(submitted, stored string) bool {
	cSubmitted := C.CString(submitted)
	cStored := C.CString(stored)
	defer C.free(unsafe.Pointer(cSubmitted))
	defer C.free(unsafe.Pointer(cStored))
	return C.check_room_password(cSubmitted, cStored) == 1
}

// H26/M40: grant is a MAC over room+epoch+exp — never needs plaintext from room_info.
func signInviteGrant(room string, epoch uint64, exp int64) string {
	if len(inviteMACKey) != 32 {
		return ""
	}
	mac := hmac.New(sha256.New, inviteMACKey)
	fmt.Fprintf(mac, "%s|%d|%d|grant", room, epoch, exp)
	return fmt.Sprintf("%d.%s", exp, hex.EncodeToString(mac.Sum(nil)))
}

func mintInviteCookie(room string, epoch uint64) string {
	return signInviteGrant(room, epoch, time.Now().Add(time.Duration(inviteCookieMaxAge)*time.Second).Unix())
}

func validInviteCookieValue(raw, room string, epoch uint64) bool {
	if raw == "" || room == "" {
		return false
	}
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || exp < time.Now().Unix() {
		return false
	}
	expect := signInviteGrant(room, epoch, exp)
	return hmac.Equal([]byte(expect), []byte(raw))
}

func roomPasswordOK(info roomInfoResult, r *http.Request, room string) bool {
	if !info.Fetched {
		return false
	}
	if !info.HasPassword {
		return true
	}
	submitted := passwordFromHeaderOrQuery(r)
	if rustCheckRoomPassword(room, submitted) {
		return true
	}
	if r == nil {
		return false
	}
	c, err := r.Cookie(inviteCookieName)
	if err != nil {
		return false
	}
	// H26/M40: cookie is a grant bound to rust grant_epoch.
	return validInviteCookieValue(c.Value, room, info.GrantEpoch)
}

type hlsSession struct {
	last time.Time
}

type hlsTracker struct {
	mu    sync.Mutex
	rooms map[string]map[string]hlsSession
}

func newHlsTracker() *hlsTracker {
	return &hlsTracker{rooms: map[string]map[string]hlsSession{}}
}

var hlsViewers = newHlsTracker()

func (t *hlsTracker) sweepLocked(now time.Time) {
	cutoff := now.Add(-hlsSessionTTL)
	for room, m := range t.rooms {
		for id, s := range m {
			if s.last.Before(cutoff) {
				delete(m, id)
			}
		}
		if len(m) == 0 {
			delete(t.rooms, room)
		}
	}
}

func (t *hlsTracker) count(room string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(time.Now())
	return len(t.rooms[room])
}

func (t *hlsTracker) has(room, id string) bool {
	if id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(time.Now())
	_, ok := t.rooms[room][id]
	return ok
}

func (t *hlsTracker) touch(room, id string) {
	if room == "" || id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rooms[room] == nil {
		t.rooms[room] = map[string]hlsSession{}
	}
	t.rooms[room][id] = hlsSession{last: time.Now()}
}

func newHlsSessionID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func mediaViewerTotal(info roomInfoResult, room string) int32 {
	return info.ViewerCount + int32(hlsViewers.count(room))
}

func viewerCapAllows(info roomInfoResult, current int32) bool {
	return C.check_viewer_cap(C.int32_t(current), C.int32_t(info.MaxViewers)) == 1
}

func setHlsAuthCookies(w http.ResponseWriter, r *http.Request, room string, epoch uint64, sessionID string, mintGrant bool) {
	path := "/hls/" + room + "/"
	secure := isSecureRequest(r)
	if mintGrant {
		http.SetCookie(w, &http.Cookie{
			Name:     inviteCookieName,
			Value:    mintInviteCookie(room, epoch),
			Path:     path,
			MaxAge:   inviteCookieMaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
		})
	}
	if sessionID != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     hlsSessionCookie,
			Value:    sessionID,
			Path:     path,
			MaxAge:   int(hlsSessionTTL.Seconds()) * 4,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
		})
	}
}

func hlsGateHandler(hlsDir string, hub *chat.Hub) http.Handler {
	fs := setCORSAndCache(http.StripPrefix("/hls/", http.FileServer(http.Dir(hlsDir))))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		room, file, ok := parseHlsRoom(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		viewerIP := chat.ClientIP(r)
		if hub != nil && hub.IsIPBanned(room, viewerIP) {
			log.Printf("HLS room '%s' IP banned for %s", room, viewerIP)
			http.Error(w, "You are banned from this room.", http.StatusForbidden)
			return
		}
		info := fetchRoomInfo(room)
		// M2/M20: live + distribution (Compatible/Preview).
		if !info.Fetched || !info.IsLive {
			http.Error(w, "Room is not live", http.StatusNotFound)
			return
		}
		if !hlsDistributionAllows(room, file) {
			http.Error(w, "HLS distribution disabled", http.StatusNotFound)
			return
		}
		if !roomPasswordOK(info, r, room) {
			log.Printf("HLS room '%s' password rejected for %s", room, r.RemoteAddr)
			http.Error(w, "Incorrect room password", http.StatusForbidden)
			return
		}

		sessionID := ""
		if c, err := r.Cookie(hlsSessionCookie); err == nil {
			sessionID = c.Value
		}
		known := hlsViewers.has(room, sessionID)

		if isHlsPlaylist(file) {
			if !known {
				// New Compatible/Preview viewer: same cap as WHEP.
				if !viewerCapAllows(info, mediaViewerTotal(info, room)) {
					log.Printf("HLS room '%s' at capacity, rejecting %s", room, r.RemoteAddr)
					http.Error(w, "Room is at viewer capacity", http.StatusServiceUnavailable)
					return
				}
				if r.Method == http.MethodGet {
					sessionID = newHlsSessionID()
					hlsViewers.touch(room, sessionID)
				}
			} else if r.Method == http.MethodGet {
				hlsViewers.touch(room, sessionID)
			}
			if r.Method == http.MethodGet {
				setHlsAuthCookies(w, r, room, info.GrantEpoch, sessionID, info.HasPassword)
			}
		}

		fs.ServeHTTP(w, r)
	})
}
