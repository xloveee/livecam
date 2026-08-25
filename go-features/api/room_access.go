package main

import (
	"net/http"
	"strings"
)

// roomAccessOK is the H18/H25 gate: rust-down or unknown room (unfetched) is not open.
func roomAccessOK(info roomInfoResult, passwordPassed bool) bool {
	if !info.Fetched {
		return false
	}
	if !info.HasPassword {
		return true
	}
	return passwordPassed
}

func parseHlsRoom(urlPath string) (room, file string, ok bool) {
	rest := strings.TrimPrefix(urlPath, "/hls/")
	if rest == "" || rest == urlPath {
		return "", "", false
	}
	parts := strings.SplitN(rest, "/", 2)
	room = parts[0]
	if room == "" || room == "." || room == ".." || strings.ContainsAny(room, `/\`) {
		return "", "", false
	}
	if len(parts) == 2 {
		file = parts[1]
	}
	if file == "" || strings.HasSuffix(file, "/") || strings.Contains(file, "..") {
		return "", "", false
	}
	return room, file, true
}

func hlsFailClosed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		room, _, ok := parseHlsRoom(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		info := fetchRoomInfo(room)
		// M2: header-only password (already); do not serve leftover HLS when not live.
		if !info.Fetched || !info.IsLive {
			http.Error(w, "Room is not live", http.StatusNotFound)
			return
		}
		passed := false
		if info.HasPassword {
			submitted := ""
			if r != nil {
				submitted = strings.TrimSpace(r.Header.Get("X-Room-Password"))
			}
			passed = rustCheckRoomPassword(room, submitted)
		}
		if !roomAccessOK(info, passed) {
			http.Error(w, "Incorrect room password", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func chatRoomAccessFetched(r *http.Request, roomID string) bool {
	info := fetchRoomInfo(roomID)
	passed := false
	if info.Fetched && info.HasPassword {
		submitted := ""
		if r != nil {
			submitted = strings.TrimSpace(r.Header.Get("X-Room-Password"))
		}
		passed = rustCheckRoomPassword(roomID, submitted)
	}
	return roomAccessOK(info, passed)
}
