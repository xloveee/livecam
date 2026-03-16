package main

/*
#cgo CFLAGS: -I${SRCDIR}/c_src
#include <stdlib.h>
#include "c_src/core_logic.h"
*/
import "C"
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"unsafe"
)

var (
	iceServers  []map[string]interface{}
	clientDir   string
	rustCoreURL string
)

func main() {
	initConfig()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/whip/", whipProxyHandler)
	mux.HandleFunc("/api/whep/", whepProxyHandler)
	mux.HandleFunc("/api/quality/", qualityProxyHandler)
	mux.HandleFunc("/api/room_info/", roomInfoProxyHandler)
	mux.HandleFunc("/api/viewer_limit/", viewerLimitProxyHandler)
	mux.HandleFunc("/api/room_password/", roomPasswordProxyHandler)
	mux.HandleFunc("/api/active", activeProxyHandler)
	mux.HandleFunc("/api/config", configHandler)
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/broadcast", broadcastHandler)
	mux.HandleFunc("/watch/", watchHandler)
	mux.HandleFunc("/", rootHandler)

	port := os.Getenv("GO_LISTEN_PORT")
	if port == "" {
		port = "8443"
	}

	fmt.Printf("Go proxy running on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func initConfig() {
	clientDir = os.Getenv("CLIENT_DIR")
	if clientDir == "" {
		clientDir = "../../client"
	}

	rustCoreURL = os.Getenv("RUST_CORE_URL")
	if rustCoreURL == "" {
		rustCoreURL = "http://127.0.0.1:8080"
	}

	allowedKeys := os.Getenv("ALLOWED_STREAM_KEYS")
	if allowedKeys != "" {
		cKeys := C.CString(allowedKeys)
		C.init_stream_key_whitelist(cKeys)
		C.free(unsafe.Pointer(cKeys))
		count := strings.Count(allowedKeys, ",") + 1
		log.Printf("Stream key whitelist loaded: %d keys", count)
	} else {
		log.Printf("Stream key whitelist: disabled (open mode)")
	}

	stunURL := os.Getenv("STUN_URL")
	if stunURL == "" {
		stunURL = "stun:stun.l.google.com:19302"
	}

	iceServers = []map[string]interface{}{
		{"urls": stunURL},
	}

	turnURL := os.Getenv("TURN_URL")
	turnUser := os.Getenv("TURN_USERNAME")
	turnCred := os.Getenv("TURN_CREDENTIAL")
	if turnURL != "" && turnUser != "" && turnCred != "" {
		iceServers = append(iceServers, map[string]interface{}{
			"urls":       turnURL,
			"username":   turnUser,
			"credential": turnCred,
		})
	}

	log.Printf("Client dir: %s", clientDir)
	log.Printf("Rust Core URL: %s", rustCoreURL)
	log.Printf("ICE servers configured: %d entries", len(iceServers))
}

func requireBroadcasterAuth(w http.ResponseWriter, r *http.Request) bool {
	key := r.Header.Get("X-Stream-Key")
	if key == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	if C.validate_stream_key(cKey) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]interface{}{
		"iceServers": iceServers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := http.Get(rustCoreURL + "/health")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `{"go":"ok","rust":"unreachable"}`)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"go":"ok","rust":"ok"}`)
}

func broadcastHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, clientDir+"/broadcast.html")
}

func watchHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, clientDir+"/watch.html")
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, clientDir+"/watch.html")
}

func activeProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rustURL := fmt.Sprintf("%s/active", rustCoreURL)
	resp, err := http.Get(rustURL)
	if err != nil {
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func whipProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	streamKey := r.URL.Path[len("/api/whip/"):]

	cKey := C.CString(streamKey)
	defer C.free(unsafe.Pointer(cKey))

	isValid := C.validate_stream_key(cKey)
	if isValid == 0 {
		http.Error(w, "Invalid stream key", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	log.Printf("Valid WHIP request for key: %s, proxying to Rust Core...", streamKey)

	rustURL := fmt.Sprintf("%s/whip/%s", rustCoreURL, streamKey)
	req, err := http.NewRequest(http.MethodPost, rustURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to reach Rust Core: %v", err)
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read media server response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func whepProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.RemoteAddr
	cIp := C.CString(ip)
	defer C.free(unsafe.Pointer(cIp))

	isAllowed := C.check_viewer_rate_limit(cIp)
	if isAllowed == 0 {
		log.Printf("Viewer Rate Limited: %s", ip)
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	roomID := r.URL.Path[len("/api/whep/"):]
	roomID = strings.TrimSuffix(roomID, "/")

	info := fetchRoomInfo(roomID)

	capAllowed := C.check_viewer_cap(C.int32_t(info.ViewerCount), C.int32_t(info.MaxViewers))
	if capAllowed == 0 {
		log.Printf("Room '%s' at capacity (%d/%d), rejecting viewer %s", roomID, info.ViewerCount, info.MaxViewers, ip)
		http.Error(w, "Room is at viewer capacity", http.StatusServiceUnavailable)
		return
	}

	if info.HasPassword {
		submitted := r.Header.Get("X-Room-Password")
		cSubmitted := C.CString(submitted)
		cStored := C.CString(info.Password)
		defer C.free(unsafe.Pointer(cSubmitted))
		defer C.free(unsafe.Pointer(cStored))

		if C.check_room_password(cSubmitted, cStored) == 0 {
			log.Printf("Room '%s' password rejected for viewer %s", roomID, ip)
			http.Error(w, "Incorrect room password", http.StatusForbidden)
			return
		}
	}

	log.Printf("WHEP request for room: %s (IP: %s), proxying to Rust Core...", roomID, ip)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	rustURL := fmt.Sprintf("%s/whep/%s", rustCoreURL, roomID)
	req, err := http.NewRequest(http.MethodPost, rustURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to reach Rust Core: %v", err)
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read media server response", http.StatusInternalServerError)
		return
	}

	if sid := resp.Header.Get("X-Session-Id"); sid != "" {
		w.Header().Set("X-Session-Id", sid)
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

type roomInfoResult struct {
	ViewerCount int32  `json:"viewer_count"`
	MaxViewers  int32  `json:"max_viewers"`
	HasPassword bool   `json:"has_password"`
	IsLive      bool   `json:"is_live"`
	Password    string `json:"password,omitempty"`
}

func fetchRoomInfo(roomID string) roomInfoResult {
	infoURL := fmt.Sprintf("%s/room_info/%s", rustCoreURL, roomID)
	resp, err := http.Get(infoURL)
	if err != nil {
		return roomInfoResult{}
	}
	defer resp.Body.Close()

	var info roomInfoResult
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return roomInfoResult{}
	}
	return info
}

func roomInfoProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	roomID := r.URL.Path[len("/api/room_info/"):]
	roomID = strings.TrimSuffix(roomID, "/")

	info := fetchRoomInfo(roomID)

	publicResp := struct {
		ViewerCount int32 `json:"viewer_count"`
		MaxViewers  int32 `json:"max_viewers"`
		HasPassword bool  `json:"has_password"`
		IsLive      bool  `json:"is_live"`
	}{
		ViewerCount: info.ViewerCount,
		MaxViewers:  info.MaxViewers,
		HasPassword: info.HasPassword,
		IsLive:      info.IsLive,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(publicResp)
}

func viewerLimitProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireBroadcasterAuth(w, r) {
		return
	}

	roomID := r.URL.Path[len("/api/viewer_limit/"):]
	roomID = strings.TrimSuffix(roomID, "/")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	rustURL := fmt.Sprintf("%s/viewer_limit/%s", rustCoreURL, roomID)
	req, err := http.NewRequest(http.MethodPost, rustURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func roomPasswordProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireBroadcasterAuth(w, r) {
		return
	}

	roomID := r.URL.Path[len("/api/room_password/"):]
	roomID = strings.TrimSuffix(roomID, "/")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	rustURL := fmt.Sprintf("%s/room_password/%s", rustCoreURL, roomID)
	req, err := http.NewRequest(http.MethodPost, rustURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func qualityProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	roomID := r.URL.Path[len("/api/quality/"):]
	roomID = strings.TrimSuffix(roomID, "/")

	sessionID := r.Header.Get("X-Session-Id")
	if sessionID == "" {
		http.Error(w, "Missing X-Session-Id header", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	rustURL := fmt.Sprintf("%s/quality/%s", rustCoreURL, roomID)
	req, err := http.NewRequest(http.MethodPost, rustURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Id", sessionID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to reach Rust Core for quality change: %v", err)
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read media server response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}
