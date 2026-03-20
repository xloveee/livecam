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

	"livecam/chat"
	"livecam/donations"
)

var (
	iceServers  []map[string]interface{}
	clientDir   string
	rustCoreURL string
)

func main() {
	initConfig()

	chatHub := chat.NewHub()
	chatAuth := chat.AuthFunc(func(r *http.Request) (string, bool) {
		cookie, err := r.Cookie("broadcaster_session")
		if err != nil || cookie.Value == "" {
			return "", false
		}
		cToken := C.CString(cookie.Value)
		defer C.free(unsafe.Pointer(cToken))
		var outKey [C.STREAM_KEY_EXACT_LEN + 1]C.char
		if C.extract_stream_key_from_token(cToken, &outKey[0]) == 0 {
			return "", false
		}
		return C.GoString(&outKey[0]), true
	})

	donationDBPath := os.Getenv("DONATION_DB_PATH")
	if donationDBPath == "" {
		donationDBPath = "/opt/livecam/data/donations.db"
	}

	var donationDB *donations.DB
	donationDB, err := donations.OpenDB(donationDBPath)
	if err != nil {
		log.Printf("WARNING: Donations disabled — could not open database at %s: %v", donationDBPath, err)
	} else {
		defer donationDB.Close()
		log.Printf("Donations database: %s", donationDBPath)

		stripeWebhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
		if stripeWebhookSecret != "" {
			donations.SetStripeWebhookSecret(stripeWebhookSecret)
			log.Printf("Stripe webhook signature verification: enabled")
		}
	}

	donationHandler := donations.NewHandler(
		donationDB,
		chatHub,
		donations.AuthFunc(requireBroadcasterAuth),
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/chat/", chat.NewHandler(chatHub, chatAuth))
	mux.Handle("/api/donations/", donationHandler)
	mux.HandleFunc("/api/whip/", whipProxyHandler)
	mux.HandleFunc("/api/whep/", whepProxyHandler)
	mux.HandleFunc("/api/quality/", qualityProxyHandler)
	mux.HandleFunc("/api/room_info/", roomInfoProxyHandler)
	mux.HandleFunc("/api/viewer_limit/", viewerLimitProxyHandler)
	mux.HandleFunc("/api/room_password/", roomPasswordProxyHandler)
	mux.HandleFunc("/api/auth/broadcast", authBroadcastHandler)
	mux.HandleFunc("/api/active", activeProxyHandler)
	mux.HandleFunc("/api/config", configHandler)
	mux.HandleFunc("/api/health", healthHandler)
	staticFS := http.FileServer(http.Dir(clientDir))
	mux.Handle("/css/", staticFS)
	mux.Handle("/js/", staticFS)
	mux.HandleFunc("/broadcast", broadcastHandler)
	mux.HandleFunc("/broadcast/", broadcastHandler)
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

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = "default_dev_secret_change_me!!"
		log.Printf("WARNING: SESSION_SECRET not set, using insecure default")
	}
	cSecret := C.CString(sessionSecret)
	C.init_session_secret(cSecret)
	C.free(unsafe.Pointer(cSecret))

	broadcastPwd := os.Getenv("BROADCAST_PASSWORD")
	if broadcastPwd != "" {
		cPwd := C.CString(broadcastPwd)
		C.init_broadcast_password(cPwd)
		C.free(unsafe.Pointer(cPwd))
		log.Printf("Broadcast page password: enabled")
	} else {
		log.Printf("Broadcast page password: disabled (open mode)")
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

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func requireBroadcasterAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	cookie, err := r.Cookie("broadcaster_session")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}

	cToken := C.CString(cookie.Value)
	defer C.free(unsafe.Pointer(cToken))

	var outKey [C.STREAM_KEY_EXACT_LEN + 1]C.char
	if C.extract_stream_key_from_token(cToken, &outKey[0]) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return C.GoString(&outKey[0]), true
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

func authBroadcastHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		authBroadcastCheckHandler(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req struct {
		Password  string `json:"password"`
		StreamKey string `json:"stream_key"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	cPwd := C.CString(req.Password)
	defer C.free(unsafe.Pointer(cPwd))
	if C.check_broadcast_password(cPwd) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cKey := C.CString(req.StreamKey)
	defer C.free(unsafe.Pointer(cKey))
	if C.validate_stream_key(cKey) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var tokenBuf [C.SESSION_TOKEN_HEX_LEN + 1]C.char
	C.generate_session_token(cKey, &tokenBuf[0])
	token := C.GoString(&tokenBuf[0])

	http.SetCookie(w, &http.Cookie{
		Name:     "broadcaster_session",
		Value:    token,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"stream_key": req.StreamKey,
	})
}

func authBroadcastCheckHandler(w http.ResponseWriter, r *http.Request) {
	streamKey, ok := requireBroadcasterAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":     "ok",
		"stream_key": streamKey,
	})
}

func broadcastHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")

	cookie, err := r.Cookie("broadcaster_session")
	if err == nil && cookie.Value != "" {
		cToken := C.CString(cookie.Value)
		defer C.free(unsafe.Pointer(cToken))
		var outKey [C.STREAM_KEY_EXACT_LEN + 1]C.char
		if C.extract_stream_key_from_token(cToken, &outKey[0]) == 1 {
			http.ServeFile(w, r, clientDir+"/broadcast.html")
			return
		}
	}

	http.ServeFile(w, r, clientDir+"/broadcast_login.html")
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
	if r.Method == http.MethodDelete {
		whepDeleteHandler(w, r)
		return
	}
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

	if !info.IsLive {
		log.Printf("Room '%s' is not live, rejecting viewer %s", roomID, ip)
		http.Error(w, "Room is not live", http.StatusNotFound)
		return
	}

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

func whepDeleteHandler(w http.ResponseWriter, r *http.Request) {
	roomID := r.URL.Path[len("/api/whep/"):]
	roomID = strings.TrimSuffix(roomID, "/")

	sessionID := r.Header.Get("X-Session-Id")
	if sessionID == "" {
		http.Error(w, "Missing X-Session-Id header", http.StatusBadRequest)
		return
	}

	rustURL := fmt.Sprintf("%s/whep/%s", rustCoreURL, roomID)
	req, err := http.NewRequest(http.MethodDelete, rustURL, nil)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Session-Id", sessionID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to reach Rust Core for disconnect: %v", err)
		http.Error(w, "Media server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
	_, ok := requireBroadcasterAuth(w, r)
	if !ok {
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
	_, ok := requireBroadcasterAuth(w, r)
	if !ok {
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
