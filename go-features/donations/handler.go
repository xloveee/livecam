package donations

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"livecam/chat"
)

const donationCooldownSec = 10

type Handler struct {
	db          *DB
	hub         *chat.Hub
	auth        AuthFunc
	rateMu      sync.Mutex
	lastDonate  map[string]int64
}

func NewHandler(db *DB, hub *chat.Hub, auth AuthFunc) *Handler {
	return &Handler{
		db:         db,
		hub:        hub,
		auth:       auth,
		lastDonate: make(map[string]int64),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		http.Error(w, "Donations are not available", http.StatusServiceUnavailable)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/donations")
	path = strings.TrimSuffix(path, "/")

	switch {
	case path == "/setup" || path == "/setup/":
		h.handleSetup(w, r)
	case strings.HasPrefix(path, "/methods/"):
		h.handleMethods(w, r, strings.TrimPrefix(path, "/methods/"))
	case path == "/initiate" || path == "/initiate/":
		h.handleInitiate(w, r)
	case strings.HasPrefix(path, "/webhook/"):
		provider := strings.TrimPrefix(path, "/webhook/")
		h.handleWebhook(w, r, provider)
	case strings.HasPrefix(path, "/confirm/"):
		donationID := strings.TrimPrefix(path, "/confirm/")
		h.handleConfirm(w, r, donationID)
	case path == "/history" || path == "/history/":
		h.handleHistory(w, r)
	default:
		http.NotFound(w, r)
	}
}

/* ── Setup (broadcaster CRUD) ────────────────────────────── */

func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	streamKey, ok := h.auth(w, r)
	if !ok {
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleSetupGet(w, streamKey)
	case http.MethodPost:
		h.handleSetupPost(w, r, streamKey)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleSetupGet(w http.ResponseWriter, streamKey string) {
	configs, err := h.db.GetConfig(streamKey)
	if err != nil {
		log.Printf("[donations] setup get error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if configs == nil {
		configs = []ProviderConfig{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs)
}

func (h *Handler) handleSetupPost(w http.ResponseWriter, r *http.Request, streamKey string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req SetupRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	validProviders := map[string]bool{
		"stripe": true, "paypal": true, "crypto": true, "bank": true,
	}
	if !validProviders[req.Provider] {
		http.Error(w, "Invalid provider", http.StatusBadRequest)
		return
	}

	if err := h.db.SaveConfig(streamKey, req.Provider, req.ConfigData, req.Enabled); err != nil {
		log.Printf("[donations] setup save error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

/* ── Methods (public — which providers are enabled) ──────── */

func (h *Handler) handleMethods(w http.ResponseWriter, r *http.Request, roomID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if roomID == "" {
		http.Error(w, "Missing room ID", http.StatusBadRequest)
		return
	}

	configs, err := h.db.GetEnabledProviders(roomID)
	if err != nil {
		log.Printf("[donations] methods error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp := MethodsResponse{}
	for _, c := range configs {
		switch c.Provider {
		case "stripe":
			resp.Stripe = true
		case "paypal":
			resp.PayPal = true
		case "crypto":
			resp.Crypto = parseCryptoCurrencies(c.ConfigData)
		case "bank":
			resp.Bank = true
		default:
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func parseCryptoCurrencies(configData string) []string {
	var cfg struct {
		Currencies []string `json:"currencies"`
	}
	if json.Unmarshal([]byte(configData), &cfg) != nil {
		return nil
	}
	return cfg.Currencies
}

/* ── Initiate (placeholder — providers fill this in Phase 2–3) */

func (h *Handler) handleInitiate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req InitiateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if req.RoomID == "" || req.Provider == "" || req.Currency == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	now := time.Now().Unix()
	h.rateMu.Lock()
	lastTime := h.lastDonate[ip]
	if !CheckRateLimit(lastTime, now, donationCooldownSec) {
		h.rateMu.Unlock()
		http.Error(w, "Please wait before donating again", http.StatusTooManyRequests)
		return
	}
	h.lastDonate[ip] = now
	h.rateMu.Unlock()

	if !ValidateAmount(req.Amount, 1, 100000000) {
		http.Error(w, "Invalid amount", http.StatusBadRequest)
		return
	}

	sanitized := ""
	if req.Message != "" {
		var ok bool
		sanitized, ok = SanitizeMessage(req.Message)
		if !ok {
			sanitized = ""
		}
	}

	configs, err := h.db.GetEnabledProviders(req.RoomID)
	if err != nil {
		log.Printf("[donations] initiate db error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	var providerConfig *ProviderConfig
	for i := range configs {
		if configs[i].Provider == req.Provider {
			providerConfig = &configs[i]
			break
		}
	}
	if providerConfig == nil {
		http.Error(w, "Provider not enabled for this stream", http.StatusBadRequest)
		return
	}

	donationID := generateID()

	rec := &DonationRecord{
		ID:         donationID,
		StreamKey:  req.RoomID,
		ViewerNick: req.ViewerNick,
		Amount:     req.Amount,
		Currency:   req.Currency,
		Message:    sanitized,
		Provider:   req.Provider,
		Status:     "pending",
		CreatedAt:  nowUnix(),
	}
	if err := h.db.InsertDonation(rec); err != nil {
		log.Printf("[donations] initiate insert error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	redirectURL, err := buildRedirectURL(req.Provider, providerConfig.ConfigData, rec, req.ReturnURL)
	if err != nil {
		log.Printf("[donations] initiate redirect error: %v", err)
		http.Error(w, "Failed to create payment session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InitiateResponse{
		DonationID:  donationID,
		RedirectURL: redirectURL,
	})
}

/* ── Webhook (provider callbacks) ────────────────────────── */

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request, provider string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	donationID, providerRef, err := parseWebhook(provider, r.Header, body)
	if err != nil {
		log.Printf("[donations] webhook parse error (%s): %v", provider, err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if err := h.db.ConfirmDonation(donationID, providerRef); err != nil {
		log.Printf("[donations] webhook confirm error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	rec, err := h.db.GetDonation(donationID)
	if err != nil || rec == nil {
		log.Printf("[donations] webhook get donation error: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	if rec.Status == "confirmed" {
		h.broadcastDonation(rec)
	}

	w.WriteHeader(http.StatusOK)
}

/* ── Manual confirm (bank/crypto) ────────────────────────── */

func (h *Handler) handleConfirm(w http.ResponseWriter, r *http.Request, donationID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	streamKey, ok := h.auth(w, r)
	if !ok {
		return
	}

	rec, err := h.db.GetDonation(donationID)
	if err != nil || rec == nil {
		http.Error(w, "Donation not found", http.StatusNotFound)
		return
	}

	if rec.StreamKey != streamKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.db.ConfirmDonation(donationID, "manual"); err != nil {
		log.Printf("[donations] confirm error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	rec.Status = "confirmed"
	h.broadcastDonation(rec)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

/* ── History (broadcaster only) ──────────────────────────── */

func (h *Handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	streamKey, ok := h.auth(w, r)
	if !ok {
		return
	}

	records, err := h.db.GetHistory(streamKey, 100)
	if err != nil {
		log.Printf("[donations] history error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if records == nil {
		records = []DonationRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

/* ── Chat broadcast ──────────────────────────────────────── */

func (h *Handler) broadcastDonation(rec *DonationRecord) {
	h.hub.BroadcastDonation(rec.StreamKey, chat.OutboundMsg{
		Type:     "donation",
		Nick:     rec.ViewerNick,
		Text:     rec.Message,
		Amount:   rec.Amount,
		Currency: rec.Currency,
		Ts:       rec.CreatedAt,
	})
}
