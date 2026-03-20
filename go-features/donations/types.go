package donations

import "net/http"

type AuthFunc func(w http.ResponseWriter, r *http.Request) (streamKey string, ok bool)

type ProviderConfig struct {
	StreamKey  string `json:"stream_key"`
	Provider   string `json:"provider"`
	ConfigData string `json:"config_data"`
	Enabled    bool   `json:"enabled"`
	UpdatedAt  int64  `json:"updated_at"`
}

type DonationRecord struct {
	ID          string `json:"id"`
	StreamKey   string `json:"stream_key"`
	ViewerNick  string `json:"viewer_nick"`
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	Message     string `json:"message"`
	Provider    string `json:"provider"`
	Status      string `json:"status"`
	ProviderRef string `json:"provider_ref,omitempty"`
	CreatedAt   int64  `json:"created_at"`
}

type SetupRequest struct {
	Provider   string `json:"provider"`
	ConfigData string `json:"config_data"`
	Enabled    bool   `json:"enabled"`
}

type InitiateRequest struct {
	RoomID     string `json:"room_id"`
	Provider   string `json:"provider"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
	Message    string `json:"message"`
	ViewerNick string `json:"viewer_nick"`
	ReturnURL  string `json:"return_url"`
}

type InitiateResponse struct {
	DonationID  string `json:"donation_id"`
	RedirectURL string `json:"redirect_url"`
}

type MethodsResponse struct {
	Stripe bool     `json:"stripe"`
	PayPal bool     `json:"paypal"`
	Crypto []string `json:"crypto,omitempty"`
	Bank   bool     `json:"bank"`
}

type ChannelPanel struct {
	Slot     int    `json:"slot"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	ImageURL string `json:"image_url"`
	LinkURL  string `json:"link_url"`
	Enabled  bool   `json:"enabled"`
}
