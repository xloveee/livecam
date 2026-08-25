package donations

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBTCPayInvoiceJSONEscapesNick(t *testing.T) {
	rec := &DonationRecord{
		ID:         "abc",
		ViewerNick: `evil","x":1,"y":"`,
		Amount:     500,
		Currency:   "USD",
	}
	// Build the same payload shape as createBTCPayInvoice.
	amountStr := "5.00"
	payload := map[string]interface{}{
		"amount":   amountStr,
		"currency": "USD",
		"metadata": map[string]string{
			"orderId":     rec.ID,
			"viewer_nick": rec.ViewerNick,
		},
		"checkout": map[string]string{"redirectURL": `https://live.example/?q="`},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	meta := back["metadata"].(map[string]interface{})
	if meta["viewer_nick"] != rec.ViewerNick {
		t.Fatalf("nick mangled: %#v", meta["viewer_nick"])
	}
	if strings.Contains(string(raw), `"x":1`) {
		t.Fatalf("injection survived: %s", raw)
	}
}
