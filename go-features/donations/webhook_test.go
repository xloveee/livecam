package donations

import (
	"time"
	"strconv"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"testing"
)

func stripeSig(secret string, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func bodyHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func paypalSig(secret, transID string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(transID))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestParseStripeWebhookRejectsUnsigned(t *testing.T) {
	SetWebhookSecrets("", "", "", "")
	body := []byte(`{"type":"checkout.session.completed","data":{"object":{"id":"cs_1","metadata":{"donation_id":"d1"}}}}`)
	if _, _, err := parseStripeWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject with no secret")
	}
	SetWebhookSecrets("stripe-webhook-secret-16", "", "", "")
	if _, _, err := parseStripeWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject with no Stripe-Signature")
	}
}

func TestParseStripeWebhookAcceptsValidHMAC(t *testing.T) {
	secret := "stripe-webhook-secret-16"
	SetWebhookSecrets(secret, "", "", "")
	body := []byte(`{"type":"checkout.session.completed","data":{"object":{"id":"cs_1","metadata":{"donation_id":"d1"}}}}`)
	h := http.Header{}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	h.Set("Stripe-Signature", stripeSig(secret, ts, body))
	id, ref, err := parseStripeWebhook(h, body)
	if err != nil {
		t.Fatal(err)
	}
	if id != "d1" || ref != "cs_1" {
		t.Fatalf("got %q %q", id, ref)
	}
	h.Set("Stripe-Signature", stripeSig("wrong-secret-value!", ts, body))
	if _, _, err := parseStripeWebhook(h, body); err == nil {
		t.Fatal("expected reject for wrong secret")
	}
}

func TestParsePayPalWebhookRejectsUnsigned(t *testing.T) {
	SetWebhookSecrets("", "", "", "")
	body := []byte(`{"event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{"id":"pay_1","custom_id":"d2"}}`)
	if _, _, err := parsePayPalWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject with no secret")
	}
	SetWebhookSecrets("", "paypal-webhook-secret16", "", "")
	if _, _, err := parsePayPalWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject without transmission id")
	}
}

func TestParsePayPalWebhookAcceptsValidHMAC(t *testing.T) {
	secret := "paypal-webhook-secret16"
	SetWebhookSecrets("", secret, "", "")
	body := []byte(`{"event_type":"PAYMENT.CAPTURE.COMPLETED","resource":{"id":"pay_1","custom_id":"d2"}}`)
	h := http.Header{}
	h.Set("PayPal-Transmission-Id", "txn-1")
	h.Set("PayPal-Transmission-Sig", paypalSig(secret, "txn-1", body))
	id, ref, err := parsePayPalWebhook(h, body)
	if err != nil {
		t.Fatal(err)
	}
	if id != "d2" || ref != "pay_1" {
		t.Fatalf("got %q %q", id, ref)
	}
}

func TestParseCryptoWebhookRequiresBTCPayHMAC(t *testing.T) {
	SetWebhookSecrets("", "", "", "")
	body := []byte(`{"invoiceId":"inv1","orderId":"d3"}`)
	if _, _, err := parseCryptoWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject with no secret")
	}
	secret := "btcpay-webhook-secret1"
	SetWebhookSecrets("", "", secret, "")
	if _, _, err := parseCryptoWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject without BTCPay-Sig")
	}
	h := http.Header{}
	h.Set("BTCPay-Sig", bodyHMAC(secret, body))
	id, ref, err := parseCryptoWebhook(h, body)
	if err != nil {
		t.Fatal(err)
	}
	if id != "d3" || ref != "inv1" {
		t.Fatalf("got %q %q", id, ref)
	}
}

func TestParseBankWebhookRequiresHMAC(t *testing.T) {
	SetWebhookSecrets("", "", "", "")
	body := []byte(`{"reference":"d4","payment_id":"bnk1"}`)
	if _, _, err := parseBankWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject with no secret")
	}
	secret := "bank-webhook-secret-16"
	SetWebhookSecrets("", "", "", secret)
	if _, _, err := parseBankWebhook(http.Header{}, body); err == nil {
		t.Fatal("expected reject without X-Bank-Signature")
	}
	h := http.Header{}
	h.Set("X-Bank-Signature", bodyHMAC(secret, body))
	id, ref, err := parseBankWebhook(h, body)
	if err != nil {
		t.Fatal(err)
	}
	if id != "d4" || ref != "bnk1" {
		t.Fatalf("got %q %q", id, ref)
	}
}

func TestRequireWebhookSecretsWhenStripeEnabled(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	SetWebhookSecrets("", "", "", "")
	if err := RequireWebhookSecrets(db); err != nil {
		t.Fatalf("empty db should not require secrets: %v", err)
	}
	if err := db.SaveConfig("k1", "stripe", `{}`, true); err != nil {
		t.Fatal(err)
	}
	if err := RequireWebhookSecrets(db); err == nil {
		t.Fatal("expected Fatal-style error when Stripe enabled without secret")
	}
	SetWebhookSecrets("stripe-webhook-secret-16", "", "", "")
	if err := RequireWebhookSecrets(db); err != nil {
		t.Fatal(err)
	}
}

func TestRequireWebhookSecretsNilDB(t *testing.T) {
	if err := RequireWebhookSecrets(nil); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyStripeRejectsStaleTimestamp(t *testing.T) {
	secret := "stripe-webhook-secret-16"
	SetWebhookSecrets(secret, "", "", "")
	body := []byte(`{"type":"checkout.session.completed","data":{"object":{"id":"cs_1","metadata":{"donation_id":"d1"}}}}`)
	h := http.Header{}
	h.Set("Stripe-Signature", stripeSig(secret, "1000", body))
	if _, _, err := parseStripeWebhook(h, body); err == nil {
		t.Fatal("expected reject for stale Stripe timestamp (M14)")
	}
}
