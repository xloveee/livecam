package donations

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func nowUnix() int64 {
	return time.Now().Unix()
}

func generateID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		ts := time.Now().UnixNano()
		for i := 0; i < 16; i++ {
			buf[i] = byte(ts >> (i * 4))
		}
	}
	buf[6] = (buf[6] & 0x0F) | 0x40
	buf[8] = (buf[8] & 0x3F) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

/* ── Redirect URL builders per provider ──────────────────── */

func buildRedirectURL(provider, configData string, rec *DonationRecord, returnURL string) (string, error) {
	switch provider {
	case "stripe":
		return buildStripeRedirect(configData, rec, returnURL)
	case "paypal":
		return buildPayPalRedirect(configData, rec)
	case "cashapp":
		return buildCashAppRedirect(configData, rec)
	case "crypto":
		return buildCryptoRedirect(configData, rec, returnURL)
	case "bank":
		return buildBankRedirect(configData, rec, returnURL)
	default:
		return "", errors.New("unsupported provider: " + provider)
	}
}

/* ── Stripe ──────────────────────────────────────────────── */

func buildStripeRedirect(configData string, rec *DonationRecord, returnURL string) (string, error) {
	var cfg struct {
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal([]byte(configData), &cfg); err != nil || cfg.SecretKey == "" {
		return "", errors.New("stripe: missing secret_key in config")
	}

	if returnURL == "" {
		returnURL = "https://example.com"
	}
	successURL := returnURL + "?donation=success&id=" + rec.ID
	cancelURL := returnURL + "?donation=cancelled"

	form := url.Values{}
	form.Set("mode", "payment")
	form.Set("success_url", successURL)
	form.Set("cancel_url", cancelURL)
	form.Set("line_items[0][price_data][currency]", strings.ToLower(rec.Currency))
	form.Set("line_items[0][price_data][unit_amount]", strconv.FormatInt(rec.Amount, 10))
	form.Set("line_items[0][price_data][product_data][name]", "Donation")
	form.Set("line_items[0][quantity]", "1")
	form.Set("metadata[donation_id]", rec.ID)
	form.Set("metadata[stream_key]", rec.StreamKey)
	form.Set("metadata[viewer_nick]", rec.ViewerNick)

	req, err := http.NewRequest(http.MethodPost,
		"https://api.stripe.com/v1/checkout/sessions",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("stripe: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.SecretKey, "")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("stripe: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("stripe: read body: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("stripe: API returned %d: %s", resp.StatusCode, string(body))
	}

	var session struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &session); err != nil || session.URL == "" {
		return "", errors.New("stripe: invalid session response")
	}

	return session.URL, nil
}

/* ── PayPal ──────────────────────────────────────────────── */

func buildPayPalRedirect(configData string, rec *DonationRecord) (string, error) {
	var cfg struct {
		Email    string `json:"email"`
		ClientID string `json:"client_id"`
		Secret   string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(configData), &cfg); err != nil {
		return "", errors.New("paypal: invalid config")
	}

	if cfg.ClientID != "" && cfg.Secret != "" {
		return buildPayPalCheckout(cfg.ClientID, cfg.Secret, rec)
	}

	if cfg.Email == "" {
		return "", errors.New("paypal: missing email in config")
	}

	amountStr := fmt.Sprintf("%.2f", float64(rec.Amount)/100.0)
	return fmt.Sprintf("https://www.paypal.com/paypalme/%s/%s%s",
		cfg.Email, amountStr, rec.Currency), nil
}

func buildPayPalCheckout(clientID, secret string, rec *DonationRecord) (string, error) {
	amountStr := fmt.Sprintf("%.2f", float64(rec.Amount)/100.0)
	currency := strings.ToUpper(rec.Currency)

	orderBody := fmt.Sprintf(`{
		"intent": "CAPTURE",
		"purchase_units": [{
			"amount": {"currency_code": "%s", "value": "%s"},
			"custom_id": "%s",
			"description": "Donation"
		}],
		"application_context": {
			"return_url": "https://example.com/donation/success?id=%s",
			"cancel_url": "https://example.com/donation/cancel"
		}
	}`, currency, amountStr, rec.ID, rec.ID)

	req, err := http.NewRequest(http.MethodPost,
		"https://api-m.paypal.com/v2/checkout/orders",
		strings.NewReader(orderBody))
	if err != nil {
		return "", fmt.Errorf("paypal: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(clientID, secret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("paypal: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("paypal: read body: %w", err)
	}

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("paypal: API returned %d: %s", resp.StatusCode, string(body))
	}

	var order struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	if err := json.Unmarshal(body, &order); err != nil {
		return "", errors.New("paypal: invalid order response")
	}

	for _, link := range order.Links {
		if link.Rel == "approve" {
			return link.Href, nil
		}
	}
	return "", errors.New("paypal: no approve link in response")
}

/* ── Cash App (no merchant API keys in v1) ───────────────── */

func parseCashAppConfig(configData string) (string, error) {
	var cfg struct {
		Handle  string `json:"handle"`
		Cashtag string `json:"cashtag"`
	}
	if err := json.Unmarshal([]byte(configData), &cfg); err != nil {
		return "", errors.New("cashapp: invalid config")
	}
	raw := strings.TrimSpace(cfg.Handle)
	if raw == "" {
		raw = strings.TrimSpace(cfg.Cashtag)
	}
	handle, ok := NormalizeCashAppHandle(raw)
	if !ok {
		return "", errors.New("cashapp: invalid handle")
	}
	return handle, nil
}

// NormalizeCashAppHandle strips a leading $ and whitespace.
// The server is the authority: only a valid cashtag is returned.
func NormalizeCashAppHandle(raw string) (string, bool) {
	h := strings.TrimSpace(raw)
	h = strings.TrimPrefix(h, "$")
	h = strings.TrimSpace(h)
	if h == "" || !ValidateCashAppHandle(h) {
		return "", false
	}
	return h, true
}

func validateCashAppSetup(configData string, enabled bool) error {
	var cfg struct {
		Handle  string `json:"handle"`
		Cashtag string `json:"cashtag"`
	}
	if err := json.Unmarshal([]byte(configData), &cfg); err != nil {
		return errors.New("cashapp: invalid config")
	}
	raw := strings.TrimSpace(cfg.Handle)
	if raw == "" {
		raw = strings.TrimSpace(cfg.Cashtag)
	}
	if raw == "" && !enabled {
		return nil
	}
	_, err := parseCashAppConfig(configData)
	return err
}

// BuildCashAppURL is the public cash.app/$Handle link.
// Amount (cents → dollars) is appended when Cash App's public path allows it.
func BuildCashAppURL(handle string, amountCents int64) string {
	u := "https://cash.app/$" + handle
	if amountCents > 0 {
		u += "/" + fmt.Sprintf("%.2f", float64(amountCents)/100.0)
	}
	return u
}

func buildCashAppRedirect(configData string, rec *DonationRecord) (string, error) {
	handle, err := parseCashAppConfig(configData)
	if err != nil {
		return "", err
	}
	amount := int64(0)
	if rec != nil {
		amount = rec.Amount
	}
	return BuildCashAppURL(handle, amount), nil
}

/* ── Crypto ──────────────────────────────────────────────── */

func buildCryptoRedirect(configData string, rec *DonationRecord, returnURL string) (string, error) {
	var cfg struct {
		BTCPayURL  string `json:"btcpay_url"`
		StoreID    string `json:"store_id"`
		APIKey     string `json:"api_key"`
		BTCAddress string `json:"btc_address"`
		ETHAddress string `json:"eth_address"`
	}
	if err := json.Unmarshal([]byte(configData), &cfg); err != nil {
		return "", errors.New("crypto: invalid config")
	}

	if cfg.BTCPayURL != "" && cfg.StoreID != "" {
		return createBTCPayInvoice(cfg.BTCPayURL, cfg.StoreID, cfg.APIKey, rec, returnURL)
	}

	if cfg.BTCAddress != "" && strings.ToUpper(rec.Currency) == "BTC" {
		satoshis := rec.Amount
		return fmt.Sprintf("bitcoin:%s?amount=%s&label=Donation&message=%s",
			cfg.BTCAddress,
			formatSatoshisAsBTC(satoshis),
			url.QueryEscape(rec.ID)), nil
	}

	if cfg.ETHAddress != "" && strings.ToUpper(rec.Currency) == "ETH" {
		return fmt.Sprintf("ethereum:%s?value=%d",
			cfg.ETHAddress, rec.Amount), nil
	}

	return "", errors.New("crypto: no payment method configured for " + rec.Currency)
}

func createBTCPayInvoice(btcpayURL, storeID, apiKey string, rec *DonationRecord, returnURL string) (string, error) {
	amountStr := fmt.Sprintf("%.2f", float64(rec.Amount)/100.0)
	payload := map[string]interface{}{
		"amount":   amountStr,
		"currency": strings.ToUpper(rec.Currency),
		"metadata": map[string]string{
			"orderId":     rec.ID,
			"viewer_nick": rec.ViewerNick,
		},
		"checkout": map[string]string{
			"redirectURL": returnURL,
		},
	}
	invoiceBody, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("btcpay: marshal: %w", err)
	}

	apiURL := fmt.Sprintf("%s/api/v1/stores/%s/invoices", btcpayURL, storeID)
	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(string(invoiceBody)))
	if err != nil {
		return "", fmt.Errorf("btcpay: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "token "+apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("btcpay: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("btcpay: read body: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("btcpay: API returned %d: %s", resp.StatusCode, string(body))
	}

	var invoice struct {
		CheckoutLink string `json:"checkoutLink"`
	}
	if err := json.Unmarshal(body, &invoice); err != nil || invoice.CheckoutLink == "" {
		return "", errors.New("btcpay: invalid invoice response")
	}

	return invoice.CheckoutLink, nil
}

func formatSatoshisAsBTC(satoshis int64) string {
	whole := satoshis / 100000000
	frac := satoshis % 100000000
	if frac < 0 {
		frac = -frac
	}
	return fmt.Sprintf("%d.%08d", whole, frac)
}

/* ── Bank / YowPay ───────────────────────────────────────── */

func buildBankRedirect(configData string, rec *DonationRecord, returnURL string) (string, error) {
	var cfg struct {
		YowPayURL  string `json:"yowpay_url"`
		MerchantID string `json:"merchant_id"`
		APIKey     string `json:"api_key"`
	}
	if err := json.Unmarshal([]byte(configData), &cfg); err != nil {
		return "", errors.New("bank: invalid config")
	}

	if cfg.YowPayURL == "" {
		cfg.YowPayURL = "https://yowpay.com"
	}

	if cfg.MerchantID == "" {
		return cfg.YowPayURL + "/register", nil
	}

	amountStr := fmt.Sprintf("%.2f", float64(rec.Amount)/100.0)
	currency := strings.ToUpper(rec.Currency)

	if cfg.APIKey != "" {
		return createYowPayPayment(cfg.YowPayURL, cfg.MerchantID, cfg.APIKey,
			amountStr, currency, rec.ID, returnURL)
	}

	params := url.Values{}
	params.Set("merchant", cfg.MerchantID)
	params.Set("amount", amountStr)
	params.Set("currency", currency)
	params.Set("ref", rec.ID)
	if returnURL != "" {
		params.Set("return_url", returnURL)
	}
	return cfg.YowPayURL + "/pay?" + params.Encode(), nil
}

func createYowPayPayment(baseURL, merchantID, apiKey, amount, currency, ref, returnURL string) (string, error) {
	payload := map[string]string{
		"merchant_id": merchantID,
		"amount":      amount,
		"currency":    currency,
		"reference":   ref,
		"return_url":  returnURL,
	}
	payloadBody, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("yowpay: marshal: %w", err)
	}

	apiURL := baseURL + "/api/v1/payments"
	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(string(payloadBody)))
	if err != nil {
		return "", fmt.Errorf("yowpay: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("yowpay: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("yowpay: read body: %w", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", fmt.Errorf("yowpay: API returned %d: %s", resp.StatusCode, string(body))
	}

	var payment struct {
		PaymentURL string `json:"payment_url"`
	}
	if err := json.Unmarshal(body, &payment); err != nil || payment.PaymentURL == "" {
		return "", errors.New("yowpay: invalid payment response")
	}

	return payment.PaymentURL, nil
}

/* ── Webhook parsers ─────────────────────────────────────── */

func parseWebhook(provider string, headers http.Header, body []byte) (donationID, providerRef string, err error) {
	switch provider {
	case "stripe":
		return parseStripeWebhook(headers, body)
	case "paypal":
		return parsePayPalWebhook(headers, body)
	case "cashapp":
		return "", "", errors.New("cashapp: no webhook in v1 (open cash.app/$Handle)")
	case "crypto":
		return parseCryptoWebhook(headers, body)
	case "bank":
		return parseBankWebhook(headers, body)
	default:
		return "", "", errors.New("unsupported provider: " + provider)
	}
}

const webhookSecretMinLen = 16

var (
	stripeWebhookSecret string
	paypalWebhookSecret string
	cryptoWebhookSecret string
	bankWebhookSecret   string
)

func SetStripeWebhookSecret(secret string) {
	stripeWebhookSecret = secret
}

func SetWebhookSecrets(stripe, paypal, crypto, bank string) {
	stripeWebhookSecret = stripe
	paypalWebhookSecret = paypal
	cryptoWebhookSecret = crypto
	bankWebhookSecret = bank
}

func RequireWebhookSecrets(db *DB) error {
	if db == nil {
		return nil
	}
	checks := []struct {
		provider string
		secret   string
		env      string
	}{
		{"stripe", stripeWebhookSecret, "STRIPE_WEBHOOK_SECRET"},
		{"paypal", paypalWebhookSecret, "PAYPAL_WEBHOOK_SECRET"},
		{"crypto", cryptoWebhookSecret, "BTCPAY_WEBHOOK_SECRET"},
		{"bank", bankWebhookSecret, "BANK_WEBHOOK_SECRET"},
	}
	for _, c := range checks {
		on, err := db.AnyProviderEnabled(c.provider)
		if err != nil {
			return err
		}
		if on && len(c.secret) < webhookSecretMinLen {
			return fmt.Errorf("%s required when %s is enabled (min %d bytes)", c.env, c.provider, webhookSecretMinLen)
		}
	}
	return nil
}

func headerHMACHex(header string) string {
	got := strings.TrimSpace(header)
	if i := strings.Index(got, "="); i >= 0 {
		got = strings.TrimSpace(got[i+1:])
	}
	return got
}

func verifyBodyHMAC(body []byte, secret, header string) bool {
	if secret == "" || header == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(headerHMACHex(header)))
}

func parseStripeWebhook(headers http.Header, body []byte) (string, string, error) {
	if len(stripeWebhookSecret) < webhookSecretMinLen {
		return "", "", errors.New("stripe: webhook secret not configured")
	}
	sig := headers.Get("Stripe-Signature")
	if !verifyStripeSignature(body, sig, stripeWebhookSecret) {
		return "", "", errors.New("stripe: invalid signature")
	}

	var event struct {
		Type string `json:"type"`
		Data struct {
			Object struct {
				ID       string            `json:"id"`
				Metadata map[string]string `json:"metadata"`
			} `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return "", "", err
	}

	if event.Type != "checkout.session.completed" {
		return "", "", fmt.Errorf("stripe: ignoring event type %s", event.Type)
	}

	donationID := event.Data.Object.Metadata["donation_id"]
	if donationID == "" {
		return "", "", errors.New("stripe: missing donation_id in metadata")
	}

	return donationID, event.Data.Object.ID, nil
}

func verifyStripeSignature(payload []byte, sigHeader, secret string) bool {
	if sigHeader == "" {
		return false
	}

	var timestamp, sig string
	for _, part := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			sig = kv[1]
		}
	}

	if timestamp == "" || sig == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(sig))
}

func parsePayPalWebhook(headers http.Header, body []byte) (string, string, error) {
	if len(paypalWebhookSecret) < webhookSecretMinLen {
		return "", "", errors.New("paypal: webhook secret not configured")
	}
	transID := headers.Get("PayPal-Transmission-Id")
	if transID == "" {
		return "", "", errors.New("paypal: missing PayPal-Transmission-Id")
	}
	sig := headers.Get("PayPal-Transmission-Sig")
	if sig == "" {
		sig = headers.Get("X-Paypal-Signature")
	}
	mac := hmac.New(sha256.New, []byte(paypalWebhookSecret))
	mac.Write([]byte(transID))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(headerHMACHex(sig))) {
		return "", "", errors.New("paypal: invalid signature")
	}

	var event struct {
		EventType string `json:"event_type"`
		Resource  struct {
			ID       string `json:"id"`
			CustomID string `json:"custom_id"`
			PurchaseUnits []struct {
				CustomID string `json:"custom_id"`
			} `json:"purchase_units"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return "", "", err
	}

	if event.EventType != "CHECKOUT.ORDER.APPROVED" && event.EventType != "PAYMENT.CAPTURE.COMPLETED" {
		return "", "", fmt.Errorf("paypal: ignoring event type %s", event.EventType)
	}

	donationID := event.Resource.CustomID
	if donationID == "" && len(event.Resource.PurchaseUnits) > 0 {
		donationID = event.Resource.PurchaseUnits[0].CustomID
	}
	if donationID == "" {
		return "", "", errors.New("paypal: missing custom_id (donation_id)")
	}

	return donationID, event.Resource.ID, nil
}

func parseCryptoWebhook(headers http.Header, body []byte) (string, string, error) {
	if len(cryptoWebhookSecret) < webhookSecretMinLen {
		return "", "", errors.New("crypto: webhook secret not configured")
	}
	sig := headers.Get("BTCPay-Sig")
	if sig == "" {
		sig = headers.Get("BTCPAY-SIG")
	}
	if !verifyBodyHMAC(body, cryptoWebhookSecret, sig) {
		return "", "", errors.New("crypto: invalid signature")
	}

	var event struct {
		InvoiceID string `json:"invoiceId"`
		Type      string `json:"type"`
		Metadata  struct {
			OrderID string `json:"orderId"`
		} `json:"metadata"`
		OrderID string `json:"orderId"`
		ID      string `json:"id"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return "", "", err
	}

	donationID := event.Metadata.OrderID
	if donationID == "" {
		donationID = event.OrderID
	}
	if donationID == "" {
		return "", "", errors.New("crypto: missing orderId in webhook")
	}

	invoiceID := event.InvoiceID
	if invoiceID == "" {
		invoiceID = event.ID
	}

	return donationID, invoiceID, nil
}

func parseBankWebhook(headers http.Header, body []byte) (string, string, error) {
	if len(bankWebhookSecret) < webhookSecretMinLen {
		return "", "", errors.New("bank: webhook secret not configured")
	}
	if !verifyBodyHMAC(body, bankWebhookSecret, headers.Get("X-Bank-Signature")) {
		return "", "", errors.New("bank: invalid signature")
	}

	var event struct {
		Reference   string `json:"reference"`
		PaymentID   string `json:"payment_id"`
		TxnID       string `json:"txn_id"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return "", "", err
	}

	if event.Reference == "" {
		return "", "", errors.New("bank: missing reference in webhook")
	}

	txnID := event.PaymentID
	if txnID == "" {
		txnID = event.TxnID
	}

	return event.Reference, txnID, nil
}

