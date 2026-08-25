package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
)

var (
	sfuInternalSecret         string
	errSfuInternalRequired    = errors.New("SFU_INTERNAL_SECRET is required")
	errSfuInternalTooWeak     = errors.New("SFU_INTERNAL_SECRET must be at least 16 bytes")
)

func applySfuInternalSecret(secret string) error {
	if secret == "" {
		return errSfuInternalRequired
	}
	if len(secret) < 16 {
		return errSfuInternalTooWeak
	}
	sfuInternalSecret = secret
	return nil
}

func rustRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-SFU-Internal", sfuInternalSecret)
	return req, nil
}

func rustDo(req *http.Request) (*http.Response, error) {
	if req.Header.Get("X-SFU-Internal") == "" && sfuInternalSecret != "" {
		req.Header.Set("X-SFU-Internal", sfuInternalSecret)
	}
	return http.DefaultClient.Do(req)
}

func rustGet(url string) (*http.Response, error) {
	req, err := rustRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return rustDo(req)
}

func rustCheckRoomPassword(roomID, submitted string) bool {
	if rustCoreURL == "" || roomID == "" {
		return false
	}
	raw, err := json.Marshal(map[string]string{"password": submitted})
	if err != nil {
		return false
	}
	req, err := rustRequest(http.MethodPost, rustCoreURL+"/check_room_password/"+roomID, bytes.NewReader(raw))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rustDo(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return false
	}
	return out.OK
}

func envSfuInternalSecret() string {
	return strings.TrimSpace(os.Getenv("SFU_INTERNAL_SECRET"))
}
