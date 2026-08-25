package donations

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// allowReturnURL is the H7 gate for Stripe/BTCPay/bank success URLs.
// Empty is ok (provider default). Otherwise https only (http for loopback),
// host must match PUBLIC_BASE_URL / PUBLIC_DOMAIN / DONATION_RETURN_HOSTS /
// the request host.
func allowReturnURL(raw string, r *http.Request) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	if isLocalReturnHost(host) {
		return scheme == "http" || scheme == "https"
	}
	if scheme != "https" {
		return false
	}
	for _, allowed := range donationReturnHosts(r) {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func isLocalReturnHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func donationReturnHosts(r *http.Request) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return
		}
		if strings.Contains(h, "://") {
			if u, err := url.Parse(h); err == nil {
				h = strings.ToLower(u.Hostname())
			}
		}
		h = strings.TrimSuffix(h, "/")
		if h == "" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}

	add(os.Getenv("PUBLIC_BASE_URL"))
	add(os.Getenv("PUBLIC_DOMAIN"))
	for _, part := range strings.Split(os.Getenv("DONATION_RETURN_HOSTS"), ",") {
		add(part)
	}
	if r != nil {
		host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
		if host == "" {
			host = r.Host
		}
		host = strings.TrimSpace(strings.Split(host, ",")[0])
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		add(host)
	}
	return out
}
