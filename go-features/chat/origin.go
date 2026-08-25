package chat

import (
	"net/http"
	"os"
	"strings"
)

// checkChatOrigin is the H5 gate: cross-site pages must not open chat sockets.
// Missing Origin (native clients / non-browser) is allowed. When Origin is set,
// it must match PUBLIC_BASE_URL, PUBLIC_DOMAIN, CHAT_ALLOWED_ORIGINS, or the
// request host.
func checkChatOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	origin = strings.TrimRight(origin, "/")
	for _, allowed := range chatAllowedOrigins(r) {
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}

func chatAllowedOrigins(r *http.Request) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		s = strings.TrimRight(s, "/")
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}

	if base := strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")); base != "" {
		add(base)
	}
	if domain := strings.TrimSpace(os.Getenv("PUBLIC_DOMAIN")); domain != "" {
		if strings.Contains(domain, "://") {
			add(domain)
		} else {
			add("https://" + domain)
			if strings.HasPrefix(domain, "127.") || domain == "localhost" || strings.HasPrefix(domain, "localhost:") {
				add("http://" + domain)
			}
		}
	}
	for _, part := range strings.Split(os.Getenv("CHAT_ALLOWED_ORIGINS"), ",") {
		add(part)
	}

	// H27: never trust client X-Forwarded-Host. Request Host is nginx $host / local.
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	host := strings.TrimSpace(strings.Split(r.Host, ",")[0])
	if host != "" {
		add(proto + "://" + host)
	}
	return out
}
