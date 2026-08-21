package chat

import (
	"net"
	"net/http"
	"sort"
	"strings"
)

// ClientIP is the address we already trust for this request.
// TCP peer first. X-Forwarded-For is used only when that peer is a
// local/private reverse proxy, and then only the last hop (what the
// proxy appended). A browser-supplied XFF on a public TCP peer is ignored.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	peer := NormalizeIP(r.RemoteAddr)
	if isTrustedProxy(peer) {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			parts := strings.Split(xff, ",")
			last := NormalizeIP(parts[len(parts)-1])
			if last != "" {
				return last
			}
		}
	}
	return peer
}

func isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

// NormalizeIP strips a host:port wrapper and maps IPv4-in-IPv6 to IPv4.
func NormalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// IsBannableIP is a public unicast address. Loopback, RFC1918, link-local,
// unspecified, and multicast are skipped so a LAN demo does not ban the streamer.
func IsBannableIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	return true
}

// ParsePublicICECandidates returns public host/srflx IPs already present
// in an SDP this room accepted. Relay (TURN) and private/loopback are skipped.
func ParsePublicICECandidates(sdp string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "a=")
		if !strings.HasPrefix(strings.ToLower(line), "candidate:") {
			continue
		}
		parts := strings.Fields(line)
		// candidate:foundation component proto prio ip port typ type
		if len(parts) < 8 || !strings.EqualFold(parts[6], "typ") {
			continue
		}
		typ := strings.ToLower(parts[7])
		if typ != "host" && typ != "srflx" {
			continue
		}
		ip := NormalizeIP(parts[4])
		if !IsBannableIP(ip) || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}
