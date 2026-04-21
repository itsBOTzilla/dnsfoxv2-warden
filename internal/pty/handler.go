// handler.go — HTTP surface for the PTY bridge.
//
// Route: GET /api/pty/{site_id}
// Auth:  X-Warden-Internal-Token header must match WARDEN_INTERNAL_TOKEN.
//        Only the v2 API is expected to reach this endpoint — customer
//        browsers speak to the API, which proxies the WebSocket here.
//
// Upgrades the request to WebSocket and hands off to Session.Start.
package pty

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// upgrader is shared — our origin check is custom because the API speaks to us
// over the private network, not through a browser's same-origin model.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Permit any origin; this endpoint is locked down by the bearer token.
	CheckOrigin: func(*http.Request) bool { return true },
}

// Handler returns an http.Handler guarded by the internal bearer token.
// token is matched in constant time against the X-Warden-Internal-Token header.
func Handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if token == "" {
			http.Error(w, "pty not configured", http.StatusServiceUnavailable)
			return
		}
		got := r.Header.Get("X-Warden-Internal-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		siteID := siteIDFromPath(r.URL.Path)
		if siteID == "" {
			http.Error(w, "site_id required", http.StatusBadRequest)
			return
		}
		username := provisioning.SiteUsername(siteID)

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[pty] upgrade failed: %v", err)
			return
		}

		if err := Start(ws, username); err != nil {
			log.Printf("[pty] session ended with error: %v", err)
		}
	})
}

// siteIDFromPath extracts <id> from /api/pty/<id>.
func siteIDFromPath(p string) string {
	const prefix = "/api/pty/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	id := p[len(prefix):]
	// Disallow further path segments.
	if strings.ContainsAny(id, "/?#") {
		return ""
	}
	return id
}
