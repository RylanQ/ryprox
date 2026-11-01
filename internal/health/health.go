// SPDX-License-Identifier: AGPL-3.0-only

// Package health provides the /healthz endpoint used by Docker and monitoring.
package health

import (
	"encoding/json"
	"net/http"
)

// Response is the JSON body returned by the health endpoint.
// It deliberately contains no version or system details, so the
// endpoint can be exposed without leaking information to attackers.
type Response struct {
	Status string `json:"status"`
}

// Handler answers GET and HEAD requests with {"status":"ok"}.
// Any other method gets 405 Method Not Allowed.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(Response{Status: "ok"})
	})
}
