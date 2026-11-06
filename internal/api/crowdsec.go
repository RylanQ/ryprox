// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rylanq/ryprox/internal/crowdsec"
	"github.com/rylanq/ryprox/internal/store"
)

const (
	crowdsecKey     = "crowdsec"
	crowdsecSecPurp = "crowdsec-api-key"
)

func (s *Server) crowdsecConfig(ctx context.Context) (crowdsec.Config, error) {
	var c crowdsec.Config
	raw, err := s.Store.GetJSONSetting(ctx, crowdsecKey)
	if err != nil || raw == "" {
		return c, err
	}
	err = json.Unmarshal([]byte(raw), &c)
	return c, err
}

// startCrowdSec applies the saved CrowdSec settings at startup.
func (s *Server) startCrowdSec(ctx context.Context) {
	if s.CrowdSec == nil {
		return
	}
	c, err := s.crowdsecConfig(ctx)
	if err != nil || !c.Enabled {
		return
	}
	key, err := s.Box.Open(c.APIKey, crowdsecSecPurp)
	if err != nil {
		s.Log.Error("could not unlock the CrowdSec API key", "err", err)
		return
	}
	c.APIKey = key
	s.CrowdSec.Configure(c)
}

func (s *Server) handleGetCrowdSec(w http.ResponseWriter, r *http.Request, _ *store.User, _ *store.Session) {
	c, err := s.crowdsecConfig(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	var st crowdsec.Status
	if s.CrowdSec != nil {
		st = s.CrowdSec.Status()
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": c.Enabled, "url": c.URL, "hasKey": c.APIKey != "", "status": st})
}

func (s *Server) handlePutCrowdSec(w http.ResponseWriter, r *http.Request, u *store.User, _ *store.Session) {
	var in crowdsec.Config
	if !readJSON(w, r, &in) {
		return
	}
	old, err := s.crowdsecConfig(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	plainKey := in.APIKey
	if plainKey == "" && old.APIKey != "" && old.URL == in.URL {
		if plainKey, err = s.Box.Open(old.APIKey, crowdsecSecPurp); err != nil {
			s.writeErr(w, err)
			return
		}
	}
	live := crowdsec.Config{Enabled: in.Enabled, URL: in.URL, APIKey: plainKey}
	if err := crowdsec.Check(live); err != nil {
		field := "url"
		if live.URL != "" && plainKey == "" {
			field = "apiKey"
		}
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error(), Field: field})
		return
	}
	saved := crowdsec.Config{Enabled: in.Enabled, URL: in.URL}
	if plainKey != "" {
		if saved.APIKey, err = s.Box.Seal(plainKey, crowdsecSecPurp); err != nil {
			s.writeErr(w, err)
			return
		}
	}
	b, _ := json.Marshal(saved)
	if err := s.Store.SetJSONSetting(r.Context(), crowdsecKey, string(b)); err != nil {
		s.writeErr(w, err)
		return
	}
	if s.CrowdSec != nil {
		s.CrowdSec.Configure(live)
	}
	what := "off"
	if in.Enabled {
		what = "on, " + in.URL
	}
	s.audit(r, u.Username, "settings.crowdsec", what)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
