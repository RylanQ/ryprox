// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/rylanq/ryprox/internal/config"
	"github.com/rylanq/ryprox/internal/importer"
	"github.com/rylanq/ryprox/internal/store"
)

const maxImportBytes = 64 << 20

type importItem struct {
	importer.Proposal
	Problem string `json:"problem,omitempty"` // why it can't be imported as is
}

// handleImportNPM reads an uploaded Nginx Proxy Manager database and returns
// proposed routes. Nothing is saved: the dashboard shows the list and
// creates the routes the admin picks through the normal route API.
func (s *Server) handleImportNPM(w http.ResponseWriter, r *http.Request, me *store.User, _ *store.Session) {
	f, err := os.CreateTemp("", "ryprox-import-*.sqlite")
	if err != nil {
		s.writeErr(w, err)
		return
	}
	defer func() { _ = os.Remove(f.Name()) }()
	n, err := io.Copy(f, io.LimitReader(r.Body, maxImportBytes+1))
	_ = f.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "the upload didn't finish; please try again")
		return
	}
	if n > maxImportBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "that file is too big for a Nginx Proxy Manager database")
		return
	}
	props, err := importer.NPM(r.Context(), f.Name())
	if err != nil {
		writeError(w, http.StatusBadRequest, "couldn't read that file. Upload database.sqlite from Nginx Proxy Manager's data folder.")
		return
	}
	existing, err := s.Store.ListRoutes(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	taken := map[string]bool{}
	for _, rt := range existing {
		taken[rt.Hostname] = true
	}
	out := []importItem{}
	for _, p := range props {
		item := importItem{Proposal: p}
		if !item.Route.Config.Access.IsPublic() {
			item.Route.Config.Access.Users = []int64{me.ID}
		}
		if err := config.NormalizeRoute(&item.Route); err != nil {
			var fe *config.FieldError
			if errors.As(err, &fe) {
				item.Problem = fe.Message
			} else {
				item.Problem = err.Error()
			}
		} else if taken[item.Route.Hostname] {
			item.Problem = "a route for this domain already exists"
		}
		out = append(out, item)
	}
	s.audit(r, me.Username, "import.preview", "Nginx Proxy Manager")
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
