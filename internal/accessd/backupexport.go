// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"errors"
	"net/http"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path
	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// serveBackupExport is the closed shell's "<product> backup export": the set,
// encrypted to the recovery keys, as a response body. The ticket came from
// PrepareBackupExport, which took the owner's new code.
func (s *Server) serveBackupExport(w http.ResponseWriter, r *http.Request) {
	l, err := s.caller(r.Context(), r.Header, accessapi.BackupExportPath)
	if err != nil {
		msg := err.Error()
		var ce *connect.Error
		if errors.As(err, &ce) {
			msg = ce.Message()
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := s.api.WriteBackupExport(r.Context(), w, l, r.URL.Query().Get("ticket")); err != nil {
		s.o.Logger.Warn("accessd: the backup export stopped", log.F("admin", l.Admin), log.F("error", err.Error()))
		http.Error(w, codes.Describe(err), http.StatusForbidden)
	}
}
