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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/supportbundle"
)

// serveSupportBundle is the closed shell's "support-bundle": the text as
// it's written, over plain HTTP on access.sock, as the login's admin. A
// bundle is a long run of text, so it's a response body, as
// /export/support-bundle is on :8443.
func (s *Server) serveSupportBundle(w http.ResponseWriter, r *http.Request) {
	l, err := s.caller(r.Context(), r.Header, accessapi.SupportBundlePath)
	if err != nil {
		msg := err.Error()
		var ce *connect.Error
		if errors.As(err, &ce) {
			msg = ce.Message()
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	}
	form := supportbundle.Short
	if r.URL.Query().Get("form") == string(supportbundle.Full) {
		form = supportbundle.Full
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err := s.api.WriteSupportBundle(r.Context(), w, l, form); err != nil {
		s.o.Logger.Warn("accessd: the support bundle stopped", log.F("admin", l.Admin), log.F("error", err.Error()))
		if codes.Is(err, codes.NotAvailable) {
			http.Error(w, codes.Describe(err), http.StatusServiceUnavailable)
		}
	}
}
