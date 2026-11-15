// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// acmeRetry is how long the follower waits to look at cert-manager again
// when it can't read it. While issuing is pending it looks every ten
// seconds, so a new certificate is served soon after the CA issues it.
const (
	acmeRetry   = time.Minute
	acmePending = 10 * time.Second
)

// FollowACME brings every ACME endpoint to what cert-manager has issued
// (docs/certificates.md#acme) and audits what it did. accessd calls it every
// minute, and SetAcme and RenewNow ask for a look at once.
func (s *Server) FollowACME(ctx context.Context) {
	if s.o.Certs == nil {
		return
	}
	f := &s.acmeFollow
	f.mu.Lock()
	defer f.mu.Unlock()
	events, err := s.o.Certs.SyncACME(ctx)
	if err != nil {
		s.o.Logger.Warn("osadmin: ACME: cert-manager can't be read; looking again", log.F("error", err.Error()))
		s.lookAtACME(acmeRetry)
		return
	}
	for _, e := range events {
		s.auditACME(e)
	}
	if s.o.Certs.ACMEPending() {
		s.lookAtACME(acmePending)
	}
}

// lookAtACME runs the follower after d; a later call replaces an earlier
// one.
func (s *Server) lookAtACME(d time.Duration) {
	f := &s.acmeFollow
	f.timerMu.Lock()
	defer f.timerMu.Unlock()
	if f.timer != nil {
		f.timer.Stop()
	}
	f.timer = s.o.Clock.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.FollowACME(ctx)
	})
}

// auditACME writes one follower event: tls.acme.issue and tls.acme.renew
// for a certificate an endpoint took, tls.acme.fail for a problem.
func (s *Server) auditACME(e certstore.ACMEEvent) {
	switch e.Kind {
	case certstore.ACMEIssued, certstore.ACMERenewed:
		action := "tls.acme.issue"
		if e.Kind == certstore.ACMERenewed {
			action = "tls.acme.renew"
		}
		s.write(osaudit.Entry{Actor: "box", Action: action, Target: "endpoint " + e.Endpoint, Detail: map[string]string{
			"endpoint": e.Endpoint, "fingerprint": e.Fingerprint, "expires": e.Expires.UTC().Format(time.RFC3339),
			"names": strings.Join(e.Names, ","), "surface": "box",
		}}, nil)
	case certstore.ACMEFailed:
		target := "ACME"
		if e.Endpoint != "" {
			target = "endpoint " + e.Endpoint
		}
		s.write(osaudit.Entry{Actor: "box", Action: "tls.acme.fail", Target: target, Detail: map[string]string{
			"endpoint": e.Endpoint, "reason": e.Message, "surface": "box",
		}}, codes.New(codes.TLSACMEFailed, "%s", e.Message))
	}
}
