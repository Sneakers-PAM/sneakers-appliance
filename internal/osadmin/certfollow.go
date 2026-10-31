// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// CertSettle is how long the box's names must hold still, with no network
// change waiting, before they cost a certificate. After a boot the
// addresses arrive one at a time, and a lease can flap; each new certificate
// is a fingerprint an admin has to check again.
const CertSettle = 30 * time.Second

// certRetry is how long the follower waits to look again when it can't
// tell, or can't finish.
const certRetry = time.Minute

// certChangeShown is how long Status keeps the note about a changed
// certificate: long enough for a lease that moved on a Friday night.
const certChangeShown = 7 * 24 * time.Hour

// certFollower holds the certificate follower's state.
type certFollower struct {
	// mu serialises FollowCerts.
	mu sync.Mutex
	// names is the set of names it's waiting on, seen from since (on the
	// monotonic clock, so a clock step doesn't shorten the wait).
	names string
	since time.Duration
	// timerMu guards timer, the next look.
	timerMu sync.Mutex
	timer   clock.Timer
}

// FollowCerts keeps the box's own self-signed certificate on the box's
// names (docs/certificates.md#following-the-box). accessd calls it at start,
// on each of netd's address and host name events, and every minute, which
// is also what finds a certificate near its end.
//
// A change that waits for its confirm, or that netd can't be asked about,
// holds the certificate, so a change that reverts never reaches it and
// the fingerprint an admin checked stays. A certificate an owner assigned
// is never replaced.
func (s *Server) FollowCerts(ctx context.Context) {
	if s.o.Certs == nil {
		return
	}
	f := &s.certFollow
	f.mu.Lock()
	defer f.mu.Unlock()
	need, err := s.o.Certs.OwnNeed(ctx)
	if err != nil {
		s.o.Logger.Warn("osadmin: the box's names can't be read; the certificate stays for now", log.F("error", err.Error()))
		s.lookAtCerts(certRetry)
		return
	}
	if need.Reason == "" {
		f.names = ""
	} else if wait, hold := s.certWait(ctx, need); hold {
		s.lookAtCerts(wait)
		return
	}
	c, err := s.o.Certs.FollowOwn(ctx)
	if err != nil {
		s.o.Logger.Warn("osadmin: the box's certificate didn't follow fully; looking again", log.F("error", err.Error()))
		s.lookAtCerts(certRetry)
	}
	if c.New == "" {
		return
	}
	f.names = ""
	s.auditCertChange(c)
	s.consoleChanged()
}

// certWait says how long need has to wait, if it does. The caller holds
// certFollow.mu.
func (s *Server) certWait(ctx context.Context, need certstore.OwnNeed) (time.Duration, bool) {
	f, lg := &s.certFollow, s.o.Logger
	if s.o.Network != nil {
		g, err := s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
		if err != nil {
			f.names = ""
			lg.Warn("osadmin: netd doesn't answer; the certificate waits", log.F("error", err.Error()))
			return certRetry, true
		}
		if g.Msg.GetPending() {
			f.names = ""
			wait := time.Duration(g.Msg.GetSecondsLeft()+1) * time.Second
			lg.Info("osadmin: the certificate waits for the network change's confirm", log.F("change", g.Msg.GetChangeId()), log.F("wait", wait.String()))
			return wait, true
		}
	}
	if need.Reason == certstore.OwnExpiring {
		return 0, false
	}
	now := s.o.Clock.Mono()
	if f.names != need.Names {
		f.names, f.since = need.Names, now
		lg.Debug("osadmin: the box's names moved; the certificate waits for them to settle", log.F("names", need.Names), log.F("reason", string(need.Reason)))
	}
	if left := CertSettle - (now - f.since); left > 0 {
		return left, true
	}
	return 0, false
}

// lookAtCerts runs the follower after d; a later call replaces an earlier
// one.
func (s *Server) lookAtCerts(d time.Duration) {
	f := &s.certFollow
	f.timerMu.Lock()
	defer f.timerMu.Unlock()
	if f.timer != nil {
		f.timer.Stop()
	}
	f.timer = s.o.Clock.AfterFunc(d, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.FollowCerts(ctx)
	})
}

func (s *Server) auditCertChange(c certstore.OwnChange) {
	s.write(osaudit.Entry{Actor: "box", Action: "tls.selfsigned.replace", Target: certTarget(c), Detail: map[string]string{
		"old": c.Old, "new": c.New, "reason": string(c.Reason), "restored": strconv.FormatBool(c.Restored),
		"names": strings.Join(c.Names, ","), "endpoints": strings.Join(c.Endpoints, ","), "surface": "box",
	}}, nil)
}

func certTarget(c certstore.OwnChange) string {
	if len(c.Names) == 0 {
		return "the box's own certificate"
	}
	return "certificate " + strings.Join(c.Names, ", ")
}

// tlsChange is the note Status carries about the last change to the box's
// own certificate, while it's recent.
func (s *Server) tlsChange() (*osadminv1.TlsChange, string) {
	if s.o.Certs == nil {
		return nil, ""
	}
	c, ok := s.o.Certs.LastOwnChange()
	if !ok || !s.o.Clock.Now().Before(c.At.Add(certChangeShown)) {
		return nil, ""
	}
	at := c.At.UTC().Format("2006-01-02 15:04 UTC")
	detail := fmt.Sprintf("The box replaced its own certificate at %s because %s. Browsers that trusted the old one ask again; check the new fingerprint against the console.", at, certReasonWords(c.Reason))
	if c.Restored {
		detail = fmt.Sprintf("The box put its earlier certificate back at %s because %s. A browser that trusted that one takes it again.", at, certReasonWords(c.Reason))
	}
	return &osadminv1.TlsChange{At: timestamppb.New(c.At), OldFingerprint: c.Old, NewFingerprint: c.New, Reason: string(c.Reason), Restored: c.Restored}, detail
}

func certReasonWords(r certstore.OwnReason) string {
	switch r {
	case certstore.OwnHostName:
		return "its host name changed"
	case certstore.OwnExpiring:
		return "the old one was near its end"
	}
	return "its addresses changed"
}
