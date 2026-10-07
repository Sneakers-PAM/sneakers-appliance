// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshsession"
)

// Shells is the admins' live SSH logins to the closed shell.
type Shells interface {
	List() ([]sshsession.Session, error)
	End(id string) (sshsession.Session, error)
	// Source is the SSH client address of a process sshd started.
	Source(pid int) string
}

// The id prefixes of each kind of session.
const (
	browserPrefix  = "web-"
	sshPrefix      = "ssh-"
	elevatedPrefix = "elevated-"
)

// browserID names a browser session without giving its cookie away.
func browserID(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return browserPrefix + hex.EncodeToString(sum[:12])
}

type liveSession struct {
	id, admin, source string
	kind              osadminv1.SessionKind
	started           time.Time
}

func (l liveSession) proto() *osadminv1.ActiveSession {
	return &osadminv1.ActiveSession{Id: l.id, Kind: l.kind, Admin: l.admin, SourceAddress: l.source, SignedIn: timestamppb.New(l.started)}
}

// liveSessions is every session on the box, oldest first: the :8443
// browsers, the SSH closed shells and the active elevated shells.
func (s *Server) liveSessions() ([]liveSession, error) {
	var out []liveSession
	for _, b := range s.sessions.All() {
		out = append(out, liveSession{id: browserID(b.ID), kind: osadminv1.SessionKind_SESSION_KIND_BROWSER, admin: b.Admin, source: b.Source, started: b.SignedIn})
	}
	if s.o.Shells != nil {
		shells, err := s.o.Shells.List()
		if err != nil {
			return out, err
		}
		for _, sh := range shells {
			out = append(out, liveSession{id: sh.ID, kind: osadminv1.SessionKind_SESSION_KIND_SSH, admin: sh.Admin, source: sh.Source, started: sh.Started})
		}
	}
	if s.o.Elevation != nil {
		// Sweep first, so a shell whose process is gone isn't listed.
		s.o.Elevation.Sweep()
		for _, r := range s.o.Elevation.List() {
			if r.State != elevation.Active || r.Started == nil {
				continue
			}
			src := r.Source
			if s.o.Shells != nil {
				if live := s.o.Shells.Source(r.PID); live != "" {
					src = live
				}
			}
			out = append(out, liveSession{id: elevatedPrefix + r.ID, kind: osadminv1.SessionKind_SESSION_KIND_ELEVATED, admin: r.Admin, source: src, started: *r.Started})
		}
	}
	slices.SortStableFunc(out, func(a, b liveSession) int { return a.started.Compare(b.started) })
	return out, nil
}

func (h *power) ListSessions(context.Context, *connect.Request[osadminv1.ListSessionsRequest]) (*connect.Response[osadminv1.ListSessionsResponse], error) {
	live, err := h.s.liveSessions()
	if err != nil {
		h.s.o.Logger.Error(err, "osadmin: the SSH sessions can't be read")
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the SSH sessions can't be read right now; try again"))
	}
	out := &osadminv1.ListSessionsResponse{}
	for _, l := range live {
		out.Sessions = append(out.Sessions, l.proto())
	}
	return connect.NewResponse(out), nil
}

var errNoSession = errors.New("there is no such session; it may have ended already")

func (h *power) EndSession(ctx context.Context, r *connect.Request[osadminv1.EndSessionRequest]) (*connect.Response[osadminv1.EndSessionResponse], error) {
	c := callFrom(ctx)
	id := r.Msg.GetId()
	c.note(id)
	notFound := connect.NewError(connect.CodeNotFound, errNoSession)
	lg := h.s.o.Logger
	switch {
	case strings.HasPrefix(id, browserPrefix):
		for _, b := range h.s.sessions.All() {
			if browserID(b.ID) == id {
				h.s.sessions.End(b.ID)
				c.note(id, "kind", "browser", "admin", b.Admin, "source", b.Source)
				lg.Info("osadmin: browser session ended", log.F("by", c.session.Admin), log.F("admin", b.Admin), log.F("id", id))
				return connect.NewResponse(&osadminv1.EndSessionResponse{}), nil
			}
		}
	case strings.HasPrefix(id, sshPrefix) && h.s.o.Shells != nil:
		sh, err := h.s.o.Shells.End(id)
		if errors.Is(err, sshsession.ErrNotFound) {
			return nil, notFound
		}
		c.note(id, "kind", "ssh", "admin", sh.Admin, "source", sh.Source)
		if err != nil {
			return nil, err
		}
		lg.Info("osadmin: SSH session ended", log.F("by", c.session.Admin), log.F("admin", sh.Admin), log.F("id", id))
		return connect.NewResponse(&osadminv1.EndSessionResponse{}), nil
	case strings.HasPrefix(id, elevatedPrefix) && h.s.o.Elevation != nil:
		rid := strings.TrimPrefix(id, elevatedPrefix)
		cur, ok := h.s.o.Elevation.Get(rid)
		if !ok || cur.State != elevation.Active {
			return nil, notFound
		}
		c.note(id, "kind", "elevated", "admin", cur.Admin, "source", cur.Source)
		if _, err := h.s.o.Elevation.Terminate(rid, c.session.Admin); err != nil {
			return nil, err
		}
		lg.Info("osadmin: elevated shell ended", log.F("by", c.session.Admin), log.F("admin", cur.Admin), log.F("id", id))
		return connect.NewResponse(&osadminv1.EndSessionResponse{}), nil
	}
	return nil, notFound
}
