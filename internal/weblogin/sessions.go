// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package weblogin

import (
	"slices"
	"sync"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
)

// The session limits.
const (
	IdleTimeout = 15 * time.Minute
	MaxAge      = 8 * time.Hour
	MaxPerAdmin = 5
	// StepUpAge is how old a sign-in may be for a sensitive action.
	StepUpAge = 5 * time.Minute
)

// Session is a signed-in browser.
type Session struct {
	ID        string
	CSRF      string
	Admin     string
	KeyFP     string
	Source    string
	UserAgent string
	SignedIn  time.Time
	LastSeen  time.Time
}

// IdleExpires is when the session ends without another call.
func (s Session) IdleExpires() time.Time { return s.LastSeen.Add(IdleTimeout) }

// Expires is the absolute end.
func (s Session) Expires() time.Time { return s.SignedIn.Add(MaxAge) }

// StepUpUntil is when sensitive actions need a fresh sign-in.
func (s Session) StepUpUntil() time.Time { return s.SignedIn.Add(StepUpAge) }

// Sessions is the in-memory session table.
type Sessions struct {
	clk  clock.Clock
	mu   sync.Mutex
	byID map[string]*Session
}

// NewSessions returns an empty table on clk.
func NewSessions(clk clock.Clock) *Sessions {
	return &Sessions{clk: clk, byID: map[string]*Session{}}
}

// Create starts a session. When the admin already has MaxPerAdmin, the
// oldest one ends.
func (t *Sessions) Create(admin, keyFP, source, userAgent string) Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clk.Now()
	s := &Session{ID: Secret(), CSRF: Secret(), Admin: admin, KeyFP: keyFP, Source: source, UserAgent: userAgent, SignedIn: now, LastSeen: now}
	mine := t.of(admin)
	for len(mine) >= MaxPerAdmin {
		delete(t.byID, mine[0].ID)
		mine = mine[1:]
	}
	t.byID[s.ID] = s
	return *s
}

// Get returns a live session and moves its idle timeout.
func (t *Sessions) Get(id string) (Session, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[id]
	if !ok {
		return Session{}, false
	}
	now := t.clk.Now()
	if !now.Before(s.IdleExpires()) || !now.Before(s.Expires()) {
		delete(t.byID, id)
		return Session{}, false
	}
	s.LastSeen = now
	return *s, true
}

// Fresh reports whether s may take a sensitive action.
func (t *Sessions) Fresh(s Session) bool { return t.clk.Now().Before(s.StepUpUntil()) }

// End ends one session.
func (t *Sessions) End(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byID, id)
}

// EndWhere ends every session match accepts and returns how many.
func (t *Sessions) EndWhere(match func(Session) bool) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for id, s := range t.byID {
		if match(*s) {
			delete(t.byID, id)
			n++
		}
	}
	return n
}

// Of returns the admin's live sessions, oldest first.
func (t *Sessions) Of(admin string) []Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Session
	for _, s := range t.of(admin) {
		out = append(out, *s)
	}
	return out
}

// All returns every live session, oldest first.
func (t *Sessions) All() []Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clk.Now()
	var out []Session
	for _, s := range t.byID {
		if now.Before(s.IdleExpires()) && now.Before(s.Expires()) {
			out = append(out, *s)
		}
	}
	slices.SortFunc(out, func(a, b Session) int { return a.SignedIn.Compare(b.SignedIn) })
	return out
}

func (t *Sessions) of(admin string) []*Session {
	now := t.clk.Now()
	var out []*Session
	for id, s := range t.byID {
		if !now.Before(s.IdleExpires()) || !now.Before(s.Expires()) {
			delete(t.byID, id)
			continue
		}
		if s.Admin == admin {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b *Session) int {
		if c := a.SignedIn.Compare(b.SignedIn); c != 0 {
			return c
		}
		return a.LastSeen.Compare(b.LastSeen)
	})
	return out
}
