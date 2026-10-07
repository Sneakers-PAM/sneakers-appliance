// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package weblogin holds the :8443 sign-in codes and browser sessions
// (spec 2, Section 2.6). A browser asks for a code, the admin approves it
// over SSH, and the waiting browser gets a session bound to the admin and
// the key that approved it. Everything is kept in memory: a restart signs
// everyone out.
package weblogin

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The sign-in limits.
const (
	CodeLifetime = 5 * time.Minute
	// MaxPending caps the codes waiting at once, since asking for one needs
	// no sign-in.
	MaxPending = 64
)

// alphabet leaves out 0, 1, I and O, which read alike.
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// State is where a code is, as its browser sees it.
type State int

// The states.
const (
	Pending State = iota + 1
	Approved
	// Expired covers expired, used and unknown codes.
	Expired
)

// Code is a freshly issued sign-in code.
type Code struct {
	Code      string
	PollToken string
	Expires   time.Time
	Source    string
	UserAgent string
}

// Approval is who approved a code.
type Approval struct {
	Admin     string
	KeyFP     string
	Source    string
	UserAgent string
}

type pending struct {
	Code
	approval *Approval
}

// Manager issues and approves codes.
type Manager struct {
	clk    clock.Clock
	mu     sync.Mutex
	byCode map[string]*pending
	byPoll map[string]*pending
}

// New returns a manager on clk.
func New(clk clock.Clock) *Manager {
	return &Manager{clk: clk, byCode: map[string]*pending{}, byPoll: map[string]*pending{}}
}

// Begin issues a code for a browser at source with userAgent.
func (m *Manager) Begin(source, userAgent string) (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune()
	if len(m.byCode) >= MaxPending {
		return Code{}, codes.New(codes.LoginCode, "too many sign-ins are waiting; try again in a few minutes")
	}
	var code string
	for {
		code = newCode()
		if _, taken := m.byCode[code]; !taken {
			break
		}
	}
	p := &pending{Code: Code{Code: code, PollToken: Secret(), Expires: m.clk.Now().Add(CodeLifetime), Source: source, UserAgent: userAgent}}
	m.byCode[code] = p
	m.byPoll[p.PollToken] = p
	return p.Code, nil
}

// Describe returns the browser a code was issued to, for the approval
// prompt.
func (m *Manager) Describe(code string) (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.live(code)
	if err != nil {
		return Code{}, err
	}
	return p.Code, nil
}

// Approve binds the waiting browser to admin and the key fingerprint that
// authenticated the SSH session. A code is approved once.
func (m *Manager) Approve(code, admin, keyFP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.live(code)
	if err != nil {
		return err
	}
	p.approval = &Approval{Admin: admin, KeyFP: keyFP, Source: p.Source, UserAgent: p.UserAgent}
	delete(m.byCode, p.Code.Code)
	return nil
}

// Poll reports a code's state to the browser holding its poll token. An
// approval is handed out once; the code is gone after that.
func (m *Manager) Poll(token string) (State, Approval) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byPoll[token]
	if !ok {
		return Expired, Approval{}
	}
	if p.approval != nil {
		delete(m.byPoll, token)
		return Approved, *p.approval
	}
	if !m.clk.Now().Before(p.Expires) {
		m.drop(p)
		return Expired, Approval{}
	}
	return Pending, Approval{}
}

func (m *Manager) live(code string) (*pending, error) {
	p, ok := m.byCode[Normalize(code)]
	if !ok || p.approval != nil {
		return nil, codes.New(codes.LoginCode, "that sign-in code is unknown, used or expired; start again in the browser")
	}
	if !m.clk.Now().Before(p.Expires) {
		m.drop(p)
		return nil, codes.New(codes.LoginCode, "that sign-in code is unknown, used or expired; start again in the browser")
	}
	return p, nil
}

func (m *Manager) drop(p *pending) {
	delete(m.byCode, p.Code.Code)
	delete(m.byPoll, p.PollToken)
}

func (m *Manager) prune() {
	now := m.clk.Now()
	for _, p := range m.byPoll {
		if !now.Before(p.Expires) {
			m.drop(p)
		}
	}
}

// Normalize turns what an admin typed into the XXXX-XXXX form.
func Normalize(code string) string {
	c := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(code)))
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}

func newCode() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(v)%len(alphabet)])
	}
	return string(out)
}

// Secret returns 32 random bytes, base64url.
func Secret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
