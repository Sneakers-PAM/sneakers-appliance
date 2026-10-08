// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package onetime

import (
	"crypto/subtle"
	"encoding/json"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The code limits (spec 2, Sections 2.2 and 2.10).
const (
	// SetupLifetime is how long a setup code works.
	SetupLifetime = 60 * time.Minute
	// RecoverLifetime is how long a Recover access code works: the same
	// rules as the setup code.
	RecoverLifetime = SetupLifetime
	// MaxAttempts is the wrong tries a code takes. The setup code is then
	// locked out until the console asks for a new one; a Recover access
	// code is withdrawn.
	MaxAttempts = 5
	// Length is a code's length in characters (four groups of four).
	Length = 16
	// SealedName is the KeyCustody item the setup code is sealed as.
	SealedName = "setup-code"
)

// Sealer keeps the sealed setup code: init's KeyCustody on the box.
type Sealer interface {
	Seal(name string, secret []byte) error
	// Unseal returns the item; ok is false when it was never sealed.
	Unseal(name string) (secret []byte, ok bool, err error)
}

// Kind is what a code is for.
type Kind int

// The kinds the console shows.
const (
	KindSetup Kind = iota + 1
	KindRecover
)

// Code is a code as the console shows it.
type Code struct {
	Kind  Kind
	Value string
	// Expires is when a new code replaces it.
	Expires      time.Time
	AttemptsLeft int
	// InUse is set once a browser redeemed it; Source is that browser and
	// Started when.
	InUse    bool
	Source   string
	Started  time.Time
	Consumed bool
	// Locked is set once MaxAttempts wrong tries used the setup code up:
	// none works until the console asks for a new one (ResetSetup).
	Locked bool
}

// Redeemed is a code a browser typed.
type Redeemed struct {
	Kind   Kind
	Source string
}

// Codes holds the setup code and the Recover access code, in accessd
// only. Both are sealed through KeyCustody whenever they change, so a
// restart shows the same codes; the setup code is destroyed for good once
// the first admin exists, and a Recover access code once it is used,
// withdrawn or expired. They are never written anywhere else.
type Codes struct {
	clk      clock.Clock
	onChange func()
	sealer   Sealer
	log      log.Logger

	mu       sync.Mutex
	setup    Code
	consumed bool
	recover  *Code
}

// sealed is the setup code's sealed form.
type sealed struct {
	Value        string    `json:"value,omitempty"`
	Expires      time.Time `json:"expires,omitzero"`
	AttemptsLeft int       `json:"attemptsLeft,omitempty"`
	Used         bool      `json:"used,omitempty"`
	Locked       bool      `json:"locked,omitempty"`
	Destroyed    bool      `json:"destroyed,omitempty"`
	Recover      *Code     `json:"recover,omitempty"`
}

// NewCodes returns the codes; onChange runs (outside the lock) whenever
// what the console shows changes. With a sealer the sealed setup code is
// read back; without one (tests) the code lives in memory.
func NewCodes(clk clock.Clock, onChange func(), sealer Sealer, lg log.Logger) *Codes {
	if onChange == nil {
		onChange = func() {}
	}
	if lg == nil {
		lg = log.Nop()
	}
	c := &Codes{clk: clk, onChange: onChange, sealer: sealer, log: lg}
	c.load()
	return c
}

func (c *Codes) load() {
	if c.sealer == nil {
		return
	}
	b, ok, err := c.sealer.Unseal(SealedName)
	if err != nil {
		c.log.Warn("onetime: the sealed setup code doesn't unseal; making a new one", log.F("error", err.Error()))
		return
	}
	if !ok {
		return
	}
	var v sealed
	if err := json.Unmarshal(b, &v); err != nil {
		c.log.Warn("onetime: the sealed setup code doesn't parse; making a new one")
		return
	}
	switch {
	case v.Destroyed:
		c.consumed = true
	case v.Used:
		// A redeemed code is single-use: its browser session didn't survive
		// the restart, so the console shows a new one.
	default:
		c.setup = Code{Kind: KindSetup, Value: v.Value, Expires: v.Expires, AttemptsLeft: v.AttemptsLeft, Locked: v.Locked}
	}
	if r := v.Recover; r != nil && !r.InUse && c.clk.Now().Before(r.Expires) {
		c.recover = r
	}
}

// seal stores the setup code's state. Caller holds mu.
func (c *Codes) seal() error {
	if c.sealer == nil {
		return nil
	}
	v := sealed{Destroyed: c.consumed}
	if !c.consumed {
		v = sealed{Value: c.setup.Value, Expires: c.setup.Expires, AttemptsLeft: c.setup.AttemptsLeft, Used: c.setup.InUse, Locked: c.setup.Locked}
	}
	if c.recover != nil && !c.recover.InUse {
		r := *c.recover
		v.Recover = &r
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.sealer.Seal(SealedName, b)
}

// Setup is the setup code, made first when there is none or it expired.
// Once a browser holds it, or it is locked, Value is empty; once the first
// admin exists (ConsumeSetup), there is none.
func (c *Codes) Setup() Code {
	c.mu.Lock()
	changed := c.refresh()
	out := c.shown()
	c.mu.Unlock()
	if changed {
		c.onChange()
	}
	return out
}

func (c *Codes) shown() Code {
	if c.consumed {
		return Code{Kind: KindSetup, Consumed: true}
	}
	out := c.setup
	if out.InUse || out.Locked {
		out.Value = ""
	}
	return out
}

// refresh makes a setup code when there is none or it expired; a locked one
// stays locked. A code that can't be sealed isn't shown. Caller holds mu.
func (c *Codes) refresh() bool {
	if c.consumed || c.setup.InUse || c.setup.Locked {
		return false
	}
	now := c.clk.Now()
	if c.setup.Value != "" && now.Before(c.setup.Expires) {
		return false
	}
	c.setup = Code{Kind: KindSetup, Value: New(Length), Expires: now.Add(SetupLifetime), AttemptsLeft: MaxAttempts}
	if err := c.seal(); err != nil {
		c.log.Warn("onetime: the setup code can't be sealed; none is shown", log.F("error", err.Error()))
		c.setup = Code{}
	}
	return true
}

// Redeem takes what a browser at source typed. A right code works once; a
// wrong one costs the live codes a try, and the setup code is locked out
// after MaxAttempts.
func (c *Codes) Redeem(typed, source string) (Redeemed, error) {
	got, err := c.redeem(typed, source)
	c.onChange()
	return got, err
}

func (c *Codes) redeem(typed, source string) (Redeemed, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refresh()
	now := c.clk.Now()
	if c.recover != nil && !now.Before(c.recover.Expires) {
		c.recover = nil
	}
	norm, ok := Normalize(typed, Length)
	live := !c.consumed && !c.setup.InUse && !c.setup.Locked && c.setup.Value != ""
	if ok && live && equal(norm, c.setup.Value) {
		c.setup.InUse, c.setup.Source, c.setup.Started = true, source, now
		c.sealOrWarn()
		return Redeemed{Kind: KindSetup, Source: source}, nil
	}
	if ok && c.recover != nil && !c.recover.InUse && equal(norm, c.recover.Value) {
		c.recover.InUse, c.recover.Source, c.recover.Started = true, source, now
		c.sealOrWarn()
		return Redeemed{Kind: KindRecover, Source: source}, nil
	}
	left := 0
	if live {
		c.setup.AttemptsLeft--
		left = c.setup.AttemptsLeft
		if c.setup.AttemptsLeft <= 0 {
			c.setup.Locked = true
		}
		c.sealOrWarn()
	}
	if c.recover != nil && !c.recover.InUse {
		c.recover.AttemptsLeft--
		left = max(left, c.recover.AttemptsLeft)
		if c.recover.AttemptsLeft <= 0 {
			c.recover = nil
		}
		c.sealOrWarn()
	}
	if c.setup.Locked && !c.consumed && left <= 0 {
		return Redeemed{}, codes.New(codes.SetupCode, "too many wrong codes; ask at the console for a new one")
	}
	return Redeemed{}, codes.New(codes.SetupCode, "that code is wrong, used or expired; %d tries left", max(left, 0))
}

func (c *Codes) sealOrWarn() {
	if err := c.seal(); err != nil {
		c.log.Warn("onetime: the setup code's state can't be sealed", log.F("error", err.Error()))
	}
}

// Matches reports whether typed is code, in constant time (for an
// invitation's code checked by its hash elsewhere, and the root-shell code).
func Matches(typed, code string, n int) bool {
	norm, ok := Normalize(typed, n)
	return ok && equal(norm, code)
}

func equal(a, b string) bool { return b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ResetSetup stops the browser holding the setup code, clears a lockout and
// shows a new code, until the first admin exists.
func (c *Codes) ResetSetup() {
	c.mu.Lock()
	if c.consumed {
		c.mu.Unlock()
		return
	}
	c.setup = Code{}
	c.refresh()
	c.mu.Unlock()
	c.onChange()
}

// ConsumeSetup destroys the setup code for good: the first admin exists.
// The sealed item is overwritten with a marker that holds no code.
func (c *Codes) ConsumeSetup() {
	c.mu.Lock()
	c.consumed, c.setup = true, Code{}
	c.sealOrWarn()
	c.mu.Unlock()
	c.onChange()
}

// BeginRecover issues a Recover access code, replacing one already out.
func (c *Codes) BeginRecover() Code {
	c.mu.Lock()
	r := Code{Kind: KindRecover, Value: New(Length), Expires: c.clk.Now().Add(RecoverLifetime), AttemptsLeft: MaxAttempts}
	c.recover = &r
	if err := c.seal(); err != nil {
		c.log.Warn("onetime: the Recover access code can't be sealed; none is shown", log.F("error", err.Error()))
		c.recover, r = nil, Code{}
	}
	c.mu.Unlock()
	c.onChange()
	return r
}

// Recover is the live Recover access code; ok is false when there is none.
func (c *Codes) Recover() (Code, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recover == nil || !c.clk.Now().Before(c.recover.Expires) {
		c.recover = nil
		return Code{}, false
	}
	return *c.recover, true
}

// CancelRecover withdraws the Recover access code.
func (c *Codes) CancelRecover() {
	c.mu.Lock()
	c.recover = nil
	c.sealOrWarn()
	c.mu.Unlock()
	c.onChange()
}

// EndRecover ends a redeemed Recover access code once its credentials are
// set.
func (c *Codes) EndRecover() { c.CancelRecover() }
