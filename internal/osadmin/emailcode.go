// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The email settings are saved only after a test email proved them (#568):
// the test message carries a one-time code, the admin types it back, and a
// pass for exactly those settings and that password lets SetEmail save
// them. The box enforces it, so a page can't skip the test.
const (
	// emailCodeLife is how long a code, and then the pass it earns, lasts.
	emailCodeLife = 10 * time.Minute
	// emailCodeTries is how many wrong codes drop the pending one.
	emailCodeTries = 5
)

// emailProof is the pending code and the pass, in memory only: a restart
// of the box asks for a new test, which is the safe side.
type emailProof struct {
	mu      sync.Mutex
	salt    []byte
	pending *pendingEmailCode
	pass    *emailPass
}

type pendingEmailCode struct {
	settings [sha256.Size]byte // the settings and password the code was sent with
	code     [sha256.Size]byte // the code, hashed with the salt
	expires  time.Time
	tries    int
}

type emailPass struct {
	settings [sha256.Size]byte
	expires  time.Time
}

// saltLocked is the random salt for this run; the caller holds p.mu.
func (p *emailProof) saltLocked() []byte {
	if p.salt == nil {
		p.salt = make([]byte, 32)
		if _, err := rand.Read(p.salt); err != nil {
			panic(fmt.Sprintf("osadmin: no randomness for the email code: %v", err))
		}
	}
	return p.salt
}

// digestLocked binds a value to this run's salt, length-prefixing each part
// so two settings can't give the same digest.
func (p *emailProof) digestLocked(parts ...string) [sha256.Size]byte {
	h := sha256.New()
	h.Write(p.saltLocked())
	for _, s := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// settingsDigestLocked is the digest of every setting the product would
// read, the password included, as resolved from the form and the saved
// password.
func (p *emailProof) settingsDigestLocked(e boxsettings.Email) [sha256.Size]byte {
	return p.digestLocked(e.Host, strconv.Itoa(e.Port), e.From, e.Username, e.Password, e.TLS, strconv.FormatBool(e.Verify), e.CA, e.PinSHA256)
}

// newCode is a random 6-digit code.
func newEmailCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// issue records a new code for e, replacing any pending one, and drops a
// pass for other settings: a test is a new proof.
func (p *emailProof) issue(e boxsettings.Email, code string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending = &pendingEmailCode{settings: p.settingsDigestLocked(e), code: p.digestLocked("code", code), expires: now.Add(emailCodeLife)}
}

// check takes a typed code for e. A match uses the code up and records a
// pass until the answered time; the errors are coded, and the code is
// never in them.
func (p *emailProof) check(e boxsettings.Email, typed string, now time.Time) (time.Time, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pe := p.pending
	if pe == nil || !now.Before(pe.expires) || pe.settings != p.settingsDigestLocked(e) {
		if pe != nil && !now.Before(pe.expires) {
			p.pending = nil
		}
		return time.Time{}, codes.New(codes.EmailCodeExpired, "no test email code is waiting for these settings; send the test email again")
	}
	got := p.digestLocked("code", typed)
	if subtle.ConstantTimeCompare(got[:], pe.code[:]) != 1 {
		pe.tries++
		if pe.tries >= emailCodeTries {
			p.pending = nil
			return time.Time{}, codes.New(codes.EmailCodeWrong, "the code is wrong; %d wrong tries dropped it, so send the test email again", emailCodeTries)
		}
		return time.Time{}, codes.New(codes.EmailCodeWrong, "the code is wrong; %d tries left", emailCodeTries-pe.tries)
	}
	p.pending = nil
	until := now.Add(emailCodeLife)
	p.pass = &emailPass{settings: pe.settings, expires: until}
	return until, nil
}

// passed reports whether a fresh pass holds for exactly e. Turning the relay
// off (no host) needs none: there's nothing to test.
func (p *emailProof) passed(e boxsettings.Email, now time.Time) bool {
	if !e.Configured() {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pass != nil && now.Before(p.pass.expires) && p.pass.settings == p.settingsDigestLocked(e)
}
