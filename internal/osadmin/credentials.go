// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// The credential flow limits.
const (
	// CodeSessionLifetime is how long a redeemed code's session lasts
	// without a call.
	CodeSessionLifetime = 30 * time.Minute
	// InviteLifetime is how long an invitation's code works.
	InviteLifetime = 24 * time.Hour
	// EnrolmentLifetime is how long a new TOTP secret waits for its first
	// code.
	EnrolmentLifetime = 10 * time.Minute
)

// FirstAdminMarker records that the first admin exists, first boot's admin
// step.
const FirstAdminMarker = "first-admin"

// codeSession is a browser that redeemed a one-time code.
type codeSession struct {
	ID, CSRF string
	Kind     osadminv1.CodeKind
	// Admin is fixed for an invitation; empty while the name is chosen.
	Admin   string
	Source  string
	Started time.Time
	Expires time.Time
}

// actor is how a code session is named in the audit log.
func (c codeSession) actor() string {
	switch c.Kind {
	case osadminv1.CodeKind_CODE_KIND_SETUP:
		return "setup"
	case osadminv1.CodeKind_CODE_KIND_RECOVER:
		return "recover-access"
	}
	return c.Admin
}

// enrolment is a password and a new TOTP secret waiting for the secret's
// first code.
type enrolment struct {
	ID       string
	Admin    string
	Hash     string
	Secret   []byte
	Expires  time.Time
	CodeID   string
	Session  string
	Replaces bool
}

type credentialFlows struct {
	mu        sync.Mutex
	sessions  map[string]*codeSession
	enrolling map[string]*enrolment
}

func (f *credentialFlows) init() {
	f.sessions = map[string]*codeSession{}
	f.enrolling = map[string]*enrolment{}
}

// codeSessionOf returns the live code session named by the request's
// cookie, moving its expiry.
func (s *Server) codeSessionOf(h http.Header) (codeSession, error) {
	r := http.Request{Header: h}
	ck, err := r.Cookie(CodeCookieName)
	if err != nil || ck.Value == "" {
		return codeSession{}, codes.New(codes.AccessSession, "type the one-time code first")
	}
	now := s.o.Clock.Now()
	s.creds.mu.Lock()
	cs, ok := s.creds.sessions[ck.Value]
	if ok && !now.Before(cs.Expires) {
		delete(s.creds.sessions, ck.Value)
		ok = false
	}
	var out codeSession
	if ok {
		cs.Expires = now.Add(CodeSessionLifetime)
		out = *cs
	}
	s.creds.mu.Unlock()
	if !ok {
		s.expireSetupSession()
		return codeSession{}, codes.New(codes.AccessSession, "the one-time code's session has ended; type a new code")
	}
	return out, nil
}

// expireSetupSession gives the console a new setup code when the browser
// that held the old one went quiet before making the first admin.
func (s *Server) expireSetupSession() {
	now := s.o.Clock.Now()
	s.creds.mu.Lock()
	live := false
	for id, cs := range s.creds.sessions {
		if !now.Before(cs.Expires) {
			delete(s.creds.sessions, id)
			continue
		}
		if cs.Kind == osadminv1.CodeKind_CODE_KIND_SETUP {
			live = true
		}
	}
	s.creds.mu.Unlock()
	if sc := s.codes.Setup(); sc.InUse && !live && !s.FirstAdminDone() {
		s.o.Logger.Info("osadmin: the setup browser went quiet; a new setup code is shown")
		s.codes.ResetSetup()
	}
}

func (s *Server) endCodeSession(id string) {
	s.creds.mu.Lock()
	delete(s.creds.sessions, id)
	s.creds.mu.Unlock()
}

// endSetupSessions ends every setup-code session: the console stopped the
// setup.
func (s *Server) endSetupSessions() int {
	s.creds.mu.Lock()
	defer s.creds.mu.Unlock()
	n := 0
	for id, cs := range s.creds.sessions {
		if cs.Kind == osadminv1.CodeKind_CODE_KIND_SETUP {
			delete(s.creds.sessions, id)
			n++
		}
	}
	return n
}

// liveSetupSession is the setup browser's session, for the console.
func (s *Server) liveSetupSession() (codeSession, bool) {
	now := s.o.Clock.Now()
	s.creds.mu.Lock()
	defer s.creds.mu.Unlock()
	for _, cs := range s.creds.sessions {
		if cs.Kind == osadminv1.CodeKind_CODE_KIND_SETUP && now.Before(cs.Expires) {
			return *cs, true
		}
	}
	return codeSession{}, false
}

// FirstAdminDone reports whether the first admin exists.
func (s *Server) FirstAdminDone() bool {
	return exists(filepath.Join(s.o.Paths.SetupDir(), FirstAdminMarker)) || s.SetupDone()
}

// codeHash is how an invitation's code is kept.
func codeHash(code string) string {
	sum := sha256.Sum256([]byte("sneakers-appliance invite v1\x00" + code))
	return hex.EncodeToString(sum[:])
}

// redeemInvite finds the admin whose open invitation code is typed.
func redeemInvite(st access.State, typed string, now time.Time) (string, bool) {
	norm, ok := onetime.Normalize(typed, onetime.Length)
	if !ok {
		return "", false
	}
	h := codeHash(norm)
	for _, a := range st.Admins {
		if a.Invite != nil && now.Before(a.Invite.Expires) && subtle.ConstantTimeCompare([]byte(a.Invite.CodeHash), []byte(h)) == 1 {
			return a.Name, true
		}
	}
	return "", false
}

// newInvite makes an invitation for admin: the code to show once, and what
// the store keeps.
func (s *Server) newInvite() (string, *access.Invite) {
	code := onetime.New(onetime.Length)
	return code, &access.Invite{CodeHash: codeHash(code), Expires: s.o.Clock.Now().UTC().Add(InviteLifetime)}
}

func (s *Server) lockoutMode() lockout.Mode {
	if s.o.Access.Read().AccessPolicy.Effective().LockoutMode == access.LockoutUntilUnlocked {
		return lockout.UntilUnlocked
	}
	return lockout.Timed
}

// checkTOTP checks a fresh TOTP code of admin's against the lockout. Every
// failure counts, every lock is audited, and the refusal (why) says what is
// left.
func (s *Server) checkTOTP(a *access.Admin, code, source, surface, why string) error {
	now := s.o.Clock.Now()
	if err := s.o.Lockout.Check(a.Name, source, now); err != nil {
		return err
	}
	secret, err := credentials.OpenTOTP(s.o.RootKey.Pepper(), a.Name, a.TOTP.Sealed)
	if err != nil {
		s.o.Logger.Error(err, "osadmin: an admin's TOTP secret doesn't open", log.F("admin", a.Name))
		return codes.New(codes.AccessCredentials, "the authenticator can't be checked; use Recover access on the console")
	}
	step, ok := credentials.VerifyTOTP(secret, code, now, s.o.Lockout.LastStep(a.Name))
	if !ok {
		return s.failed(a.Name, source, surface, why)
	}
	s.o.Lockout.SetStep(a.Name, step)
	s.o.Lockout.Succeed(a.Name, now)
	return nil
}

// wrongCode is the refusal of a wrong or reused TOTP code.
const wrongCode = "the authenticator code is wrong or was used already"

// failed records a failed try of admin's (empty for an unknown name) from
// source, audits the lock or throttle it causes, and returns the refusal.
func (s *Server) failed(admin, source, surface, why string) error {
	r := s.o.Lockout.Fail(admin, source, s.o.Clock.Now(), s.lockoutMode())
	detail := map[string]string{"surface": surface, "attemptsLeft": itoa(r.AttemptsLeft)}
	switch {
	case r.UntilUnlocked || !r.LockedUntil.IsZero():
		if !r.LockedUntil.IsZero() {
			detail["until"] = r.LockedUntil.UTC().Format(time.RFC3339)
		} else {
			detail["until"] = "unlocked"
		}
		s.write(osaudit.Entry{Actor: "accessd", Source: source, Action: "access.lockout", Target: admin, Detail: detail}, nil)
		s.o.Logger.Warn("osadmin: an account locked", log.F("admin", admin), log.F("source", source))
	case !r.RetryAfter.IsZero():
		detail["until"] = r.RetryAfter.UTC().Format(time.RFC3339)
		s.write(osaudit.Entry{Actor: "accessd", Source: source, Action: "access.throttle", Target: source, Detail: detail}, nil)
		s.o.Logger.Warn("osadmin: a source throttled", log.F("source", source))
	}
	if r.AttemptsLeft > 0 {
		why += "; " + itoa(r.AttemptsLeft) + " tries left"
	}
	return lockout.WithRefusal(codes.New(codes.AccessCredentials, "%s", why), r)
}

// newSession signs the browser in as admin and records the sign-in.
func (s *Server) newSession(a access.Admin, source, userAgent string) (weblogin.Session, []string) {
	sess := s.sessions.Create(a.Name, source, userAgent)
	var notices []string
	st := s.o.Access.Read()
	if st.LastRecoverAccess != nil && (a.LastSignIn == nil || st.LastRecoverAccess.After(*a.LastSignIn)) {
		notices = append(notices, "The console's Recover access was used at "+st.LastRecoverAccess.UTC().Format(time.RFC3339)+". Check the OS audit log.")
	}
	now := s.o.Clock.Now().UTC()
	if err := s.o.Access.Update(func(st *access.State) error {
		if x, ok := st.Admin(a.Name); ok {
			x.LastSignIn = &now
		}
		return nil
	}); err != nil {
		s.o.Logger.Warn("osadmin: the sign-in time wasn't recorded", log.F("admin", a.Name), log.F("error", describe(err)))
	}
	return sess, notices
}

func sessionCookie(id string, maxAge time.Duration) string {
	return (&http.Cookie{Name: CookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(maxAge.Seconds())}).String()
}

func codeCookie(id string, maxAge time.Duration) string {
	return (&http.Cookie{Name: CodeCookieName, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(maxAge.Seconds())}).String()
}
