// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package enrol is the SSH key enrolment window (spec 2, Sections 2.4 and
// 3.3). The console opens a window for one admin and shows its code; while
// it is open the enrol account exists and any key authenticates for it
// (sneakers-enrol-keys), and sneakers-enrol asks for the code. A key that
// gave the right code waits until the console's typed yes stores it.
// Three wrong codes close the window and a new one opens with a new code;
// 30 idle minutes or the console's Done close it.
package enrol

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// The window's limits.
const (
	MaxAttempts = 3
	IdleFor     = 30 * time.Minute
	// MaxKeys bounds the keys one window holds.
	MaxKeys = 10
)

// KeyState is where a submitted key is.
type KeyState string

// The key states.
const (
	Waiting  KeyState = "waiting"
	Accepted KeyState = "accepted"
	Rejected KeyState = "rejected"
)

// Why a window closed.
const (
	ReasonDone     = "done"
	ReasonIdle     = "idle"
	ReasonAttempts = "attempts"
)

// Key is a key that gave the right code.
type Key struct {
	ID          string
	Fingerprint string
	Type        string
	Comment     string
	Source      string
	State       KeyState
	// Via is how the key reached the window: access.ViaEnrol over SSH,
	// or typed or fetched on the console.
	Via  string
	line string
}

// View is the window as the console shows it.
type View struct {
	Open         bool
	Admin        string
	Code         string
	Opened       time.Time
	IdleUntil    time.Time
	AttemptsLeft int
	Keys         []Key
	Enrolled     int
	ClosedReason string
	// Recovery marks the console's Recover access window.
	Recovery bool
}

// RecoveryHold is how long a key added with Recover access can't approve
// elevations (spec 2 Section 2.10); another owner can lift it sooner.
const RecoveryHold = 24 * time.Hour

// OpenOptions shape a window.
type OpenOptions struct {
	// Recovery is the console's Recover access: owners only, and each key
	// stored is held from approving elevations for RecoveryHold.
	Recovery bool
}

// Options wire a Service.
type Options struct {
	Store *access.Store
	Clock clock.Clock
	Audit osaudit.Appender
	// OnChange is called when the window opens or closes (the enrol
	// account and sshd's enrol block follow it), outside the lock.
	OnChange func()
	// NewCode makes an enrolment code; nil is the sign-in code alphabet.
	NewCode func() string
	Logger  log.Logger
}

// Service is the enrolment window; at most one is open.
type Service struct {
	o Options

	mu       sync.Mutex
	w        View
	lastSeen time.Time
}

// New returns a closed window.
func New(o Options) *Service {
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.NewCode == nil {
		o.NewCode = weblogin.NewCode
	}
	return &Service{o: o}
}

// IsOpen reports an open window.
func (s *Service) IsOpen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Open
}

// Get returns the window.
func (s *Service) Get() View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view()
}

func (s *Service) view() View {
	v := s.w
	v.Keys = slices.Clone(s.w.Keys)
	if v.Open {
		v.IdleUntil = s.lastSeen.Add(IdleFor)
	}
	return v
}

// Open opens a window for admin's keys, replacing an open one.
func (s *Service) Open(admin string) (View, error) { return s.OpenWith(admin, OpenOptions{}) }

// OpenWith opens a window shaped by o.
func (s *Service) OpenWith(admin string, o OpenOptions) (View, error) {
	st := s.o.Store.Read()
	a, ok := st.Admin(admin)
	var err error
	switch {
	case !ok:
		err = codes.New(codes.AccessName, "there is no admin named %q", admin)
	case o.Recovery && a.Role != access.RoleOwner:
		err = codes.New(codes.AccessForbidden, "Recover access adds keys to owners only; %s isn't one", admin)
	}
	if err != nil {
		s.audit(osaudit.Entry{Action: "enrol.open", Target: admin}, "", err)
		return View{}, err
	}
	s.mu.Lock()
	v := s.open(admin, o.Recovery)
	s.mu.Unlock()
	s.changed()
	return v, nil
}

// open starts a fresh window. Caller holds mu.
func (s *Service) open(admin string, recovery bool) View {
	now := s.o.Clock.Now().UTC()
	s.w = View{Open: true, Admin: admin, Code: s.o.NewCode(), Opened: now, AttemptsLeft: MaxAttempts, Recovery: recovery}
	s.lastSeen = now
	s.o.Logger.Info("enrol: window open", log.F("admin", admin), log.F("recovery", recovery))
	e := osaudit.Entry{Action: "enrol.open", Target: admin}
	if recovery {
		e.Detail = map[string]string{"recovery": "true"}
	}
	s.audit(e, "ok", nil)
	return s.view()
}

// Close closes the window for reason.
func (s *Service) Close(reason string) {
	s.mu.Lock()
	was := s.w.Open
	s.close(reason)
	s.mu.Unlock()
	if was {
		s.changed()
	}
}

// close closes an open window. Caller holds mu.
func (s *Service) close(reason string) {
	if !s.w.Open {
		return
	}
	s.w.Open, s.w.ClosedReason, s.w.Code = false, reason, ""
	s.o.Logger.Info("enrol: window closed", log.F("admin", s.w.Admin), log.F("reason", reason), log.F("enrolled", s.w.Enrolled))
	s.audit(osaudit.Entry{Action: "enrol.close", Target: s.w.Admin, Detail: map[string]string{"enrolled": fmt.Sprint(s.w.Enrolled)}}, reason, nil)
}

// Sweep closes a window idle for IdleFor; accessd runs it every minute.
func (s *Service) Sweep() {
	s.mu.Lock()
	closed := s.w.Open && !s.o.Clock.Now().UTC().Before(s.lastSeen.Add(IdleFor))
	if closed {
		s.close(ReasonIdle)
	}
	s.mu.Unlock()
	if closed {
		s.changed()
	}
}

// Submit is sneakers-enrol's: the code typed and the key sshd
// authenticated, from source. The key waits for the console.
func (s *Service) Submit(code, publicKey, source string) (Key, error) {
	k, reopened, err := s.submit(code, publicKey, source)
	if reopened {
		s.changed()
	}
	return k, err
}

func (s *Service) submit(code, publicKey, source string) (Key, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := osaudit.Entry{Actor: "enrol", Source: source, Action: "enrol.code", Target: s.w.Admin}
	if !s.w.Open {
		err := codes.New(codes.EnrolClosed, "the enrolment window is closed; open one on the console")
		s.audit(e, "", err)
		return Key{}, false, err
	}
	s.lastSeen = s.o.Clock.Now().UTC()
	if subtle.ConstantTimeCompare([]byte(weblogin.Normalize(code)), []byte(s.w.Code)) != 1 {
		s.w.AttemptsLeft--
		if s.w.AttemptsLeft > 0 {
			err := codes.New(codes.EnrolCode, "wrong code; %d attempts left", s.w.AttemptsLeft)
			s.audit(e, "", err)
			return Key{}, false, err
		}
		err := codes.New(codes.EnrolCode, "wrong code three times; the window closed and the console shows a new code")
		s.audit(e, "", err)
		admin, recovery := s.w.Admin, s.w.Recovery
		s.close(ReasonAttempts)
		s.open(admin, recovery)
		return Key{}, true, err
	}
	pk, err := access.ParseLoginKey(publicKey)
	if err != nil {
		s.audit(e, "", err)
		return Key{}, false, err
	}
	if len(s.w.Keys) >= MaxKeys {
		err := codes.New(codes.EnrolClosed, "this window already holds %d keys; press Done and open a new one", MaxKeys)
		s.audit(e, "", err)
		return Key{}, false, err
	}
	k := Key{ID: newID(), Fingerprint: pk.Fingerprint, Type: pk.Type, Comment: pk.Comment, Source: source, State: Waiting, Via: access.ViaEnrol, line: pk.PublicKey}
	s.w.Keys = append(s.w.Keys, k)
	e.Action, e.KeyFP = "enrol.submit", k.Fingerprint
	s.audit(e, "ok", nil)
	s.o.Logger.Info("enrol: a key gave the right code", log.F("admin", s.w.Admin), log.F("fingerprint", k.Fingerprint))
	return k, false, nil
}

// Offer puts a key typed or fetched on the console (via is access.ViaTyped
// or access.ViaURL, from the URL it came from) into the open window. It
// waits for the typed yes like a key offered over SSH, and uses no code
// attempt: the console is where the code is shown.
func (s *Service) Offer(publicKey, via, from string) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := osaudit.Entry{Actor: osaudit.SurfaceConsole, Source: "console", Action: "enrol.offer", Target: s.w.Admin, Detail: map[string]string{"via": via}}
	if from != "" {
		e.Detail["from"] = from
	}
	if !s.w.Open {
		err := codes.New(codes.EnrolClosed, "the enrolment window is closed; open one on the console")
		s.audit(e, "", err)
		return Key{}, err
	}
	pk, err := access.ParseLoginKey(publicKey)
	if err != nil {
		s.audit(e, "", err)
		return Key{}, err
	}
	e.KeyFP = pk.Fingerprint
	if slices.ContainsFunc(s.w.Keys, func(k Key) bool { return k.Fingerprint == pk.Fingerprint && k.State != Rejected }) {
		err := codes.New(codes.AccessKeyDuplicate, "key %s is already in this window", pk.Fingerprint)
		s.audit(e, "", err)
		return Key{}, err
	}
	if len(s.w.Keys) >= MaxKeys {
		err := codes.New(codes.EnrolClosed, "this window already holds %d keys; press Done and open a new one", MaxKeys)
		s.audit(e, "", err)
		return Key{}, err
	}
	k := Key{ID: newID(), Fingerprint: pk.Fingerprint, Type: pk.Type, Comment: pk.Comment, Source: "console", State: Waiting, Via: via, line: pk.PublicKey}
	s.w.Keys = append(s.w.Keys, k)
	s.lastSeen = s.o.Clock.Now().UTC()
	s.audit(e, "ok", nil)
	s.o.Logger.Info("enrol: a key was offered on the console", log.F("admin", s.w.Admin), log.F("fingerprint", k.Fingerprint), log.F("via", via))
	return k, nil
}

// Key returns submitted key id of the open window.
func (s *Service) Key(id string) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.find(id)
	if err != nil {
		return Key{}, err
	}
	return s.w.Keys[i], nil
}

func (s *Service) find(id string) (int, error) {
	i := slices.IndexFunc(s.w.Keys, func(k Key) bool { return k.ID == id })
	if !s.w.Open || i < 0 {
		return -1, codes.New(codes.EnrolUnknown, "no key %s is waiting in the enrolment window", id)
	}
	return i, nil
}

// Accept stores waiting key id as a key of the window's admin; confirm is
// the console's typed yes. The store is written outside the window's
// lock, since its change re-renders the files that follow the window.
func (s *Service) Accept(id, confirm string) (access.AdminKey, error) {
	s.mu.Lock()
	e := osaudit.Entry{Actor: osaudit.SurfaceConsole, Action: "enrol.accept", Target: s.w.Admin}
	recovery := s.w.Recovery
	if recovery {
		e.Action = "access.console-recovery"
	}
	i, err := s.find(id)
	if err == nil && s.w.Keys[i].State != Waiting {
		err = codes.New(codes.EnrolUnknown, "key %s was already %s", id, s.w.Keys[i].State)
	}
	if err == nil && strings.TrimSpace(confirm) != "yes" {
		err = codes.New(codes.AccessConfirm, "type yes to store the key")
	}
	var k Key
	if err == nil {
		k = s.w.Keys[i]
		e.KeyFP, e.Source = k.Fingerprint, k.Source
		// Taken while it is stored, so a second Accept can't store it twice.
		s.w.Keys[i].State = Accepted
	}
	admin := s.w.Admin
	s.mu.Unlock()
	if err != nil {
		s.audit(e, "", err)
		return access.AdminKey{}, err
	}
	ak, err := s.store(admin, k, recovery)
	s.mu.Lock()
	defer s.mu.Unlock()
	if j := slices.IndexFunc(s.w.Keys, func(x Key) bool { return x.ID == id }); j >= 0 {
		if err != nil {
			s.w.Keys[j].State = Waiting
		} else {
			s.w.Enrolled++
			s.lastSeen = s.o.Clock.Now().UTC()
		}
	}
	s.audit(e, "ok", err)
	if err != nil {
		return access.AdminKey{}, err
	}
	s.o.Logger.Info("enrol: key stored", log.F("admin", admin), log.F("fingerprint", k.Fingerprint))
	return ak, nil
}

func (s *Service) store(admin string, k Key, recovery bool) (access.AdminKey, error) {
	pk, err := access.ParseLoginKey(k.line)
	if err != nil {
		return access.AdminKey{}, err
	}
	now := s.o.Clock.Now().UTC()
	via := k.Via
	if via == "" {
		via = access.ViaEnrol
	}
	if recovery {
		via = access.ViaConsoleRecovery
	}
	ak := access.AdminKey{Key: pk, Added: now, AddedBy: osaudit.SurfaceConsole, Via: via}
	err = s.o.Store.Update(func(st *access.State) error {
		a, ok := st.Admin(admin)
		if !ok {
			return codes.New(codes.AccessName, "there is no admin named %q any more", admin)
		}
		a.Keys = append(a.Keys, ak)
		if recovery {
			until := now.Add(RecoveryHold)
			a.ApprovalHoldUntil = &until
		}
		return nil
	})
	return ak, err
}

// Reject refuses waiting key id.
func (s *Service) Reject(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := osaudit.Entry{Actor: osaudit.SurfaceConsole, Action: "enrol.reject", Target: s.w.Admin}
	i, err := s.find(id)
	if err == nil && s.w.Keys[i].State != Waiting {
		err = codes.New(codes.EnrolUnknown, "key %s was already %s", id, s.w.Keys[i].State)
	}
	if err != nil {
		s.audit(e, "", err)
		return err
	}
	s.w.Keys[i].State = Rejected
	e.KeyFP, e.Source = s.w.Keys[i].Fingerprint, s.w.Keys[i].Source
	s.audit(e, "ok", nil)
	return nil
}

// AuthorizedLine is sneakers-enrol-keys' answer for the key sshd offers
// (%f, %k and %t): the key back, restricted, when the three agree and the
// key is of an accepted type. sshd runs it only while the enrol account
// exists, which is only while a window is open.
func AuthorizedLine(fingerprint, key, keyType string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("the offered key isn't base64: %w", err)
	}
	pk, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return "", fmt.Errorf("the offered key doesn't parse: %w", err)
	}
	if pk.Type() != keyType || ssh.FingerprintSHA256(pk) != fingerprint {
		return "", fmt.Errorf("the offered key's type or fingerprint doesn't match")
	}
	if _, err := access.ParseLoginKey(keyType + " " + key); err != nil {
		return "", err
	}
	return "restrict " + keyType + " " + key, nil
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "K-" + base64.RawURLEncoding.EncodeToString(b)
}

func (s *Service) changed() {
	if s.o.OnChange != nil {
		s.o.OnChange()
	}
}

func (s *Service) audit(e osaudit.Entry, outcome string, err error) {
	if s.o.Audit == nil {
		return
	}
	if e.Actor == "" {
		e.Actor = osaudit.SurfaceConsole
	}
	e.Outcome = outcome
	if err != nil {
		e.Outcome = "refused"
		if code, ok := codes.Of(err); ok {
			e.Code = codes.Symbol(code)
		}
	}
	if e.Detail == nil {
		e.Detail = map[string]string{}
	}
	if aerr := s.o.Audit.Append(e); aerr != nil {
		s.o.Logger.Error(aerr, "enrol: audit append failed", log.F("action", e.Action))
	}
}
