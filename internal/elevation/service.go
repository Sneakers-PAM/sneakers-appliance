// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package elevation is the root shell (spec 2, Sections 2.8 and 3.4). A
// root operator's closed shell asks for a challenge; the operator, signed
// in to :8443, gets the challenge's code, made with the box's root key
// after a fresh TOTP code; the closed shell trades challenge and code for
// a one-use ticket; and sneakers-elevated uses the ticket up and runs the
// recorded root shell. It also writes sshd's revocation list, the serials
// and keys of removed SSH keys. sneakers-accessd owns it.
package elevation

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// State is where a root shell is in its life.
type State string

// The states.
const (
	// Challenged: the challenge is out, waiting for its code.
	Challenged State = "challenged"
	// Issued: :8443 gave the code; the operator hasn't typed it yet.
	Issued State = "issued"
	// Opened: the code was right; the ticket is out.
	Opened State = "opened"
	// Active: the root shell runs.
	Active State = "active"
	Ended  State = "ended"
	// Expired: the challenge, the code or the ticket lapsed, or the code
	// was wrong too often.
	Expired State = "expired"
)

// The limits.
const (
	// TicketLifetime is how long a ticket waits for sneakers-elevated.
	TicketLifetime = time.Minute
	// MaxCodeTries are the wrong codes a challenge takes.
	MaxCodeTries = 3
	// ChallengeLength is a challenge's length in characters.
	ChallengeLength = 16
)

// The end reasons.
const (
	ReasonExit       = "exit"
	ReasonIdle       = "idle"
	ReasonTimeBox    = "time-box"
	ReasonTerminated = "terminated"
	ReasonExpired    = "expired"
	ReasonCodeTries  = "wrong-codes"
	// ReasonLost is a session whose sneakers-elevated died without saying
	// how it ended.
	ReasonLost = "lost"
)

// The files in the SSH state directory (/var/lib/sneakers/ssh).
const (
	// RevokedFile is the revocation list sshd reads (RevokedKeys).
	RevokedFile = "revoked.krl"
)

// Request is one root shell: its challenge, its code and its session.
type Request struct {
	ID              string     `json:"id"`
	Admin           string     `json:"admin"`
	KeyFP           string     `json:"keyFp,omitempty"`
	Source          string     `json:"source"`
	Reason          string     `json:"reason,omitempty"`
	Minutes         int        `json:"minutes"`
	Requested       time.Time  `json:"requested"`
	State           State      `json:"state"`
	Challenge       string     `json:"challenge"`
	ApprovedBy      string     `json:"approvedBy,omitempty"`
	Approved        *time.Time `json:"approved,omitempty"`
	ValidBefore     *time.Time `json:"validBefore,omitempty"`
	CodeTries       int        `json:"codeTries,omitempty"`
	TicketHash      string     `json:"ticketHash,omitempty"`
	Started         *time.Time `json:"started,omitempty"`
	PID             int        `json:"pid,omitempty"`
	Ended           *time.Time `json:"ended,omitempty"`
	EndReason       string     `json:"endReason,omitempty"`
	RecordingSHA256 string     `json:"recordingSha256,omitempty"`
}

// Caller is who asks: the closed-shell login's admin, the key sshd says
// signed it in, and its SSH client address.
type Caller struct {
	Admin, KeyFP, Source string
}

// Coder is the root key as this package uses it.
type Coder interface {
	// Code is the root key's code for msg.
	Code(msg []byte) string
	PublicKey() ssh.PublicKey
}

// Options wire a Service.
type Options struct {
	// RootKey makes the codes and signs the revocation list's serials.
	// Required.
	RootKey Coder
	// SSHDir holds the revocation list.
	SSHDir string
	// StateFile is elevation.json.
	StateFile string
	Clock     clock.Clock
	Audit     osaudit.Appender
	// Maintenance reports an update being applied, which refuses new root
	// shells; nil is never.
	Maintenance func() bool
	// Signal asks an active session's sneakers-elevated to end (SIGTERM).
	Signal func(pid int) error
	// Alive reports whether an active session's sneakers-elevated still
	// runs; nil is always.
	Alive func(pid int) bool
	// OnChange is called after a root shell changed state, outside the
	// service's lock.
	OnChange func()
	// RevokedKeys and RevokedSerials are the access store's revocations
	// when the service opens, so the first list written has them.
	RevokedKeys    []ssh.PublicKey
	RevokedSerials []uint64
	Logger         log.Logger
}

type file struct {
	Requests []Request `json:"requests"`
}

// Service is the root shells and the revocation list.
type Service struct {
	o Options

	mu  sync.Mutex
	cur file
	// revokedKeys and revokedSerials are the removed SSH keys, on the
	// revocation list.
	revokedKeys    []ssh.PublicKey
	revokedSerials []uint64
}

// Open loads the history and writes the revocation list.
func Open(o Options) (*Service, error) {
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.RootKey == nil {
		return nil, errors.New("elevation: no root key")
	}
	s := &Service{o: o, revokedKeys: slices.Clone(o.RevokedKeys), revokedSerials: slices.Clone(o.RevokedSerials)}
	b, err := os.ReadFile(o.StateFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(o.StateFile), 0o700); err != nil {
			return nil, fmt.Errorf("elevation: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("elevation: %w", err)
	default:
		if err := json.Unmarshal(b, &s.cur); err != nil {
			return nil, fmt.Errorf("elevation: %s doesn't parse: %w", o.StateFile, err)
		}
	}
	if err := os.MkdirAll(o.SSHDir, 0o700); err != nil {
		return nil, fmt.Errorf("elevation: %w", err)
	}
	if err := s.writeKRL(); err != nil {
		return nil, err
	}
	o.Logger.Info("elevation: opened", log.F("rootShells", len(s.cur.Requests)))
	return s, nil
}

// Challenge opens a root-shell challenge for the caller, who must be a root
// operator with a known SSH client address.
func (s *Service) Challenge(st access.State, c Caller, reason string) (Request, error) {
	r, err := s.challenge(st, c, reason)
	s.audit(osaudit.Entry{Actor: c.Admin, KeyFP: c.KeyFP, Source: c.Source, Action: "rootshell.challenge", Target: r.ID,
		Detail: map[string]string{"reason": reason}}, "ok", err)
	if err == nil {
		s.changed()
	}
	return r, err
}

func (s *Service) challenge(st access.State, c Caller, reason string) (Request, error) {
	if s.maintenance() {
		return Request{}, codes.New(codes.ElevMaintenance, "an update is being applied; ask again once it has finished")
	}
	if _, ok := st.Admin(c.Admin); !ok || !st.IsRootOperator(c.Admin) {
		return Request{}, codes.New(codes.AccessForbidden, "only a root operator opens the root shell")
	}
	src, err := netip.ParseAddr(c.Source)
	if err != nil {
		return Request{}, codes.New(codes.AccessForbidden, "this login's SSH client address isn't known, so the challenge can't be bound to it")
	}
	p := st.AccessPolicy.Effective()
	now := s.now()
	vb := now.Add(time.Duration(p.RootCodeMinutes) * time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Request{ID: s.newID(), Admin: c.Admin, KeyFP: c.KeyFP, Source: src.String(), Reason: reason,
		Minutes: p.RootSessionMinutes, Requested: now, State: Challenged, Challenge: onetime.New(ChallengeLength), ValidBefore: &vb}
	next := file{Requests: append(slices.Clone(s.cur.Requests), r)}
	if err := s.save(next); err != nil {
		return Request{}, err
	}
	s.o.Logger.Info("elevation: challenge opened", log.F("id", r.ID), log.F("admin", r.Admin))
	return r, nil
}

// IssueCode answers a challenge for admin, who must be the root operator
// it was opened for. The code works for the access policy's code lifetime
// from now, once.
func (s *Service) IssueCode(st access.State, admin, challenge string) (Request, string, error) {
	r, code, err := s.issue(st, admin, challenge)
	s.audit(osaudit.Entry{Actor: admin, Action: "rootshell.code", Target: r.ID, Detail: map[string]string{"source": r.Source}}, "ok", err)
	if err == nil {
		s.changed()
	}
	return r, code, err
}

func (s *Service) issue(st access.State, admin, challenge string) (Request, string, error) {
	norm, ok := onetime.Normalize(challenge, ChallengeLength)
	if !ok {
		return Request{}, "", codes.New(codes.RootChallenge, "that isn't a root-shell challenge; paste it as the SSH session shows it")
	}
	if !st.IsRootOperator(admin) {
		return Request{}, "", codes.New(codes.AccessForbidden, "only a root operator gets a root-shell code")
	}
	if s.maintenance() {
		return Request{}, "", codes.New(codes.ElevMaintenance, "an update is being applied; ask again once it has finished")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.byChallenge(norm)
	if err != nil {
		return Request{}, "", err
	}
	r := s.cur.Requests[i]
	if r.Admin != admin {
		return Request{}, "", codes.New(codes.RootChallenge, "that challenge isn't yours")
	}
	if r.State != Challenged && r.State != Issued {
		return Request{}, "", codes.New(codes.RootChallenge, "that challenge was %s; ask for a new one in the SSH session", r.State)
	}
	now := s.now()
	vb := now.Add(time.Duration(st.AccessPolicy.Effective().RootCodeMinutes) * time.Minute)
	r.State, r.ApprovedBy, r.Approved, r.ValidBefore = Issued, admin, &now, &vb
	if err := s.put(i, r); err != nil {
		return Request{}, "", err
	}
	s.o.Logger.Info("elevation: code issued", log.F("id", r.ID), log.F("admin", admin))
	return r, s.code(r), nil
}

// code is the root key's code for r: tied to its id, challenge, operator,
// source and expiry.
func (s *Service) code(r Request) string {
	msg := fmt.Sprintf("%s|%s|%s|%s|%d", r.ID, r.Challenge, r.Admin, r.Source, r.ValidBefore.Unix())
	return s.o.RootKey.Code([]byte(msg))
}

// Open checks the code the caller typed for its challenge and returns a
// one-use ticket for sneakers-elevated. A wrong code is ROOT_CODE; after
// MaxCodeTries the challenge closes.
func (s *Service) Open(st access.State, c Caller, challenge, code string) (Request, string, error) {
	r, ticket, err := s.open(st, c, challenge, code)
	s.audit(osaudit.Entry{Actor: c.Admin, KeyFP: c.KeyFP, Source: c.Source, Action: "rootshell.open", Target: r.ID,
		Detail: map[string]string{"tries": strconv.Itoa(r.CodeTries)}}, "ok", err)
	s.changed()
	return r, ticket, err
}

func (s *Service) open(st access.State, c Caller, challenge, code string) (Request, string, error) {
	norm, ok := onetime.Normalize(challenge, ChallengeLength)
	if !ok {
		return Request{}, "", codes.New(codes.RootChallenge, "that isn't a root-shell challenge")
	}
	if !st.IsRootOperator(c.Admin) {
		return Request{}, "", codes.New(codes.AccessForbidden, "only a root operator opens the root shell")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.byChallenge(norm)
	if err != nil {
		return Request{}, "", err
	}
	r := s.cur.Requests[i]
	if r.Admin != c.Admin {
		return Request{}, "", codes.New(codes.RootChallenge, "that challenge isn't yours")
	}
	if r.Source != c.Source {
		return r, "", codes.New(codes.RootChallenge, "that challenge was opened from another address")
	}
	if r.State == Challenged {
		return r, "", codes.New(codes.RootCode, "no code was issued for this challenge yet; get it on :8443 first")
	}
	if r.State != Issued {
		return r, "", codes.New(codes.RootChallenge, "that challenge was %s; ask for a new one", r.State)
	}
	if !onetime.Matches(code, s.code(r), 8) {
		r.CodeTries++
		left := MaxCodeTries - r.CodeTries
		if left <= 0 {
			now := s.now()
			r.State, r.Ended, r.EndReason = Expired, &now, ReasonCodeTries
		}
		if err := s.put(i, r); err != nil {
			return r, "", err
		}
		if left <= 0 {
			return r, "", codes.New(codes.RootChallenge, "%d wrong codes; the challenge is closed, ask for a new one", MaxCodeTries)
		}
		return r, "", codes.New(codes.RootCode, "that code doesn't match the challenge; %d tries left", left)
	}
	ticket := secret()
	now := s.now()
	tb := now.Add(TicketLifetime)
	r.State, r.TicketHash, r.ValidBefore = Opened, hash(ticket), &tb
	if err := s.put(i, r); err != nil {
		return r, "", err
	}
	s.o.Logger.Info("elevation: code accepted, ticket out", log.F("id", r.ID), log.F("admin", r.Admin))
	return r, ticket, nil
}

// byChallenge finds the request a challenge opened, expiring it first when
// its time is up. Caller holds mu.
func (s *Service) byChallenge(challenge string) (int, error) {
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool {
		return subtle.ConstantTimeCompare([]byte(r.Challenge), []byte(challenge)) == 1
	})
	if i < 0 {
		return -1, codes.New(codes.RootChallenge, "there is no such challenge; ask for a new one in the SSH session")
	}
	r := s.cur.Requests[i]
	if (r.State == Challenged || r.State == Issued) && r.ValidBefore != nil && !s.now().Before(*r.ValidBefore) {
		now := s.now()
		r.State, r.Ended, r.EndReason = Expired, &now, ReasonExpired
		if err := s.put(i, r); err != nil {
			return -1, err
		}
		return -1, codes.New(codes.RootChallenge, "that challenge has expired; ask for a new one")
	}
	return i, nil
}

// Begin uses up a ticket for admin, the SSH session's: the root shell goes
// active. ends is when its limit runs out.
func (s *Service) Begin(ticket, admin string, pid int) (Request, time.Time, error) {
	r, ends, err := s.begin(ticket, admin, pid)
	s.audit(osaudit.Entry{Actor: admin, KeyFP: r.KeyFP, Source: r.Source, Action: "rootshell.start", Target: r.ID,
		Detail: map[string]string{"pid": strconv.Itoa(pid), "minutes": strconv.Itoa(r.Minutes)}}, "ok", err)
	if err == nil {
		s.changed()
	}
	return r, ends, err
}

func (s *Service) begin(ticket, admin string, pid int) (Request, time.Time, error) {
	if s.maintenance() {
		return Request{}, time.Time{}, codes.New(codes.ElevMaintenance, "an update is being applied; open the root shell once it has finished")
	}
	h := hash(ticket)
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool {
		return r.TicketHash != "" && subtle.ConstantTimeCompare([]byte(r.TicketHash), []byte(h)) == 1
	})
	if i < 0 {
		return Request{}, time.Time{}, codes.New(codes.ElevUnknown, "that ticket opens no root shell")
	}
	r := s.cur.Requests[i]
	if r.Admin != admin {
		return r, time.Time{}, codes.New(codes.ElevUnknown, "that ticket isn't this login's")
	}
	if r.State != Opened {
		return r, time.Time{}, codes.New(codes.ElevUsed, "that ticket was already used (%s)", r.State)
	}
	now := s.now()
	if !now.Before(*r.ValidBefore) {
		r.State, r.Ended, r.EndReason = Expired, &now, ReasonExpired
		return r, time.Time{}, errors.Join(codes.New(codes.ElevExpired, "that ticket expired"), s.put(i, r))
	}
	r.State, r.Started, r.PID, r.TicketHash = Active, &now, pid, ""
	if err := s.put(i, r); err != nil {
		return r, time.Time{}, err
	}
	s.o.Logger.Info("elevation: root shell started", log.F("id", r.ID), log.F("admin", r.Admin), log.F("pid", pid))
	return r, now.Add(time.Duration(r.Minutes) * time.Minute), nil
}

// End records how an active session ended and its recording's hash.
func (s *Service) End(id, reason, recordingSHA string) error {
	r, err := s.end(id, reason, recordingSHA)
	s.audit(osaudit.Entry{Actor: "sneakers-elevated", Action: "rootshell.end", Target: id,
		Detail: map[string]string{"admin": r.Admin, "recordingSha256": recordingSHA}}, reason, err)
	if err == nil {
		s.changed()
	}
	return err
}

func (s *Service) end(id, reason, sha string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool { return r.ID == id })
	if i < 0 {
		return Request{}, codes.New(codes.ElevUnknown, "there is no root shell %s", id)
	}
	r := s.cur.Requests[i]
	if r.State != Active {
		return r, codes.New(codes.ElevUsed, "%s isn't an active root shell (%s)", id, r.State)
	}
	now := s.now()
	r.State, r.Ended, r.EndReason, r.RecordingSHA256 = Ended, &now, reason, sha
	if err := s.put(i, r); err != nil {
		return r, err
	}
	s.o.Logger.Info("elevation: root shell ended", log.F("id", id), log.F("reason", reason))
	return r, nil
}

// Terminate ends an active root shell (its sneakers-elevated is told to stop
// and reports the end), or closes a challenge, code or ticket nobody used.
func (s *Service) Terminate(id, by string) (Request, error) {
	r, err := s.terminate(id, by)
	if err == nil {
		s.changed()
	}
	return r, err
}

func (s *Service) terminate(id, by string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool { return r.ID == id })
	if i < 0 {
		return Request{}, codes.New(codes.ElevUnknown, "there is no root shell %s", id)
	}
	r := s.cur.Requests[i]
	now := s.now()
	switch r.State {
	case Active:
		s.o.Logger.Info("elevation: terminating", log.F("id", id), log.F("by", by), log.F("pid", r.PID))
		if s.o.Signal == nil {
			return r, errors.New("elevation: this service can't reach sessions")
		}
		if err := s.o.Signal(r.PID); err != nil {
			s.o.Logger.Warn("elevation: the session's process is gone; ended here", log.F("id", id), log.F("error", err.Error()))
			r.State, r.Ended, r.EndReason = Ended, &now, ReasonTerminated
			return r, s.put(i, r)
		}
		return r, nil
	case Challenged, Issued, Opened:
		r.State, r.Ended, r.EndReason, r.TicketHash = Expired, &now, ReasonTerminated, ""
		s.o.Logger.Info("elevation: an unused challenge closed", log.F("id", id), log.F("by", by))
		return r, s.put(i, r)
	}
	return r, codes.New(codes.ElevUsed, "%s is %s; there is nothing to end", id, r.State)
}

// Sweep expires challenges, codes and tickets past their time, and ends
// active sessions whose sneakers-elevated is gone. accessd runs it every
// minute.
func (s *Service) Sweep() {
	expired := s.sweep()
	for _, r := range expired {
		s.audit(osaudit.Entry{Actor: "accessd", Action: "rootshell.expire", Target: r.ID, Detail: map[string]string{"admin": r.Admin, "was": r.EndReason}}, r.EndReason, nil)
	}
	if len(expired) > 0 {
		s.changed()
	}
}

func (s *Service) sweep() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	next := file{Requests: slices.Clone(s.cur.Requests)}
	var out []Request
	for i, r := range next.Requests {
		switch {
		case (r.State == Challenged || r.State == Issued || r.State == Opened) && r.ValidBefore != nil && !now.Before(*r.ValidBefore):
			r.State, r.Ended, r.EndReason, r.TicketHash = Expired, &now, ReasonExpired, ""
		case r.State == Active && s.o.Alive != nil && !s.o.Alive(r.PID):
			r.State, r.Ended, r.EndReason = Ended, &now, ReasonLost
		default:
			continue
		}
		next.Requests[i] = r
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	if err := s.save(next); err != nil {
		s.o.Logger.Error(err, "elevation: sweep not saved")
		return nil
	}
	return out
}

// Get returns root shell id.
func (s *Service) Get(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool { return r.ID == id })
	if i < 0 {
		return Request{}, false
	}
	return s.cur.Requests[i], true
}

// List returns every root shell, newest first.
func (s *Service) List() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.cur.Requests)
	slices.Reverse(out)
	return out
}

// Active reports an active root shell (an automatic upgrade waits for it to
// end).
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.cur.Requests, func(r Request) bool { return r.State == Active })
}

// put replaces request i and saves. Caller holds mu.
func (s *Service) put(i int, r Request) error {
	next := file{Requests: slices.Clone(s.cur.Requests)}
	next.Requests[i] = r
	return s.save(next)
}

// save writes next. Caller holds mu.
func (s *Service) save(next file) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("elevation: %w", err)
	}
	if err := writeFile(s.o.StateFile, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("elevation: %w", err)
	}
	s.cur = next
	return nil
}

// RevokeLoginKeys writes the revocation list with st's removed SSH keys and
// their serials: the access store's Revoke, run inside its write.
func (s *Service) RevokeLoginKeys(st access.State) error {
	keys, err := st.RevokedPublicKeys()
	if err != nil {
		return err
	}
	serials := st.RevokedSerials()
	s.mu.Lock()
	defer s.mu.Unlock()
	prevK, prevS := s.revokedKeys, s.revokedSerials
	s.revokedKeys, s.revokedSerials = keys, serials
	if err := s.writeKRL(); err != nil {
		s.revokedKeys, s.revokedSerials = prevK, prevS
		return err
	}
	if len(keys) != len(prevK) {
		s.o.Logger.Info("elevation: revocation list written", log.F("keys", len(keys)), log.F("serials", len(serials)))
	}
	return nil
}

// writeKRL writes the revocation list. Caller holds mu (or is Open).
func (s *Service) writeKRL() error {
	krl := MarshalKRL(s.o.RootKey.PublicKey(), s.revokedSerials, s.revokedKeys, uint64(len(s.revokedSerials)+len(s.revokedKeys)), s.now())
	if err := writeFile(filepath.Join(s.o.SSHDir, RevokedFile), krl, 0o644); err != nil {
		return fmt.Errorf("elevation: revocation list: %w", err)
	}
	return nil
}

// idAlphabet leaves out 0, 1, I and O, which read alike.
const idAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newID is R- and four characters no root shell has. Caller holds mu.
func (s *Service) newID() string {
	for {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		id := []byte("R-")
		for _, v := range b {
			id = append(id, idAlphabet[int(v)%len(idAlphabet)])
		}
		if !slices.ContainsFunc(s.cur.Requests, func(r Request) bool { return r.ID == string(id) }) {
			return string(id)
		}
	}
}

func secret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (s *Service) maintenance() bool { return s.o.Maintenance != nil && s.o.Maintenance() }

func (s *Service) now() time.Time { return s.o.Clock.Now().UTC().Truncate(time.Second) }

func (s *Service) changed() {
	if s.o.OnChange != nil {
		s.o.OnChange()
	}
}

func (s *Service) audit(e osaudit.Entry, outcome string, err error) {
	if s.o.Audit == nil {
		return
	}
	e.Outcome = outcome
	if err != nil {
		e.Outcome = "refused"
		if code, ok := codes.Of(err); ok {
			e.Code = codes.Symbol(code)
		} else {
			e.Code = "internal"
		}
	}
	if e.Detail == nil {
		e.Detail = map[string]string{}
	}
	if aerr := s.o.Audit.Append(e); aerr != nil {
		s.o.Logger.Error(aerr, "elevation: audit append failed", log.F("action", e.Action))
	}
}

// writeFile replaces path atomically with data, synced.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) // #nosec G304 -- a file in a directory accessd owns
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
