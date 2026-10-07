// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package elevation is the one-time root shell (spec 2, Sections 2.8 and
// 3.4): the requests and their approval rules, the user CA that signs a
// single-use OpenSSH certificate for each approved request, the serial
// counter and the revocation list. sneakers-accessd owns it; the closed
// shell requests, owners approve on :8443 or the console, and
// sneakers-elevated uses the certificate up and reports the session's end.
package elevation

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// State is where a request is in its life.
type State string

// The request states.
const (
	Pending  State = "pending"
	Approved State = "approved"
	Active   State = "active"
	Ended    State = "ended"
	Denied   State = "denied"
	Expired  State = "expired"
	// Withdrawn is a pending request its own requester gave up on (the
	// closed shell's Ctrl-C while it waits). It can't be approved.
	Withdrawn State = "withdrawn"
)

// The time limits (spec 2, Section 2.8.1).
const (
	// MinMinutes is the shortest elevation.
	MinMinutes = 15
	// PendingFor is how long a request waits for an approver.
	PendingFor = 30 * time.Minute
	// ConnectWindow is how long an approved certificate can be used to
	// connect; it isn't the session's length.
	ConnectWindow = 10 * time.Minute
)

// The end reasons.
const (
	ReasonExit       = "exit"
	ReasonTimeBox    = "time-box"
	ReasonTerminated = "terminated"
	ReasonDenied     = "denied"
	ReasonExpired    = "expired"
	ReasonWithdrawn  = "withdrawn"
	// ReasonLost is a session whose sneakers-elevated died without saying
	// how it ended.
	ReasonLost = "lost"
)

// ConsoleApprover is the approver of a decision made on the console (root
// on access.sock). No admin can have it as a name ('@' isn't allowed), so
// an admin named console is still checked as an admin.
const ConsoleApprover = "@console"

// DefaultElevated is sneakers-elevated on the box, the certificate's
// force-command.
const DefaultElevated = "/usr/libexec/sneakers-elevated"

// Request is one elevation request and what became of it.
type Request struct {
	ID              string     `json:"id"`
	Admin           string     `json:"admin"`
	KeyFP           string     `json:"keyFp"`
	PublicKey       string     `json:"publicKey"`
	Source          string     `json:"source"`
	Reason          string     `json:"reason"`
	Minutes         int        `json:"minutes"`
	Requested       time.Time  `json:"requested"`
	State           State      `json:"state"`
	ApprovedBy      string     `json:"approvedBy,omitempty"`
	Approved        *time.Time `json:"approved,omitempty"`
	SelfApproved    bool       `json:"selfApproved,omitempty"`
	Serial          uint64     `json:"serial,omitempty"`
	Certificate     string     `json:"certificate,omitempty"`
	ValidBefore     *time.Time `json:"validBefore,omitempty"`
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

// Options wire a Service.
type Options struct {
	// SSHDir holds the user CA, the revocation list and the serial counter.
	SSHDir string
	// StateFile is elevation.json.
	StateFile string
	Clock     clock.Clock
	Audit     osaudit.Appender
	// Elevated is the certificate's force-command; empty is
	// DefaultElevated.
	Elevated string
	// Maintenance reports an upgrade between its snapshot and MarkGood,
	// which blocks approvals; nil is never.
	Maintenance func() bool
	// Signal asks an active session's sneakers-elevated to end (SIGTERM).
	Signal func(pid int) error
	// Alive reports whether an active session's sneakers-elevated still
	// runs; nil is always.
	Alive func(pid int) bool
	// OnChange is called after the open principals or the revocation list
	// changed, outside the service's lock.
	OnChange func()
	// RevokedKeys are the login keys already revoked when the service
	// opens (the access store's), so the first list written has them.
	RevokedKeys []ssh.PublicKey
	Logger      log.Logger
}

type file struct {
	Requests []Request `json:"requests"`
}

// Service is the elevation requests and the user CA.
type Service struct {
	o  Options
	ca ssh.Signer

	mu  sync.Mutex
	cur file
	// revokedKeys are the removed login keys, also on the revocation list.
	revokedKeys []ssh.PublicKey
}

// Open loads the requests and the user CA, making the CA, the serial
// counter and the revocation list the first time.
func Open(o Options) (*Service, error) {
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Elevated == "" {
		o.Elevated = DefaultElevated
	}
	ca, err := loadCA(o.SSHDir)
	if err != nil {
		return nil, err
	}
	s := &Service{o: o, ca: ca, revokedKeys: slices.Clone(o.RevokedKeys)}
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
	if err := s.writeKRL(); err != nil {
		return nil, err
	}
	o.Logger.Info("elevation: opened", log.F("requests", len(s.cur.Requests)), log.F("ca", ssh.FingerprintSHA256(ca.PublicKey())))
	return s, nil
}

// UserCA is the CA's public key, the one sshd trusts for maint.
func (s *Service) UserCA() ssh.PublicKey { return s.ca.PublicKey() }

// Request records a request for an elevated shell for the caller's key.
// minutes 0 takes the policy's default.
func (s *Service) Request(st access.State, c Caller, reason string, minutes int) (Request, error) {
	r, err := s.request(st, c, reason, minutes)
	e := osaudit.Entry{Actor: c.Admin, KeyFP: c.KeyFP, Source: c.Source, Action: "elevation.request", Target: r.ID,
		Detail: map[string]string{"minutes": strconv.Itoa(r.Minutes), "reason": reason}}
	s.audit(e, "ok", err)
	return r, err
}

func (s *Service) request(st access.State, c Caller, reason string, minutes int) (Request, error) {
	if strings.TrimSpace(reason) == "" {
		return Request{}, codes.New(codes.ShellParse, "give a reason: shell --reason \"...\"")
	}
	a, ok := st.Admin(c.Admin)
	if !ok {
		return Request{}, codes.New(codes.AccessForbidden, "only an admin's closed-shell login can ask for elevation")
	}
	key := keyOf(a, c.KeyFP)
	if key == "" {
		return Request{}, codes.New(codes.AccessForbidden, "sshd didn't name a key of %s for this login, so there is nothing to sign", a.Name)
	}
	src, err := netip.ParseAddr(c.Source)
	if err != nil {
		return Request{}, codes.New(codes.AccessForbidden, "this login's SSH client address isn't known, so the certificate can't be bound to it")
	}
	p := st.ElevationPolicy
	if minutes == 0 {
		minutes = p.DefaultMinutes
	}
	if minutes < MinMinutes || minutes > p.MaxMinutes {
		return Request{}, codes.New(codes.ElevMinutes, "an elevation lasts %d to %d minutes", MinMinutes, p.MaxMinutes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Request{ID: s.newID(), Admin: a.Name, KeyFP: c.KeyFP, PublicKey: key, Source: src.String(), Reason: reason,
		Minutes: minutes, Requested: s.now(), State: Pending}
	next := s.cur
	next.Requests = append(slices.Clone(s.cur.Requests), r)
	if err := s.save(next); err != nil {
		return Request{}, err
	}
	s.o.Logger.Info("elevation: requested", log.F("id", r.ID), log.F("admin", r.Admin), log.F("minutes", minutes))
	return r, nil
}

func keyOf(a *access.Admin, fp string) string {
	for _, k := range a.Keys {
		if fp != "" && k.Fingerprint == fp {
			return k.PublicKey
		}
	}
	return ""
}

// Approve approves request id as approver (an owner's name, or
// ConsoleApprover),
// shortening it to minutes when that isn't 0, and signs its certificate.
func (s *Service) Approve(st access.State, approver, id string, minutes int) (Request, error) {
	r, err := s.approve(st, approver, id, minutes)
	if err == nil {
		s.audit(osaudit.Entry{Actor: r.ApprovedBy, Action: "elevation.certificate", Target: id, Detail: map[string]string{
			"serial": strconv.FormatUint(r.Serial, 10), "validBefore": r.ValidBefore.UTC().Format(time.RFC3339),
			"minutes": strconv.Itoa(r.Minutes), "admin": r.Admin, "selfApproved": strconv.FormatBool(r.SelfApproved)}}, "ok", nil)
		s.changed()
	}
	return r, err
}

func (s *Service) approve(st access.State, approver, id string, minutes int) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.live(id)
	if err != nil {
		return Request{}, err
	}
	r := s.cur.Requests[i]
	if r.State != Pending {
		return Request{}, codes.New(codes.ElevUsed, "%s was already %s", id, r.State)
	}
	if s.o.Maintenance != nil && s.o.Maintenance() {
		return Request{}, codes.New(codes.ElevMaintenance, "an upgrade is in progress; approve once it has finished")
	}
	self := false
	by := approver
	if approver == ConsoleApprover {
		by = osaudit.SurfaceConsole
	} else {
		a, ok := st.Admin(approver)
		if !ok || a.Role != access.RoleOwner {
			return Request{}, codes.New(codes.AccessForbidden, "only an owner approves an elevation")
		}
		if a.ApprovalHoldUntil != nil && s.now().Before(*a.ApprovalHoldUntil) {
			return Request{}, codes.New(codes.ElevHold, "%s's key came through the console's Recover access; %s can approve from %s", a.Name, a.Name, a.ApprovalHoldUntil.UTC().Format(time.RFC3339))
		}
		if approver == r.Admin {
			if owners(st) > 1 || !st.ElevationPolicy.SelfApprovalWhenSingleOwner {
				return Request{}, codes.New(codes.ElevSelfApproval, "another owner approves %s", id)
			}
			self = true
		}
	}
	if minutes != 0 {
		if minutes < MinMinutes || minutes > r.Minutes {
			return Request{}, codes.New(codes.ElevMinutes, "an approval can shorten %s to between %d and %d minutes, not lengthen it", id, MinMinutes, r.Minutes)
		}
		r.Minutes = minutes
	}
	if a, ok := st.Admin(r.Admin); !ok || keyOf(a, r.KeyFP) == "" {
		return Request{}, codes.New(codes.AccessForbidden, "the key %s asked with was removed", id)
	}
	serial, err := s.nextSerial()
	if err != nil {
		return Request{}, err
	}
	now := s.now()
	cert, err := s.sign(r, serial, now)
	if err != nil {
		return Request{}, err
	}
	vb := now.Add(ConnectWindow)
	r.State, r.ApprovedBy, r.Approved, r.SelfApproved = Approved, by, &now, self
	r.Serial, r.Certificate, r.ValidBefore = serial, cert, &vb
	if err := s.put(i, r); err != nil {
		return Request{}, err
	}
	s.o.Logger.Info("elevation: approved", log.F("id", id), log.F("by", approver), log.F("serial", serial), log.F("selfApproved", self))
	return r, nil
}

func owners(st access.State) int {
	n := 0
	for _, a := range st.Admins {
		if a.Role == access.RoleOwner {
			n++
		}
	}
	return n
}

func (s *Service) sign(r Request, serial uint64, now time.Time) (string, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.PublicKey))
	if err != nil {
		return "", fmt.Errorf("elevation: the requester's key doesn't parse: %w", err)
	}
	c := &ssh.Certificate{
		Key:             pk,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("%s admin=%s fp=%s", Principal(r.ID), r.Admin, r.KeyFP),
		ValidPrincipals: []string{Principal(r.ID)},
		ValidAfter:      uint64(max(now.Unix(), 0)),                    // #nosec G115 -- clamped
		ValidBefore:     uint64(max(now.Add(ConnectWindow).Unix(), 0)), // #nosec G115 -- clamped
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"force-command": s.o.Elevated, "source-address": r.Source},
			Extensions:      map[string]string{"permit-pty": ""},
		},
	}
	if err := c.SignCert(rand.Reader, s.ca); err != nil {
		return "", fmt.Errorf("elevation: signing: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))), nil
}

// Principal is the maint principal request id opens.
func Principal(id string) string { return "elev-" + id }

// Deny refuses a pending request.
func (s *Service) Deny(id, by string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.live(id)
	if err != nil {
		return Request{}, err
	}
	r := s.cur.Requests[i]
	if r.State != Pending {
		return Request{}, codes.New(codes.ElevUsed, "%s was already %s", id, r.State)
	}
	now := s.now()
	r.State, r.Ended, r.EndReason = Denied, &now, ReasonDenied
	if err := s.put(i, r); err != nil {
		return Request{}, err
	}
	s.o.Logger.Info("elevation: denied", log.F("id", id), log.F("by", by))
	return r, nil
}

// Withdraw withdraws admin's own pending request (the closed shell's
// Ctrl-C while it waits for an approval). A withdrawn request can't be
// approved afterwards.
func (s *Service) Withdraw(admin, id string) (Request, error) {
	r, err := s.withdraw(admin, id)
	s.audit(osaudit.Entry{Actor: admin, Action: "elevation.withdraw", Target: id}, "ok", err)
	return r, err
}

func (s *Service) withdraw(admin, id string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.live(id)
	if err != nil {
		return Request{}, err
	}
	r := s.cur.Requests[i]
	if r.Admin != admin {
		return Request{}, codes.New(codes.ElevUnknown, "%s isn't yours to withdraw", id)
	}
	if r.State != Pending {
		return Request{}, codes.New(codes.ElevUsed, "%s was already %s", id, r.State)
	}
	now := s.now()
	r.State, r.Ended, r.EndReason = Withdrawn, &now, ReasonWithdrawn
	if err := s.put(i, r); err != nil {
		return Request{}, err
	}
	s.o.Logger.Info("elevation: withdrawn", log.F("id", id), log.F("by", admin))
	return r, nil
}

// Certificate returns admin's own approved request id, with its
// certificate.
func (s *Service) Certificate(admin, id string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.live(id)
	if err != nil {
		return Request{}, err
	}
	r := s.cur.Requests[i]
	if r.Admin != admin || r.Certificate == "" {
		return Request{}, codes.New(codes.ElevUnknown, "%s has no certificate of yours", id)
	}
	if r.State != Approved {
		return Request{}, codes.New(codes.ElevUsed, "%s's certificate was %s", id, r.State)
	}
	return r, nil
}

// Begin uses up the certificate sshd accepted for a maint login (the
// authorized_keys-style line from SSH_USER_AUTH): the request goes active,
// its principal leaves the principals file and its serial joins the
// revocation list before this returns. ends is when the time box runs out.
func (s *Service) Begin(certificate string, pid int) (Request, time.Time, error) {
	r, ends, err := s.begin(certificate, pid)
	s.audit(osaudit.Entry{Actor: r.Admin, KeyFP: r.KeyFP, Source: r.Source, Action: "elevation.connect", Target: r.ID,
		Detail: map[string]string{"serial": strconv.FormatUint(r.Serial, 10), "pid": strconv.Itoa(pid)}}, "ok", err)
	if err == nil {
		s.changed()
	}
	return r, ends, err
}

func (s *Service) begin(certificate string, pid int) (Request, time.Time, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certificate))
	if err != nil {
		return Request{}, time.Time{}, codes.New(codes.ElevUnknown, "the login's certificate doesn't parse")
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok || c.SignatureKey == nil || !slices.Equal(c.SignatureKey.Marshal(), s.ca.PublicKey().Marshal()) {
		return Request{}, time.Time{}, codes.New(codes.ElevUnknown, "the login's certificate isn't one of this box's elevation certificates")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool { return r.Serial == c.Serial && r.Certificate != "" })
	if i < 0 {
		return Request{}, time.Time{}, codes.New(codes.ElevUnknown, "no request has certificate serial %d", c.Serial)
	}
	r := s.cur.Requests[i]
	issued, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(r.Certificate))
	if perr != nil || !slices.Equal(issued.Marshal(), c.Marshal()) {
		return r, time.Time{}, codes.New(codes.ElevUnknown, "the certificate isn't the one issued for %s", r.ID)
	}
	now := s.now()
	if r.State == Approved && !now.Before(*r.ValidBefore) {
		r.State, r.Ended, r.EndReason = Expired, &now, ReasonExpired
		if err := s.put(i, r); err != nil {
			return r, time.Time{}, err
		}
		return r, time.Time{}, codes.New(codes.ElevExpired, "%s's certificate expired at %s", r.ID, r.ValidBefore.UTC().Format(time.RFC3339))
	}
	if r.State != Approved {
		return r, time.Time{}, codes.New(codes.ElevUsed, "%s's certificate was already used (%s)", r.ID, r.State)
	}
	r.State, r.Started, r.PID = Active, &now, pid
	if err := s.put(i, r); err != nil {
		return r, time.Time{}, err
	}
	s.o.Logger.Info("elevation: session started", log.F("id", r.ID), log.F("admin", r.Admin), log.F("pid", pid))
	return r, now.Add(time.Duration(r.Minutes) * time.Minute), nil
}

// End records how an active session ended and its recording's hash.
func (s *Service) End(id, reason, recordingSHA string) error {
	r, err := s.end(id, reason, recordingSHA)
	s.audit(osaudit.Entry{Actor: "sneakers-elevated", Action: "elevation.end", Target: id,
		Detail: map[string]string{"admin": r.Admin, "recordingSha256": recordingSHA}}, reason, err)
	return err
}

func (s *Service) end(id, reason, sha string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.live(id)
	if err != nil {
		return Request{}, err
	}
	r := s.cur.Requests[i]
	if r.State != Active {
		return r, codes.New(codes.ElevUsed, "%s isn't an active session (%s)", id, r.State)
	}
	now := s.now()
	r.State, r.Ended, r.EndReason, r.RecordingSHA256 = Ended, &now, reason, sha
	if err := s.put(i, r); err != nil {
		return r, err
	}
	s.o.Logger.Info("elevation: session ended", log.F("id", id), log.F("reason", reason))
	return r, nil
}

// Terminate ends an active session (its sneakers-elevated is told to
// stop and reports the end) or revokes an approved certificate nobody has
// used yet.
func (s *Service) Terminate(id, by string) (Request, error) {
	r, revoked, err := s.terminate(id, by)
	if revoked {
		s.changed()
	}
	return r, err
}

func (s *Service) terminate(id, by string) (Request, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, err := s.live(id)
	if err != nil {
		return Request{}, false, err
	}
	r := s.cur.Requests[i]
	switch r.State {
	case Active:
		s.o.Logger.Info("elevation: terminating", log.F("id", id), log.F("by", by), log.F("pid", r.PID))
		if s.o.Signal == nil {
			return r, false, errors.New("elevation: this service can't reach sessions")
		}
		if err := s.o.Signal(r.PID); err != nil {
			s.o.Logger.Warn("elevation: the session's process is gone; ended here", log.F("id", id), log.F("error", err.Error()))
			now := s.now()
			r.State, r.Ended, r.EndReason = Ended, &now, ReasonTerminated
			return r, false, s.put(i, r)
		}
		return r, false, nil
	case Approved:
		now := s.now()
		r.State, r.Ended, r.EndReason = Expired, &now, ReasonTerminated
		if err := s.put(i, r); err != nil {
			return r, false, err
		}
		s.o.Logger.Info("elevation: an unused certificate revoked", log.F("id", id), log.F("by", by))
		return r, true, nil
	}
	return r, false, codes.New(codes.ElevUsed, "%s is %s; there is nothing to terminate", id, r.State)
}

// Sweep expires pending requests past PendingFor and approved
// certificates past their connect window, and ends active sessions whose
// sneakers-elevated is gone. accessd runs it every minute.
func (s *Service) Sweep() {
	changed, expired := s.sweep()
	for _, r := range expired {
		s.audit(osaudit.Entry{Actor: "accessd", Action: "elevation.expire", Target: r.ID, Detail: map[string]string{"admin": r.Admin, "was": r.EndReason}}, r.EndReason, nil)
	}
	if changed {
		s.changed()
	}
}

func (s *Service) sweep() (bool, []Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	next := file{Requests: slices.Clone(s.cur.Requests)}
	var out []Request
	changed := false
	for i, r := range next.Requests {
		switch {
		case r.State == Pending && !now.Before(r.Requested.Add(PendingFor)):
			r.State, r.Ended, r.EndReason = Expired, &now, ReasonExpired
		case r.State == Approved && !now.Before(*r.ValidBefore):
			r.State, r.Ended, r.EndReason = Expired, &now, ReasonExpired
			changed = true
		case r.State == Active && s.o.Alive != nil && !s.o.Alive(r.PID):
			r.State, r.Ended, r.EndReason = Ended, &now, ReasonLost
		default:
			continue
		}
		next.Requests[i] = r
		out = append(out, r)
	}
	if len(out) == 0 {
		return false, nil
	}
	if err := s.save(next); err != nil {
		s.o.Logger.Error(err, "elevation: sweep not saved")
		return false, nil
	}
	return changed, out
}

// Get returns request id.
func (s *Service) Get(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool { return r.ID == id })
	if i < 0 {
		return Request{}, false
	}
	return s.cur.Requests[i], true
}

// List returns every request, newest first.
func (s *Service) List() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.cur.Requests)
	slices.Reverse(out)
	return out
}

// Principals are the maint principals of the approved, unused
// certificates.
func (s *Service) Principals() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	now := s.now()
	for _, r := range s.cur.Requests {
		if r.State == Approved && now.Before(*r.ValidBefore) {
			out = append(out, Principal(r.ID))
		}
	}
	return out
}

// Revoked are the serials on the revocation list: every certificate that
// was used, expired or revoked.
func (s *Service) Revoked() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked()
}

func (s *Service) revoked() []uint64 {
	var out []uint64
	for _, r := range s.cur.Requests {
		if r.Serial != 0 && r.State != Approved {
			out = append(out, r.Serial)
		}
	}
	return out
}

// Active reports an active elevated session (an automatic upgrade waits
// for it to end).
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.cur.Requests, func(r Request) bool { return r.State == Active })
}

// live finds request id, expiring it first when its time is up. Caller
// holds mu.
func (s *Service) live(id string) (int, error) {
	i := slices.IndexFunc(s.cur.Requests, func(r Request) bool { return r.ID == id })
	if i < 0 {
		return -1, codes.New(codes.ElevUnknown, "there is no elevation request %s", id)
	}
	r := s.cur.Requests[i]
	if r.State == Pending && !s.now().Before(r.Requested.Add(PendingFor)) {
		now := s.now()
		r.State, r.Ended, r.EndReason = Expired, &now, ReasonExpired
		if err := s.put(i, r); err != nil {
			return -1, err
		}
		return -1, codes.New(codes.ElevExpired, "%s waited %s without an approval and expired", id, PendingFor)
	}
	return i, nil
}

// put replaces request i and saves. Caller holds mu.
func (s *Service) put(i int, r Request) error {
	next := file{Requests: slices.Clone(s.cur.Requests)}
	next.Requests[i] = r
	return s.save(next)
}

// save writes next, then the revocation list from it. Caller holds mu.
func (s *Service) save(next file) error {
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("elevation: %w", err)
	}
	if err := writeFile(s.o.StateFile, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("elevation: %w", err)
	}
	s.cur = next
	return s.writeKRL()
}

// RevokeLoginKeys writes the revocation list with st's revoked login keys:
// the access store's Revoke, run inside its write.
func (s *Service) RevokeLoginKeys(st access.State) error {
	keys, err := st.RevokedPublicKeys()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.revokedKeys
	s.revokedKeys = keys
	if err := s.writeKRL(); err != nil {
		s.revokedKeys = prev
		return err
	}
	if len(keys) != len(prev) {
		s.o.Logger.Info("elevation: revocation list written", log.F("loginKeys", len(keys)), log.F("serials", len(s.revoked())))
	}
	return nil
}

// writeKRL writes the revocation list from the current requests and the
// revoked login keys. Caller holds mu (or is Open).
func (s *Service) writeKRL() error {
	revoked := s.revoked()
	krl := MarshalKRL(s.ca.PublicKey(), revoked, s.revokedKeys, uint64(len(revoked)+len(s.revokedKeys)), s.now())
	if err := writeFile(filepath.Join(s.o.SSHDir, RevokedFile), krl, 0o644); err != nil {
		return fmt.Errorf("elevation: revocation list: %w", err)
	}
	return nil
}

// nextSerial counts the serial file up and returns the new serial; the
// file is written before the serial is used, so no serial is issued twice.
// Caller holds mu.
func (s *Service) nextSerial() (uint64, error) {
	p := filepath.Join(s.o.SSHDir, SerialFile)
	var last uint64
	b, err := os.ReadFile(p) // #nosec G304 -- the serial file in the state directory
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return 0, fmt.Errorf("elevation: serial: %w", err)
	default:
		last, err = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("elevation: serial file doesn't parse: %w", err)
		}
	}
	for _, r := range s.cur.Requests {
		last = max(last, r.Serial)
	}
	next := last + 1
	if err := writeFile(p, []byte(strconv.FormatUint(next, 10)+"\n"), 0o600); err != nil {
		return 0, fmt.Errorf("elevation: serial: %w", err)
	}
	return next, nil
}

// idAlphabet leaves out 0, 1, I and O, which read alike.
const idAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// newID is E- and four characters no request has. Caller holds mu.
func (s *Service) newID() string {
	for {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		id := []byte("E-")
		for _, v := range b {
			id = append(id, idAlphabet[int(v)%len(idAlphabet)])
		}
		if !slices.ContainsFunc(s.cur.Requests, func(r Request) bool { return r.ID == string(id) }) {
			return string(id)
		}
	}
}

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
