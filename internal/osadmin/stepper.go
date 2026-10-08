// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// The step markers in Paths.SetupDir for the steps that change nothing.
const (
	NetworkSeenMarker    = "network-seen"
	ProtectionSeenMarker = "protection-seen"
)

// TOTPIssuer names the box in an authenticator app when it has no host
// name.
const TOTPIssuer = "sneakers-appliance"

func (h *setup) RedeemCode(ctx context.Context, r *connect.Request[osadminv1.RedeemCodeRequest]) (*connect.Response[osadminv1.RedeemCodeResponse], error) {
	c := callFrom(ctx)
	now := h.s.o.Clock.Now()
	if err := h.s.o.Lockout.Check("", c.source, now); err != nil {
		return nil, err
	}
	if err := h.s.allowListed(ctx, c.source); err != nil {
		return nil, err
	}
	cs := &codeSession{ID: weblogin.Secret(), CSRF: weblogin.Secret(), Source: c.source, Started: now, Expires: now.Add(CodeSessionLifetime)}
	expires := cs.Expires
	st := h.s.o.Access.Read()
	if name, ok := redeemInvite(st, r.Msg.GetCode(), now); ok {
		cs.Kind, cs.Admin = osadminv1.CodeKind_CODE_KIND_INVITE, name
		a, _ := st.Admin(name)
		expires = a.Invite.Expires
	} else {
		got, err := h.s.codes.Redeem(r.Msg.GetCode(), c.source)
		if err != nil {
			err = lockout.WithRefusal(err, lockout.Refusal{AttemptsLeft: h.s.codes.Setup().AttemptsLeft})
			fail := h.s.o.Lockout.Fail("", c.source, now, h.s.lockoutMode())
			if !fail.RetryAfter.IsZero() {
				h.s.write(osaudit.Entry{Actor: "accessd", Source: c.source, Action: "access.throttle", Target: c.source,
					Detail: map[string]string{"surface": osaudit.SurfaceAdmin, "until": fail.RetryAfter.UTC().Format(time.RFC3339)}}, nil)
			}
			return nil, err
		}
		switch got.Kind {
		case onetime.KindSetup:
			cs.Kind = osadminv1.CodeKind_CODE_KIND_SETUP
		case onetime.KindRecover:
			cs.Kind = osadminv1.CodeKind_CODE_KIND_RECOVER
		}
	}
	h.s.creds.mu.Lock()
	h.s.creds.sessions[cs.ID] = cs
	h.s.creds.mu.Unlock()
	c.code = cs
	c.note(cs.actor(), "kind", cs.Kind.String())
	h.s.o.Logger.Info("osadmin: a one-time code redeemed", log.F("kind", cs.Kind.String()), log.F("source", c.source))
	h.s.consoleChanged()
	out := &osadminv1.RedeemCodeResponse{Kind: cs.Kind, Admin: cs.Admin, Expires: timestamppb.New(expires), CsrfToken: cs.CSRF}
	if cs.Kind == osadminv1.CodeKind_CODE_KIND_RECOVER {
		for _, a := range st.Admins {
			if a.Role == access.RoleOwner {
				out.ExistingOwners = append(out.ExistingOwners, a.Name)
			}
		}
	}
	resp := connect.NewResponse(out)
	resp.Header().Add("Set-Cookie", codeCookie(cs.ID, CodeSessionLifetime))
	return resp, nil
}

// allowListed refuses a source outside the allow-list the firewall
// applies; an empty list (first boot) lets the management network in.
func (s *Server) allowListed(ctx context.Context, source string) error {
	g, err := s.networkSettings(ctx)
	if err != nil || len(g) == 0 {
		return nil
	}
	if !inPrefixes(source, g) {
		return codes.New(codes.AccessForbidden, "%s isn't on the list of who may connect", source)
	}
	return nil
}

func (h *setup) CheckPassword(ctx context.Context, r *connect.Request[osadminv1.CheckPasswordRequest]) (*connect.Response[osadminv1.CheckPasswordResponse], error) {
	pw, name := r.Msg.GetPassword(), r.Msg.GetAdmin()
	out := &osadminv1.CheckPasswordResponse{Ok: true, MinLength: credentials.MinPasswordLength}
	if err := credentials.CheckPassword(pw, name); err != nil {
		out.Ok, out.Message = false, codes.Describe(err)
		out.TooShort = len([]rune(pw)) < credentials.MinPasswordLength
		out.Breached = !out.TooShort && credentials.Breached(pw)
	}
	return connect.NewResponse(out), nil
}

func (h *setup) BeginCredentials(ctx context.Context, r *connect.Request[osadminv1.BeginCredentialsRequest]) (*connect.Response[osadminv1.BeginCredentialsResponse], error) {
	c := callFrom(ctx)
	if c.code == nil {
		return nil, codes.New(codes.AccessSession, "type the one-time code first")
	}
	cs := *c.code
	name := r.Msg.GetAdmin()
	c.note(name, "kind", cs.Kind.String())
	if cs.Kind == osadminv1.CodeKind_CODE_KIND_SETUP && h.s.FirstAdminDone() {
		return nil, codes.New(codes.SetupIncomplete, "the first admin exists already; sign in instead")
	}
	if err := h.s.credentialsTarget(cs, name); err != nil {
		return nil, err
	}
	if err := credentials.CheckPassword(r.Msg.GetPassword(), name); err != nil {
		return nil, err
	}
	hash, err := credentials.HashPassword(h.s.o.RootKey.Pepper(), r.Msg.GetPassword())
	if err != nil {
		return nil, err
	}
	en, err := h.s.creds.startEnrolment(name, hash, cs.ID, "", h.s.o.Clock.Now())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.BeginCredentialsResponse{Totp: h.s.totpToWire(en)}), nil
}

// credentialsTarget checks name against what the code session may set up.
func (s *Server) credentialsTarget(cs codeSession, name string) error {
	st := s.o.Access.Read()
	a, exists := st.Admin(name)
	switch cs.Kind {
	case osadminv1.CodeKind_CODE_KIND_SETUP:
		if !access.ValidName(name) {
			return codes.New(codes.AccessName, "%q isn't a valid admin name: use 2 to 31 lowercase letters, digits, _ or -, starting with a letter", name)
		}
		if exists {
			return codes.New(codes.AccessName, "there is already an admin named %q", name)
		}
	case osadminv1.CodeKind_CODE_KIND_INVITE:
		if name != cs.Admin {
			return codes.New(codes.AccessName, "this invitation is for %s", cs.Admin)
		}
	case osadminv1.CodeKind_CODE_KIND_RECOVER:
		if exists && a.Role != access.RoleOwner {
			return codes.New(codes.AccessForbidden, "Recover access resets an owner, or makes a new one; %s isn't an owner", name)
		}
		if !exists && !access.ValidName(name) {
			return codes.New(codes.AccessName, "%q isn't a valid admin name", name)
		}
	default:
		return codes.New(codes.AccessSession, "type the one-time code first")
	}
	return nil
}

func (f *credentialFlows) startEnrolment(admin, hash, codeID, session string, now time.Time) (*enrolment, error) {
	secret, err := credentials.NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	en := &enrolment{ID: weblogin.Secret(), Admin: admin, Hash: hash, Secret: secret, Expires: now.Add(EnrolmentLifetime), CodeID: codeID, Session: session, Replaces: session != ""}
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, e := range f.enrolling {
		if !now.Before(e.Expires) || (codeID != "" && e.CodeID == codeID) {
			delete(f.enrolling, id)
		}
	}
	f.enrolling[en.ID] = en
	return en, nil
}

// enrolmentOf returns the live enrolment id.
func (f *credentialFlows) enrolmentOf(id string, now time.Time) (*enrolment, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.enrolling[id]
	if !ok || !now.Before(e.Expires) {
		delete(f.enrolling, id)
		return nil, false
	}
	return e, true
}

func (f *credentialFlows) drop(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.enrolling, id)
}

func (s *Server) totpToWire(en *enrolment) *osadminv1.TotpEnrolment {
	issuer := s.issuer()
	return &osadminv1.TotpEnrolment{
		Id: en.ID, Secret: credentials.Base32(en.Secret), Uri: credentials.URI(en.Secret, issuer, en.Admin),
		Issuer: issuer, Account: en.Admin, Digits: credentials.Digits, PeriodSeconds: int32(credentials.Period.Seconds()),
		Algorithm: credentials.Algorithm, Expires: timestamppb.New(en.Expires),
	}
}

// issuer is the box's host name, for the authenticator app's label.
func (s *Server) issuer() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if st, err := s.netStatus(ctx); err == nil && st != "" {
		return st
	}
	return TOTPIssuer
}

// checkNewTOTP checks the first code from a new authenticator.
func checkNewTOTP(en *enrolment, code string, now time.Time) (uint64, error) {
	step, ok := credentials.VerifyTOTP(en.Secret, code, now, 0)
	if !ok {
		return 0, codes.New(codes.AccessCredentials, "that code isn't from the new authenticator; check its clock and try the next code")
	}
	return step, nil
}

func (h *setup) CompleteCredentials(ctx context.Context, r *connect.Request[osadminv1.CompleteCredentialsRequest]) (*connect.Response[osadminv1.CompleteCredentialsResponse], error) {
	c := callFrom(ctx)
	if c.code == nil {
		return nil, codes.New(codes.AccessSession, "type the one-time code first")
	}
	cs := *c.code
	now := h.s.o.Clock.Now()
	en, ok := h.s.creds.enrolmentOf(r.Msg.GetEnrolmentId(), now)
	if !ok || en.CodeID != cs.ID {
		return nil, codes.New(codes.SetupIncomplete, "that authenticator setup has expired; start the step again")
	}
	c.note(en.Admin, "kind", cs.Kind.String())
	if err := h.s.o.Lockout.Check("", c.source, now); err != nil {
		return nil, err
	}
	step, err := checkNewTOTP(en, r.Msg.GetTotpCode(), now)
	if err != nil {
		h.s.o.Lockout.Fail("", c.source, now, h.s.lockoutMode())
		return nil, err
	}
	if err := h.s.credentialsTarget(cs, en.Admin); err != nil {
		return nil, err
	}
	sealed, err := credentials.SealTOTP(h.s.o.RootKey.Pepper(), en.Admin, en.Secret)
	if err != nil {
		return nil, err
	}
	utc := now.UTC()
	pw, totp := &access.Password{Hash: en.Hash, Changed: utc}, &access.TOTP{Sealed: sealed, Added: utc}
	first := false
	err = h.s.o.Access.UpdateAs(cs.actor(), func(st *access.State) error {
		a, exists := st.Admin(en.Admin)
		switch {
		case cs.Kind == osadminv1.CodeKind_CODE_KIND_SETUP:
			if len(st.Admins) > 0 {
				return codes.New(codes.SetupIncomplete, "the first admin exists already; sign in instead")
			}
			a = st.AddAdmin(en.Admin, access.RoleOwner, "setup", utc)
			st.Quorum = &access.QuorumRoster{Members: []string{en.Admin}, Required: 1}
			first = true
		case cs.Kind == osadminv1.CodeKind_CODE_KIND_RECOVER && !exists:
			a = st.AddAdmin(en.Admin, access.RoleOwner, "recover-access", utc)
			addToRoster(st, en.Admin)
		case !exists:
			return codes.New(codes.AccessName, "there is no admin named %q any more", en.Admin)
		}
		a.Password, a.TOTP, a.Invite = pw, totp, nil
		if cs.Kind == osadminv1.CodeKind_CODE_KIND_RECOVER {
			st.LastRecoverAccess = &utc
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	h.s.creds.drop(en.ID)
	h.s.endCodeSession(cs.ID)
	h.s.sessions.EndWhere(func(x weblogin.Session) bool { return x.Admin == en.Admin })
	h.s.o.Lockout.Forget(en.Admin)
	h.s.o.Lockout.SetStep(en.Admin, step)
	switch cs.Kind {
	case osadminv1.CodeKind_CODE_KIND_SETUP:
		h.s.codes.ConsumeSetup()
	case osadminv1.CodeKind_CODE_KIND_RECOVER:
		h.s.codes.EndRecover()
	}
	if first {
		if err := h.s.mark(FirstAdminMarker); err != nil {
			h.s.o.Logger.Error(err, "osadmin: the first admin wasn't marked")
		}
		h.s.o.Logger.Info("osadmin: the first admin exists", log.F("admin", en.Admin))
		if h.s.o.OnFirstAdmin != nil {
			h.s.o.OnFirstAdmin()
		}
	}
	h.s.consoleChanged()
	st := h.s.o.Access.Read()
	a, _ := st.Admin(en.Admin)
	sess, notices := h.s.newSession(*a, c.source, c.userAgent)
	c.session = sess
	h.s.o.Logger.Info("osadmin: credentials set", log.F("admin", en.Admin), log.F("kind", cs.Kind.String()))
	resp := connect.NewResponse(&osadminv1.CompleteCredentialsResponse{Session: h.s.toSession(sess, a.Role, notices...)})
	resp.Header().Add("Set-Cookie", sessionCookie(sess.ID, weblogin.MaxAge))
	resp.Header().Add("Set-Cookie", codeCookie("", -1))
	return resp, nil
}

func (h *setup) AcknowledgeStep(ctx context.Context, r *connect.Request[osadminv1.AcknowledgeStepRequest]) (*connect.Response[osadminv1.AcknowledgeStepResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetStep().String())
	var marker string
	switch r.Msg.GetStep() {
	case osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK:
		marker = NetworkSeenMarker
	case osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION:
		marker = ProtectionSeenMarker
	default:
		return nil, codes.New(codes.SetupIncomplete, "only the network and protection steps are acknowledged; the others finish by doing them")
	}
	steps := h.s.setupSteps()
	for _, st := range steps {
		if st.GetKind() == r.Msg.GetStep() {
			break
		}
		if !st.GetDone() {
			return nil, codes.New(codes.SetupIncomplete, "step %d is still open", st.GetNumber())
		}
	}
	if err := h.s.mark(marker); err != nil {
		return nil, err
	}
	h.s.consoleChanged()
	return connect.NewResponse(&osadminv1.AcknowledgeStepResponse{}), nil
}

// setupSteps are the stepper's six steps and whether each is done.
func (s *Server) setupSteps() []*osadminv1.SetupStep {
	st := s.o.Access.Read()
	dir := s.o.Paths.SetupDir()
	done := s.SetupDone()
	esc, _ := s.newestEscrow()
	first := s.FirstAdminDone()
	_, codeInUse := s.liveSetupSession()
	type step struct {
		kind     osadminv1.SetupStepKind
		done     bool
		optional bool
	}
	steps := []step{
		{osadminv1.SetupStepKind_SETUP_STEP_KIND_CODE, first || codeInUse, false},
		{osadminv1.SetupStepKind_SETUP_STEP_KIND_ADMIN, first, false},
		{osadminv1.SetupStepKind_SETUP_STEP_KIND_RECOVERY_KEYS, len(st.RecoveryKeys) > 0 && esc != "", false},
		{osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK, exists(filepath.Join(dir, NetworkSeenMarker)), true},
		{osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION, exists(filepath.Join(dir, ProtectionSeenMarker)), false},
		{osadminv1.SetupStepKind_SETUP_STEP_KIND_SIGN_IN, done, false},
	}
	out := make([]*osadminv1.SetupStep, 0, len(steps))
	for i, x := range steps {
		out = append(out, &osadminv1.SetupStep{Number: int32(i + 1), Kind: x.kind, Done: done || x.done, Optional: x.optional}) // #nosec G115 -- six steps
	}
	return out
}

// currentStep is the first step not done, 0 once setup is.
func currentStep(steps []*osadminv1.SetupStep) (int32, osadminv1.SetupStepKind) {
	for _, s := range steps {
		if !s.GetDone() {
			return s.GetNumber(), s.GetKind()
		}
	}
	return 0, osadminv1.SetupStepKind_SETUP_STEP_KIND_UNSPECIFIED
}

// dummyHash is what an unknown name's password is checked against, so the
// answer takes as long as for a real one.
var dummyHash = sync.OnceValue(func() string {
	h, _ := credentials.HashPassword(make([]byte, 32), "not a password anyone has")
	return h
})

// networkSettings is the allow-list netd applies.
func (s *Server) networkSettings(ctx context.Context) ([]string, error) {
	g, err := s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return nil, err
	}
	return g.Msg.GetSettings().GetAllowList(), nil
}

// netStatus is the box's host name.
func (s *Server) netStatus(ctx context.Context) (string, error) {
	st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return "", err
	}
	return st.Msg.GetHostname(), nil
}

// inPrefixes reports whether address addr falls in one of prefixes.
func inPrefixes(addr string, prefixes []string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		pf, err := netip.ParsePrefix(p)
		if err != nil {
			if one, aerr := netip.ParseAddr(p); aerr == nil && one.Unmap() == a {
				return true
			}
			continue
		}
		if pf.Contains(a) {
			return true
		}
	}
	return false
}
