// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// call is what the interceptor learned about a request, for the handler
// and the audit entry.
type call struct {
	procedure string
	session   weblogin.Session
	// code is the redeemed one-time code's session, for a code_session
	// method called without a signed-in admin.
	code *codeSession
	// keyFP is the SSH key of a closed-shell login, for the audit entry.
	keyFP     string
	role      access.Role
	source    string
	userAgent string
	header    http.Header
	// target and detail are set by the handler for the audit entry.
	target string
	detail map[string]string
}

type callKey struct{}

func callFrom(ctx context.Context) *call {
	c, _ := ctx.Value(callKey{}).(*call)
	if c == nil {
		return &call{}
	}
	return c
}

func (c *call) note(target string, detail ...string) {
	c.target = target
	for i := 0; i+1 < len(detail); i += 2 {
		if c.detail == nil {
			c.detail = map[string]string{}
		}
		c.detail[detail[i]] = detail[i+1]
	}
}

// RuleOf returns the method's Rule, or nil when it has none.
func RuleOf(md protoreflect.MethodDescriptor) *osadminv1.Rule {
	if md == nil {
		return nil
	}
	opts, ok := md.Options().(*descriptorpb.MethodOptions)
	if !ok || opts == nil || !proto.HasExtension(opts, osadminv1.E_Rule) {
		return nil
	}
	r, _ := proto.GetExtension(opts, osadminv1.E_Rule).(*osadminv1.Rule)
	return r
}

func readOnly(md protoreflect.MethodDescriptor) bool {
	opts, ok := md.Options().(*descriptorpb.MethodOptions)
	return ok && opts.GetIdempotencyLevel() == descriptorpb.MethodOptions_NO_SIDE_EFFECTS
}

func (s *Server) interceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			md, _ := req.Spec().Schema.(protoreflect.MethodDescriptor)
			c := &call{procedure: req.Spec().Procedure, source: hostOf(req.Peer().Addr), userAgent: req.Header().Get("User-Agent"), header: req.Header()}
			rule := RuleOf(md)
			if rule == nil {
				s.o.Logger.Error(nil, "osadmin: a method has no rule; refused", log.F("procedure", c.procedure))
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("this method has no access rule"))
			}
			ctx = context.WithValue(ctx, callKey{}, c)
			if !rule.GetPublic() {
				if err := s.authorize(c, rule, readOnly(md)); err != nil {
					s.audit(c, rule, err)
					return nil, toConnect(err)
				}
			}
			if err := s.setupGate(c, rule); err != nil {
				s.o.Logger.Warn("osadmin: a setup call after setup; refused", log.F("procedure", c.procedure), log.F("admin", c.session.Admin), log.F("source", c.source))
				s.audit(c, rule, err)
				return nil, toConnect(err)
			}
			s.o.Logger.Debug("osadmin: call", log.F("procedure", c.procedure), log.F("admin", c.session.Admin), log.F("source", c.source))
			resp, err := next(ctx, req)
			if err != nil && connect.CodeOf(err) == connect.CodeUnimplemented {
				err = notAvailable()
			}
			s.audit(c, rule, err)
			if err != nil {
				s.o.Logger.Warn("osadmin: call failed", log.F("procedure", c.procedure), log.F("admin", c.session.Admin), log.F("error", describe(err)))
				return nil, toConnect(err)
			}
			return resp, nil
		}
	}
}

// setupGate is the one setup-done check: once setup is done a
// setup_only method, and any call made with a setup code's session, is
// refused.
func (s *Server) setupGate(c *call, rule *osadminv1.Rule) error {
	setupCode := c.code != nil && c.code.Kind == osadminv1.CodeKind_CODE_KIND_SETUP
	if !rule.GetSetupOnly() && !setupCode {
		return nil
	}
	if !s.SetupDone() {
		return nil
	}
	return codes.New(codes.SetupDone, "setup is done; this is a setup step")
}

// authorize checks the session (or, for a code_session method, the
// redeemed code's), the admin it is bound to, the role, the CSRF token and
// the step-up.
func (s *Server) authorize(c *call, rule *osadminv1.Rule, read bool) error {
	sess, err := s.session(c.header)
	if err != nil && rule.GetCodeSession() {
		cs, cerr := s.codeSessionOf(c.header)
		if cerr != nil {
			return err
		}
		if !read && subtle.ConstantTimeCompare([]byte(c.header.Get(CSRFHeader)), []byte(cs.CSRF)) != 1 {
			return codes.New(codes.AccessForbidden, "the request's CSRF token is missing or wrong; reload the page")
		}
		c.code = &cs
		return nil
	}
	if err != nil {
		return err
	}
	if rule.GetRole() == osadminv1.Role_ROLE_UNSPECIFIED {
		return codes.New(codes.AccessForbidden, "this is done with a one-time code, not a signed-in session")
	}
	c.session = sess
	role, err := s.liveRole(sess)
	if err != nil {
		return err
	}
	c.role = role
	if rule.GetRole() == osadminv1.Role_ROLE_OWNER && role != access.RoleOwner {
		return codes.New(codes.AccessForbidden, "only an owner may do this")
	}
	if !read && subtle.ConstantTimeCompare([]byte(c.header.Get(CSRFHeader)), []byte(sess.CSRF)) != 1 {
		return codes.New(codes.AccessForbidden, "the request's CSRF token is missing or wrong; reload the page")
	}
	if rule.GetStepUp() && !s.sessions.Fresh(sess) {
		return codes.New(codes.AccessStepUpRequired, "this needs a fresh authenticator code; confirm it's you")
	}
	return nil
}

// session returns the live session named by the request's cookie.
func (s *Server) session(h http.Header) (weblogin.Session, error) {
	r := http.Request{Header: h}
	ck, err := r.Cookie(CookieName)
	if err != nil || ck.Value == "" {
		return weblogin.Session{}, codes.New(codes.AccessSession, "sign in first")
	}
	sess, ok := s.sessions.Get(ck.Value)
	if !ok {
		return weblogin.Session{}, codes.New(codes.AccessSession, "the session has ended; sign in again")
	}
	return sess, nil
}

// liveRole checks the session's admin still exists and can sign in, and
// returns the admin's current role. A session whose admin is gone ends
// here.
func (s *Server) liveRole(sess weblogin.Session) (access.Role, error) {
	st := s.o.Access.Read()
	a, ok := st.Admin(sess.Admin)
	if !ok || !a.HasCredentials() {
		s.sessions.End(sess.ID)
		s.o.Logger.Info("osadmin: session ended, its admin was removed or re-invited", log.F("admin", sess.Admin))
		return "", codes.New(codes.AccessSession, "the admin this session signed in as was removed or re-invited; sign in again")
	}
	return a.Role, nil
}

func hasKey(a *access.Admin, fp string) bool {
	for _, k := range a.Keys {
		if k.Fingerprint == fp {
			return true
		}
	}
	return false
}

// SurfaceSSH marks an audit entry from a closed-shell login.
const SurfaceSSH = "ssh"

// Local is a caller on access.sock that accessd named by its peer uid: a
// closed-shell login (Admin set, KeyFP the key sshd says signed it in, when
// the shell knows it) or the console (Admin empty, an owner named console).
type Local struct {
	Admin, KeyFP, Source string
}

// RunLocal runs fn, the body of procedure, as l: the procedure's rule
// decides the role it needs (no session, CSRF or step-up: the caller
// authenticated to sshd or sits at the console), and the call is audited
// like one from :8443, from the ssh or console surface.
func (s *Server) RunLocal(ctx context.Context, l Local, procedure string, fn func(context.Context) error) error {
	md := methodOf(procedure)
	rule := RuleOf(md)
	if rule == nil {
		s.o.Logger.Error(nil, "osadmin: a local call names a method with no rule; refused", log.F("procedure", procedure))
		return connect.NewError(connect.CodePermissionDenied, errors.New("this method has no access rule"))
	}
	surface := SurfaceSSH
	if l.Admin == "" {
		surface = osaudit.SurfaceConsole
	}
	c := &call{procedure: procedure, source: l.Source, detail: map[string]string{"surface": surface}}
	err := s.localIdentity(c, l, rule)
	if err == nil {
		s.o.Logger.Debug("osadmin: local call", log.F("procedure", procedure), log.F("admin", c.session.Admin))
		err = fn(context.WithValue(ctx, callKey{}, c))
		if err != nil && connect.CodeOf(err) == connect.CodeUnimplemented {
			err = notAvailable()
		}
	}
	if c.detail == nil {
		c.detail = map[string]string{}
	}
	c.detail["surface"] = surface
	s.audit(c, rule, err)
	if err != nil {
		s.o.Logger.Warn("osadmin: local call failed", log.F("procedure", procedure), log.F("admin", c.session.Admin), log.F("error", describe(err)))
		return toConnect(err)
	}
	return nil
}

func (s *Server) localIdentity(c *call, l Local, rule *osadminv1.Rule) error {
	if l.Admin == "" {
		c.session, c.role = weblogin.Session{Admin: osaudit.SurfaceConsole}, access.RoleOwner
		return nil
	}
	c.session, c.keyFP = weblogin.Session{Admin: l.Admin}, l.KeyFP
	st := s.o.Access.Read()
	a, ok := st.Admin(l.Admin)
	if !ok {
		return codes.New(codes.AccessSession, "there is no admin named %q any more", l.Admin)
	}
	if l.KeyFP != "" && !hasKey(a, l.KeyFP) {
		return codes.New(codes.AccessForbidden, "that key isn't one of %s's keys", a.Name)
	}
	c.role = a.Role
	if rule.GetRole() == osadminv1.Role_ROLE_OWNER && a.Role != access.RoleOwner {
		return codes.New(codes.AccessForbidden, "only an owner may do this")
	}
	return nil
}

// methodOf finds a procedure's method descriptor, or nil.
func methodOf(procedure string) protoreflect.MethodDescriptor {
	name := strings.ReplaceAll(strings.TrimPrefix(procedure, "/"), "/", ".")
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil
	}
	md, _ := d.(protoreflect.MethodDescriptor)
	return md
}

// audit writes the entry for a method whose rule names an action.
func (s *Server) audit(c *call, rule *osadminv1.Rule, err error) {
	if rule.GetAudit() == "" {
		return
	}
	actor := c.session.Admin
	if actor == "" && c.code != nil {
		actor = c.code.actor()
	}
	s.write(osaudit.Entry{Actor: actor, KeyFP: c.keyFP, Source: c.source, Action: rule.GetAudit(), Target: c.target, Detail: c.detail}, err)
}

// write appends e with the outcome of err.
func (s *Server) write(e osaudit.Entry, err error) {
	e.Outcome = "ok"
	if err != nil {
		e.Outcome = "refused"
		e.Code = symbolOf(err)
	}
	if e.Detail == nil {
		e.Detail = map[string]string{}
	}
	if _, set := e.Detail["surface"]; !set {
		e.Detail["surface"] = osaudit.SurfaceAdmin
	}
	if aerr := s.o.Audit.Append(e); aerr != nil {
		s.o.Logger.Error(aerr, "osadmin: audit append failed", log.F("action", e.Action))
	}
}

func symbolOf(err error) string {
	if code, ok := codes.Of(err); ok {
		return codes.Symbol(code)
	}
	if ce := new(connect.Error); errors.As(err, &ce) {
		return ce.Code().String()
	}
	return "internal"
}

func describe(err error) string {
	if _, ok := codes.Of(err); ok {
		return codes.Describe(err)
	}
	return err.Error()
}

// toConnect maps a coded error to a Connect error whose message starts with
// the code's symbol. Connect errors from the daemons pass through.
func toConnect(err error) error {
	if ce := new(connect.Error); errors.As(err, &ce) {
		return ce
	}
	code, ok := codes.Of(err)
	if !ok {
		return connect.NewError(connect.CodeInternal, errors.New("internal error; see the box's log"))
	}
	c := connect.CodeFailedPrecondition
	switch code {
	case codes.AccessSession, codes.AccessCredentials:
		c = connect.CodeUnauthenticated
	case codes.AccessForbidden, codes.AccessStepUpRequired:
		c = connect.CodePermissionDenied
	case codes.AccessKeyType, codes.AccessKeyWeak, codes.AccessName, codes.AccessConfirm, codes.NetInvalid, codes.AccessPassword, codes.AccessPolicy, codes.AccessQuorum:
		c = connect.CodeInvalidArgument
	case codes.AccessLocked, codes.AccessThrottled:
		c = connect.CodeResourceExhausted
	case codes.SetupCode, codes.RootChallenge, codes.RootCode:
		c = connect.CodeNotFound
	}
	ce := connect.NewError(c, errors.New(codes.Describe(err)))
	if r := lockout.RefusalOf(err); r != (lockout.Refusal{}) || code == codes.AccessCredentials || code == codes.SetupCode || code == codes.RootCode {
		if d, derr := connect.NewErrorDetail(refusalToWire(r)); derr == nil {
			ce.AddDetail(d)
		}
	}
	return ce
}

// refusalToWire is a lockout refusal as the pages read it.
func refusalToWire(r lockout.Refusal) *osadminv1.SignInRefusal {
	out := &osadminv1.SignInRefusal{AttemptsLeft: int32(min(r.AttemptsLeft, 1<<30)), LockedUntilUnlocked: r.UntilUnlocked} // #nosec G115 -- clamped
	if !r.LockedUntil.IsZero() {
		out.LockedUntil = timestamppb.New(r.LockedUntil)
	}
	if !r.RetryAfter.IsZero() {
		out.RetryAfter = timestamppb.New(r.RetryAfter)
	}
	return out
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
