// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// call is what the interceptor learned about a request, for the handler
// and the audit entry.
type call struct {
	procedure string
	session   weblogin.Session
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

// authorize checks the session, the admin and key it is bound to, the
// role, the CSRF token and the step-up.
func (s *Server) authorize(c *call, rule *osadminv1.Rule, read bool) error {
	sess, err := s.session(c.header)
	if err != nil {
		return err
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
		return codes.New(codes.AccessStepUpRequired, "this needs a sign-in from the last 5 minutes; sign in again with a new code")
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

// liveRole checks the session's admin and key still exist and returns the
// admin's current role. A session whose admin or key is gone ends here.
func (s *Server) liveRole(sess weblogin.Session) (access.Role, error) {
	st := s.o.Access.Read()
	a, ok := st.Admin(sess.Admin)
	if !ok || !hasKey(a, sess.KeyFP) {
		s.sessions.End(sess.ID)
		s.o.Logger.Info("osadmin: session ended, its admin or key was removed", log.F("admin", sess.Admin))
		return "", codes.New(codes.AccessSession, "the admin or key this session signed in with was removed; sign in again")
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

// audit writes the entry for a method whose rule names an action.
func (s *Server) audit(c *call, rule *osadminv1.Rule, err error) {
	if rule.GetAudit() == "" {
		return
	}
	s.write(osaudit.Entry{Actor: c.session.Admin, KeyFP: c.session.KeyFP, Source: c.source, Action: rule.GetAudit(), Target: c.target, Detail: c.detail}, err)
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
	case codes.AccessSession:
		c = connect.CodeUnauthenticated
	case codes.AccessForbidden, codes.AccessStepUpRequired:
		c = connect.CodePermissionDenied
	case codes.AccessKeyType, codes.AccessKeyWeak, codes.AccessName, codes.AccessConfirm, codes.NetInvalid:
		c = connect.CodeInvalidArgument
	case codes.LoginCode:
		c = connect.CodeNotFound
	}
	return connect.NewError(c, errors.New(codes.Describe(err)))
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
