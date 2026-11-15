// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	netmodel "github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// HandoffTTL is how long the code SetHostname hands the page lasts.
const HandoffTTL = 2 * time.Minute

// certServedWait is how long SetHostname waits for :8443 to serve the
// certificate made for the new name.
const certServedWait = 30 * time.Second

// HostLookup is what a name resolves to.
type HostLookup struct {
	// Addrs are the name's A and AAAA records.
	Addrs []netip.Addr
	// Found is false when the name isn't in DNS or has no such record.
	Found bool
}

// HostResolver looks a name up through the box's own DNS servers. A lookup
// no server answered is NET_DNS.
type HostResolver interface {
	Resolve(ctx context.Context, name string) (HostLookup, error)
}

// netdResolver is the default: netd's lookup.
type netdResolver struct{ s *Server }

func (r netdResolver) Resolve(ctx context.Context, name string) (HostLookup, error) {
	res, err := r.s.o.Network.Resolve(ctx, connect.NewRequest(&netdv1.ResolveRequest{Name: name}))
	if err != nil {
		if strings.Contains(err.Error(), codes.Symbol(codes.NetDNS)) {
			return HostLookup{}, codes.New(codes.NetDNS, "none of the box's DNS servers answered for %s", name)
		}
		return HostLookup{}, err
	}
	out := HostLookup{Found: res.Msg.GetFound()}
	for _, a := range res.Msg.GetAddresses() {
		if ip, perr := netip.ParseAddr(a); perr == nil {
			out.Addrs = append(out.Addrs, ip.Unmap())
		}
	}
	return out, nil
}

func (s *Server) resolver() HostResolver {
	if s.o.Resolver != nil {
		return s.o.Resolver
	}
	return netdResolver{s}
}

// handoffStore holds the one-time codes SetHostname hands out: in memory
// only, keyed by the code's digest, so a restart forgets them and nothing
// readable is kept.
type handoffStore struct {
	mu    sync.Mutex
	codes map[[32]byte]handoff
}

type handoff struct {
	admin, session string
	expires        time.Time
}

func (h *handoffStore) put(code string, v handoff, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.codes == nil {
		h.codes = map[[32]byte]handoff{}
	}
	for k, o := range h.codes {
		if !now.Before(o.expires) {
			delete(h.codes, k)
		}
	}
	h.codes[sha256.Sum256([]byte(code))] = v
}

// take removes and returns the code's entry; the code works once.
func (h *handoffStore) take(code string) (handoff, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := sha256.Sum256([]byte(code))
	v, ok := h.codes[k]
	delete(h.codes, k)
	return v, ok
}

// networkStepOpen says whether setup stands at its network step: too early
// before it, and done (or Network's) after.
func (s *Server) networkStepOpen() error {
	for _, st := range s.setupSteps() {
		if st.GetKind() != osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK {
			continue
		}
		if st.GetDone() {
			return codes.New(codes.SetupStepDone, "the network step is done; change the host name on Network")
		}
		if cur, _ := currentStep(s.setupSteps()); cur != st.GetNumber() {
			return codes.New(codes.SetupIncomplete, "finish the earlier steps first; the host name is the network step's")
		}
		return nil
	}
	return nil
}

// hostnameVerdict is a name checked against the box's DNS servers.
type hostnameVerdict struct {
	name       string
	result     osadminv1.HostnameCheck
	code       int
	message    string
	addrs      []*osadminv1.HostnameAddress
	management []string
}

func normalHostname(raw string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if !netmodel.ValidHostname(name) {
		return "", codes.New(codes.NetInvalid, "the host name must be a fully qualified name, such as appliance.example.org")
	}
	return name, nil
}

// checkHostname looks name up and says whether it points at this box. A
// lookup that failed for any reason but NET_DNS is the error.
func (s *Server) checkHostname(ctx context.Context, name string) (hostnameVerdict, error) {
	v := hostnameVerdict{name: name}
	st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return v, err
	}
	v.management = netdapi.Bare(st.Msg.GetManagementAddresses())
	mine := map[netip.Addr]bool{}
	for _, m := range v.management {
		if ip, perr := netip.ParseAddr(m); perr == nil {
			mine[ip.Unmap()] = true
		}
	}
	look, err := s.resolver().Resolve(ctx, name)
	switch {
	case err != nil && codes.Is(err, codes.NetDNS):
		v.result, v.code = osadminv1.HostnameCheck_HOSTNAME_CHECK_DNS_DOWN, codes.NetDNS
		v.message = "None of the box's DNS servers answered, so the name can't be checked now. You can go on and set it on Network later."
		return v, nil
	case err != nil:
		return v, err
	case !look.Found || len(look.Addrs) == 0:
		v.result, v.code = osadminv1.HostnameCheck_HOSTNAME_CHECK_NOT_FOUND, codes.NetNameNotFound
		v.message = fmt.Sprintf("%s isn't in DNS yet. Add a record pointing at %s, then check again.", name, strings.Join(v.management, ", "))
		return v, nil
	}
	var seen []string
	match := false
	for _, a := range look.Addrs {
		here := mine[a.Unmap()]
		match = match || here
		v.addrs = append(v.addrs, &osadminv1.HostnameAddress{Address: a.String(), ThisBox: here})
		seen = append(seen, a.String())
	}
	if match {
		v.result = osadminv1.HostnameCheck_HOSTNAME_CHECK_MATCH
		v.message = fmt.Sprintf("%s points at this box.", name)
		return v, nil
	}
	v.result, v.code = osadminv1.HostnameCheck_HOSTNAME_CHECK_ELSEWHERE, codes.NetNameElsewhere
	v.message = fmt.Sprintf("%s points at %s, not this box (%s).", name, strings.Join(seen, ", "), strings.Join(v.management, ", "))
	return v, nil
}

func resultWord(r osadminv1.HostnameCheck) string {
	switch r {
	case osadminv1.HostnameCheck_HOSTNAME_CHECK_MATCH:
		return "match"
	case osadminv1.HostnameCheck_HOSTNAME_CHECK_ELSEWHERE:
		return "elsewhere"
	case osadminv1.HostnameCheck_HOSTNAME_CHECK_NOT_FOUND:
		return "not-found"
	}
	return "dns-down"
}

func (h *setup) CheckHostname(ctx context.Context, r *connect.Request[osadminv1.CheckHostnameRequest]) (*connect.Response[osadminv1.CheckHostnameResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetHostname())
	if err := h.s.networkStepOpen(); err != nil {
		return nil, err
	}
	name, err := normalHostname(r.Msg.GetHostname())
	if err != nil {
		return nil, err
	}
	v, err := h.s.checkHostname(ctx, name)
	if err != nil {
		return nil, err
	}
	match := v.result == osadminv1.HostnameCheck_HOSTNAME_CHECK_MATCH
	c.note(name, "match", fmt.Sprint(match), "result", resultWord(v.result))
	h.s.o.Logger.Debug("osadmin: setup host name checked", log.F("hostname", name), log.F("result", resultWord(v.result)), log.F("by", c.session.Admin))
	out := &osadminv1.CheckHostnameResponse{Hostname: name, Result: v.result, Addresses: v.addrs, ManagementAddresses: v.management, Message: v.message}
	if v.code != 0 {
		out.Code = codes.Symbol(v.code)
	}
	return connect.NewResponse(out), nil
}

func (h *setup) SetHostname(ctx context.Context, r *connect.Request[osadminv1.SetHostnameRequest]) (*connect.Response[osadminv1.SetHostnameResponse], error) {
	c := callFrom(ctx)
	s := h.s
	c.note(r.Msg.GetHostname())
	if err := s.networkStepOpen(); err != nil {
		return nil, err
	}
	name, err := normalHostname(r.Msg.GetHostname())
	if err != nil {
		return nil, err
	}
	// The name is looked up again here: a record may have moved since the
	// page's check, and a name that isn't this box's would lock the page out.
	v, err := s.checkHostname(ctx, name)
	if err != nil {
		return nil, err
	}
	switch v.result {
	case osadminv1.HostnameCheck_HOSTNAME_CHECK_DNS_DOWN:
		return nil, codes.New(codes.NetDNS, "none of the box's DNS servers answered, so %s can't be checked; set it on Network later", name)
	case osadminv1.HostnameCheck_HOSTNAME_CHECK_NOT_FOUND:
		return nil, codes.New(codes.NetNameNotFound, "%s", v.message)
	case osadminv1.HostnameCheck_HOSTNAME_CHECK_ELSEWHERE:
		return nil, codes.New(codes.NetNameElsewhere, "%s", v.message)
	}
	before := s.netHostname(ctx)
	set, err := s.o.Network.SetHostname(ctx, connect.NewRequest(&netdv1.SetHostnameRequest{Hostname: name}))
	if err != nil {
		return nil, err
	}
	prev := set.Msg.GetPrevious()
	if prev == "" {
		prev = before // what DHCP named the box, say
	}
	c.note(name, "old", prev, "new", name)
	s.o.Logger.Info("osadmin: setup set the host name", log.F("hostname", name), log.F("previous", prev), log.F("by", c.session.Admin))

	fp, err := s.followCertNow(ctx)
	if err != nil {
		return nil, err
	}
	code, err := newHandoffCode()
	if err != nil {
		return nil, err
	}
	now := s.o.Clock.Now()
	exp := now.Add(HandoffTTL)
	s.handoffs.put(code, handoff{admin: c.session.Admin, session: c.session.ID, expires: exp}, now)
	return connect.NewResponse(&osadminv1.SetHostnameResponse{
		Hostname: name, Previous: prev, HandoffCode: code, HandoffExpires: timestamppb.New(exp),
		Url: "https://" + name + ":8443/setup#handoff=" + code, Fingerprint: fp,
	}), nil
}

// followCertNow makes the box's own certificate for the names it has now,
// without the settle wait the follower keeps for a name that may still move
// (the owner has just said it's right and DNS agrees), then waits until
// :8443 serves it. It returns the certificate's fingerprint, empty when the
// box has no certificate store.
func (s *Server) followCertNow(ctx context.Context) (string, error) {
	if s.o.Certs == nil {
		return "", nil
	}
	f := &s.certFollow
	f.mu.Lock()
	ch, err := s.o.Certs.FollowOwn(ctx)
	if err == nil && ch.New != "" {
		f.names = ""
		s.auditCertChange(ch)
		s.consoleChanged()
	}
	f.mu.Unlock()
	if err != nil {
		s.o.Logger.Warn("osadmin: the certificate for the new host name wasn't made; the follower will try again", log.F("error", err.Error()))
		s.lookAtCerts(certRetry)
		return "", err
	}
	fp := ch.New
	if fp != "" && s.o.CertProbe != nil {
		pctx, cancel := context.WithTimeout(ctx, certServedWait)
		defer cancel()
		if perr := s.o.CertProbe(pctx, fp); perr != nil {
			s.o.Logger.Warn("osadmin: :8443 doesn't serve the new certificate yet", log.F("error", perr.Error()))
			return "", codes.New(codes.NetInvalid, "the host name is set, but :8443 doesn't serve its certificate yet; sign in again at the new name in a minute")
		}
	}
	s.o.Logger.Info("osadmin: :8443 serves the certificate for the new host name", log.F("fingerprint", fp))
	return fp, nil
}

// newHandoffCode is 32 random bytes in URL-safe base64 (43 characters).
func newHandoffCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("handoff code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RedeemHandoff swaps a handoff code for a session at the new name.
func (h *signIn) RedeemHandoff(ctx context.Context, r *connect.Request[osadminv1.RedeemHandoffRequest]) (*connect.Response[osadminv1.RedeemHandoffResponse], error) {
	c := callFrom(ctx)
	s := h.s
	expired := func(why string) error {
		s.o.Logger.Info("osadmin: handoff code refused", log.F("why", why), log.F("source", c.source))
		return codes.New(codes.SetupHandoff, "That link has expired. Sign in to carry on.")
	}
	v, ok := s.handoffs.take(r.Msg.GetCode())
	if !ok {
		return nil, expired("unknown or used")
	}
	if !s.o.Clock.Now().Before(v.expires) {
		return nil, expired("expired")
	}
	if _, live := s.sessions.Get(v.session); !live {
		return nil, expired("its session ended")
	}
	st := s.o.Access.Read()
	a, known := st.Admin(v.admin)
	if !known || !a.HasCredentials() {
		return nil, expired("its admin can't sign in")
	}
	sess, notices := s.newSession(*a, c.source, c.userAgent)
	c.session = sess
	c.note(sess.Admin, "admin", sess.Admin)
	s.o.Logger.Info("osadmin: handoff redeemed", log.F("admin", sess.Admin), log.F("source", c.source))
	resp := connect.NewResponse(&osadminv1.RedeemHandoffResponse{Session: s.toSession(sess, a.Role, notices...)})
	resp.Header().Add("Set-Cookie", sessionCookie(sess.ID, weblogin.MaxAge))
	return resp, nil
}

// netHostname is the box's host name now, empty when it has none or netd
// doesn't say.
func (s *Server) netHostname(ctx context.Context) string {
	st, err := s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return ""
	}
	return st.Msg.GetHostname()
}
