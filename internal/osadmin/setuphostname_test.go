// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"software.sslmate.com/src/go-pkcs12"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

const setName = "appliance.example.org"

// fakeResolver is the box's DNS servers as setup's host name check sees
// them.
type fakeResolver struct {
	mu    sync.Mutex
	names map[string][]netip.Addr
	down  bool
	asked []string
}

func (f *fakeResolver) Resolve(_ context.Context, name string) (osadmin.HostLookup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, name)
	if f.down {
		return osadmin.HostLookup{}, codes.New(codes.NetDNS, "none of the box's DNS servers answered for %s", name)
	}
	a, ok := f.names[name]
	return osadmin.HostLookup{Addrs: slices.Clone(a), Found: ok && len(a) > 0}, nil
}

func (f *fakeResolver) point(name string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.names == nil {
		f.names = map[string][]netip.Addr{}
	}
	f.names[name] = nil
	for _, a := range addrs {
		f.names[name] = append(f.names[name], netip.MustParseAddr(a))
	}
}

func withResolver(r *fakeResolver) func(*box, *osadmin.Options) {
	return func(_ *box, o *osadmin.Options) { o.Resolver = r }
}

// logBuffer is everything osadmin logs, at trace.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func withLog(l *logBuffer) func(*box, *osadmin.Options) {
	return func(_ *box, o *osadmin.Options) {
		o.Logger = log.NewLoggerWithOptions("osadmin", log.WithOutput(l), log.WithDefaultLevel(log.LevelTrace))
	}
}

// atNetworkStep signs alice in and sets a recovery key, so setup stands at
// step 4, the network.
func atNetworkStep(t *testing.T, b *box) *browser {
	t.Helper()
	br := b.browser()
	br.signIn("alice")
	if _, err := setupClient(br).AddRecoveryKey(context.Background(), connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line, Label: "safe"})); err != nil {
		t.Fatal(err)
	}
	if cur := currentSetupStep(t, br); cur != 4 {
		t.Fatalf("setup stands at step %d, want 4", cur)
	}
	return br
}

func currentSetupStep(t *testing.T, br *browser) int32 {
	t.Helper()
	g, err := setupClient(br).GetSetup(context.Background(), connect.NewRequest(&osadminv1.GetSetupRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg.GetCurrent()
}

func check(t *testing.T, br *browser, name string) *osadminv1.CheckHostnameResponse {
	t.Helper()
	res, err := setupClient(br).CheckHostname(context.Background(), connect.NewRequest(&osadminv1.CheckHostnameRequest{Hostname: name}))
	if err != nil {
		t.Fatalf("check %s: %v", name, err)
	}
	return res.Msg
}

func setHostname(br *browser, name, code string) (*connect.Response[osadminv1.SetHostnameResponse], error) {
	return setupClient(br).SetHostname(context.Background(), connect.NewRequest(&osadminv1.SetHostnameRequest{Hostname: name, TotpCode: code}))
}

// The check lists every address the name resolves to, marked this box or
// not, and says why when it isn't a match.
func TestCheckHostnameSaysWhereTheNamePoints(t *testing.T) {
	dns := &fakeResolver{}
	b := newBox(t, false, withResolver(dns))
	br := atNetworkStep(t, b)

	dns.point(setName, "192.0.2.77", "192.0.2.10")
	got := check(t, br, "Appliance.Example.org.")
	if got.GetHostname() != setName || got.GetResult() != osadminv1.HostnameCheck_HOSTNAME_CHECK_MATCH || got.GetCode() != "" {
		t.Fatalf("%+v", got)
	}
	if a := got.GetAddresses(); len(a) != 2 || a[0].GetAddress() != "192.0.2.77" || a[0].GetThisBox() || a[1].GetAddress() != "192.0.2.10" || !a[1].GetThisBox() {
		t.Fatalf("addresses %+v", a)
	}
	if !slices.Equal(got.GetManagementAddresses(), []string{"192.0.2.10"}) {
		t.Fatalf("management %v", got.GetManagementAddresses())
	}
	e := lastEntry(t, b.log, "setup.hostname.check")
	if e.Outcome != "ok" || e.Actor != "alice" || e.Target != setName || e.Detail["match"] != "true" {
		t.Fatalf("%+v", e)
	}

	dns.point(setName, "192.0.2.77")
	got = check(t, br, setName)
	if got.GetResult() != osadminv1.HostnameCheck_HOSTNAME_CHECK_ELSEWHERE || got.GetCode() != "NET_NAME_ELSEWHERE" ||
		got.GetMessage() != "appliance.example.org points at 192.0.2.77, not this box (192.0.2.10)." {
		t.Fatalf("%+v", got)
	}
	if e := lastEntry(t, b.log, "setup.hostname.check"); e.Detail["match"] != "false" || e.Detail["result"] != "elsewhere" {
		t.Fatalf("%+v", e)
	}

	got = check(t, br, "nothere.example.org")
	if got.GetResult() != osadminv1.HostnameCheck_HOSTNAME_CHECK_NOT_FOUND || got.GetCode() != "NET_NAME_NOT_FOUND" ||
		!strings.Contains(got.GetMessage(), "isn't in DNS yet") || !strings.Contains(got.GetMessage(), "pointing at 192.0.2.10") || len(got.GetAddresses()) != 0 {
		t.Fatalf("%+v", got)
	}

	dns.down = true
	got = check(t, br, setName)
	if got.GetResult() != osadminv1.HostnameCheck_HOSTNAME_CHECK_DNS_DOWN || got.GetCode() != "NET_DNS" || !strings.Contains(got.GetMessage(), "set it on Network later") {
		t.Fatalf("%+v", got)
	}

	_, err := setupClient(br).CheckHostname(context.Background(), connect.NewRequest(&osadminv1.CheckHostnameRequest{Hostname: "appliance"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "NET_INVALID")
	if e := lastEntry(t, b.log, "setup.hostname.check"); e.Outcome != "refused" || e.Code != "NET_INVALID" {
		t.Fatalf("%+v", e)
	}
	if len(b.netd.hostnameSets) != 0 {
		t.Fatalf("a check set a name: %v", b.netd.hostnameSets)
	}
}

// Without a resolver of its own, osadmin asks netd's.
func TestCheckHostnameAsksNetdByDefault(t *testing.T) {
	b := newBox(t, false)
	br := atNetworkStep(t, b)
	b.netd.mu.Lock()
	b.netd.names = map[string][]string{setName: {"192.0.2.10"}}
	b.netd.mu.Unlock()
	if got := check(t, br, setName); got.GetResult() != osadminv1.HostnameCheck_HOSTNAME_CHECK_MATCH {
		t.Fatalf("%+v", got)
	}
	b.netd.mu.Lock()
	b.netd.dnsDown = true
	b.netd.mu.Unlock()
	if got := check(t, br, setName); got.GetResult() != osadminv1.HostnameCheck_HOSTNAME_CHECK_DNS_DOWN {
		t.Fatalf("%+v", got)
	}
}

// The host name is the network step's alone: before the recovery keys it's
// too early, and once the step is done (or setup is) it's Network's.
func TestTheHostNameIsTheNetworkStepsOnly(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	b := newBox(t, false, withResolver(dns))
	br := b.browser()
	br.signIn("alice")
	ctx := context.Background()
	su := setupClient(br)
	_, err := su.CheckHostname(ctx, connect.NewRequest(&osadminv1.CheckHostnameRequest{Hostname: setName}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_INCOMPLETE")

	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	if _, err := su.AcknowledgeStep(ctx, connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK})); err != nil {
		t.Fatal(err)
	}
	_, err = su.CheckHostname(ctx, connect.NewRequest(&osadminv1.CheckHostnameRequest{Hostname: setName}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_STEP_DONE")
	_, err = setHostname(br, setName, b.code("alice"))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_STEP_DONE")
	if e := lastEntry(t, b.log, "setup.hostname.set"); e.Outcome != "refused" || e.Code != "SETUP_STEP_DONE" {
		t.Fatalf("%+v", e)
	}

	b.finishSetup()
	_, err = su.CheckHostname(ctx, connect.NewRequest(&osadminv1.CheckHostnameRequest{Hostname: setName}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	if len(b.netd.hostnameSets) != 0 {
		t.Fatalf("set %v", b.netd.hostnameSets)
	}
}

func TestSetHostnameTakesAFreshAuthenticatorCode(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	b := newBox(t, false, withResolver(dns))
	br := atNetworkStep(t, b)

	_, err := setHostname(br, setName, "")
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	_, err = setHostname(br, setName, "000000")
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	if e := lastEntry(t, b.log, "setup.hostname.set"); e.Outcome != "refused" || e.Code != "ACCESS_CREDENTIALS" {
		t.Fatalf("%+v", e)
	}
	if len(b.netd.hostnameSets) != 0 {
		t.Fatalf("a wrong code set %v", b.netd.hostnameSets)
	}
}

// The name is checked again on the box when it's set: a record that moved
// since the page's check stops it.
func TestSetHostnameChecksTheNameAgain(t *testing.T) {
	dns := &fakeResolver{}
	b := newBox(t, false, withResolver(dns))
	br := atNetworkStep(t, b)

	dns.point(setName, "192.0.2.77")
	_, err := setHostname(br, setName, b.code("alice"))
	symbolIn(t, err, connect.CodeFailedPrecondition, "NET_NAME_ELSEWHERE")
	if !strings.Contains(err.Error(), "points at 192.0.2.77, not this box (192.0.2.10)") {
		t.Fatalf("%v", err)
	}
	_, err = setHostname(br, "nothere.example.org", b.code("alice"))
	symbolIn(t, err, connect.CodeFailedPrecondition, "NET_NAME_NOT_FOUND")
	dns.down = true
	_, err = setHostname(br, setName, b.code("alice"))
	symbolIn(t, err, connect.CodeFailedPrecondition, "NET_DNS")
	if len(b.netd.hostnameSets) != 0 {
		t.Fatalf("set %v", b.netd.hostnameSets)
	}
	if cur := currentSetupStep(t, br); cur != 4 {
		t.Fatalf("setup moved on to step %d", cur)
	}
}

// The name is set at once (no confirm window to roll it back), the box's
// own certificate is made for it and served before the answer comes, and
// the answer carries the handoff to the new name. The step stays open.
func TestSetHostnameSetsTheNameAndTheCertificateFollowsAtOnce(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	logs := &logBuffer{}
	cb := newCertBox(t, false, false, withResolver(dns), withLog(logs))
	br := atNetworkStep(t, cb.box)
	old := cb.fingerprint(t)

	res, err := setHostname(br, "Appliance.Example.org", cb.code("alice"))
	if err != nil {
		t.Fatal(err)
	}
	out := res.Msg
	if !slices.Equal(cb.netd.hostnameSets, []string{setName}) {
		t.Fatalf("netd was asked to set %v", cb.netd.hostnameSets)
	}
	now := cb.fingerprint(t)
	if now == old || out.GetFingerprint() != now || served(t, cb.addr) != now {
		t.Fatalf("old %s, now %s, answered %s, served %s", old, now, out.GetFingerprint(), served(t, cb.addr))
	}
	if names := certNames(t, cb.adminDir); len(names) == 0 || names[0] != setName {
		t.Fatalf("the certificate names %v", names)
	}
	if out.GetHostname() != setName || out.GetPrevious() != boxHost {
		t.Fatalf("%+v", out)
	}
	code := out.GetHandoffCode()
	if len(code) < 43 || out.GetUrl() != "https://"+setName+":8443/setup#handoff="+code {
		t.Fatalf("url %q, code %q", out.GetUrl(), code)
	}
	if !out.GetHandoffExpires().AsTime().Equal(cb.clk.Now().Add(osadmin.HandoffTTL)) {
		t.Fatalf("expires %v", out.GetHandoffExpires().AsTime())
	}

	e := lastEntry(t, cb.log, "setup.hostname.set")
	if e.Outcome != "ok" || e.Actor != "alice" || e.Target != setName || e.Detail["old"] != boxHost || e.Detail["new"] != setName {
		t.Fatalf("%+v", e)
	}
	if r := lastEntry(t, cb.log, replaced); r.Detail["reason"] != "hostname" || r.Detail["new"] != now {
		t.Fatalf("%+v", r)
	}

	// No window: nothing waits for a confirm, and nothing undoes it.
	cb.clk.Advance(3 * time.Minute)
	cb.netd.mu.Lock()
	pending, confirmed, host := cb.netd.pending, cb.netd.confirmed, cb.netd.hostname
	cb.netd.mu.Unlock()
	if pending != "" || confirmed != 0 || host != setName {
		t.Fatalf("pending %q, confirmed %d, host %q", pending, confirmed, host)
	}
	if cur := currentSetupStep(t, br); cur != 4 {
		t.Fatalf("setup moved on to step %d; the step is the page's to finish", cur)
	}
	// The code is never written down.
	if strings.Contains(logs.String(), code) {
		t.Fatal("the handoff code is in a log line")
	}
	audit, err := os.ReadFile(filepath.Join(cb.state, "os-audit", "current.jsonl"))
	if err == nil && strings.Contains(string(audit), code) {
		t.Fatal("the handoff code is in the audit log")
	}
	es, _ := cb.log.Entries()
	for _, e := range es {
		for _, v := range e.Detail {
			if strings.Contains(v, code) {
				t.Fatalf("the handoff code is in %s", e.Action)
			}
		}
	}
}

func certNames(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "tls.crt")) // #nosec G304 -- the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.DNSNames
}

// The original #176 failure: a wildcard PFX for the domain is refused
// while the box has no name, and accepted once setup has set it.
func TestAWildcardPFXFitsOnceSetupSetTheName(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	cb := newCertBox(t, false, false, withResolver(dns), func(b *box, _ *osadmin.Options) {
		b.netd.hostname, b.netd.settings.Hostname = "", ""
	})
	br := atNetworkStep(t, cb.box)
	ctx := context.Background()
	l := cb.leaf(t, "*.example.org")
	p12, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{cb.ca.Intermediate, cb.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	imp := &osadminv1.ImportCertificateRequest{Pkcs12: p12, Pkcs12Password: "test-only-password"}
	if _, err := br.tls().ImportCertificate(ctx, connect.NewRequest(imp)); err == nil {
		t.Fatal("a wildcard was taken while the box has no name")
	}
	if _, err := setHostname(br, setName, cb.code("alice")); err != nil {
		t.Fatal(err)
	}
	if _, err := br.tls().ImportCertificate(ctx, connect.NewRequest(imp)); err != nil {
		t.Fatalf("the wildcard for the box's domain: %v", err)
	}
}

// handoff sets the name and returns the code the page carries to it.
func handoff(t *testing.T, b *box, br *browser) string {
	t.Helper()
	res, err := setHostname(br, setName, b.code("alice"))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.GetHandoffCode()
}

func redeem(br *browser, code string) (*connect.Response[osadminv1.RedeemHandoffResponse], error) {
	return signInClient(br).RedeemHandoff(context.Background(), connect.NewRequest(&osadminv1.RedeemHandoffRequest{Code: code}))
}

// The browser at the new name has no cookie: the code swaps for a session
// of its own there, once. The session at the address goes on until it
// times out as usual.
func TestRedeemHandoffGivesTheNewNameASessionOnce(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	b := newBox(t, false, withResolver(dns))
	byAddress := atNetworkStep(t, b)
	code := handoff(t, b, byAddress)

	byName := b.browser()
	res, err := redeem(byName, code)
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Msg.GetSession(); s.GetAdmin() != "alice" || s.GetRole() != osadminv1.Role_ROLE_OWNER || s.GetCsrfToken() == "" {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(res.Header().Get("Set-Cookie"), osadmin.CookieName+"=") {
		t.Fatalf("no session cookie: %q", res.Header().Get("Set-Cookie"))
	}
	byName.csrf = res.Msg.GetSession().GetCsrfToken()
	if cur := currentSetupStep(t, byName); cur != 4 {
		t.Fatalf("the new name's session lands on step %d, want 4", cur)
	}
	if _, err := signInClient(byAddress).GetSession(context.Background(), connect.NewRequest(&osadminv1.GetSessionRequest{})); err != nil {
		t.Fatalf("the session at the address ended: %v", err)
	}
	e := lastEntry(t, b.log, "signin.handoff.redeem")
	if e.Outcome != "ok" || e.Actor != "alice" || e.Source == "" || e.Detail["admin"] != "alice" {
		t.Fatalf("%+v", e)
	}

	_, err = redeem(b.browser(), code)
	symbolIn(t, err, connect.CodeUnauthenticated, "SETUP_HANDOFF")
	if !strings.Contains(err.Error(), "That link has expired. Sign in to carry on.") {
		t.Fatalf("%v", err)
	}
	if e := lastEntry(t, b.log, "signin.handoff.redeem"); e.Outcome != "refused" || e.Code != "SETUP_HANDOFF" {
		t.Fatalf("%+v", e)
	}
}

func TestAHandoffCodeLastsTwoMinutes(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	b := newBox(t, false, withResolver(dns))
	br := atNetworkStep(t, b)
	code := handoff(t, b, br)
	b.clk.Advance(osadmin.HandoffTTL + time.Second)
	_, err := redeem(b.browser(), code)
	symbolIn(t, err, connect.CodeUnauthenticated, "SETUP_HANDOFF")
}

func TestAnUnknownHandoffCodeIsRefused(t *testing.T) {
	b := newBox(t, false)
	for _, code := range []string{"", "not-a-code", strings.Repeat("A", 43)} {
		_, err := redeem(b.browser(), code)
		symbolIn(t, err, connect.CodeUnauthenticated, "SETUP_HANDOFF")
	}
}

// The code belongs to the session that set the name: once that one has
// ended (signed out, say), the code is no one's.
func TestAHandoffCodeEndsWithItsSession(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	b := newBox(t, false, withResolver(dns))
	br := atNetworkStep(t, b)
	code := handoff(t, b, br)
	if _, err := signInClient(br).SignOut(context.Background(), connect.NewRequest(&osadminv1.SignOutRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err := redeem(b.browser(), code)
	symbolIn(t, err, connect.CodeUnauthenticated, "SETUP_HANDOFF")
}

// The codes live in osadmin's memory only: a restart drops them, and the
// owner signs in again at the new name.
func TestARestartDropsTheHandoffCodes(t *testing.T) {
	dns := &fakeResolver{}
	dns.point(setName, "192.0.2.10")
	var opts osadmin.Options
	b := newBox(t, false, withResolver(dns), func(_ *box, o *osadmin.Options) { opts = *o })
	br := atNetworkStep(t, b)
	code := handoff(t, b, br)

	restarted := osadmin.New(opts)
	t.Cleanup(restarted.Close)
	ts := newTLSServer(t, restarted.Handler())
	si := osadminv1connect.NewSignInServiceClient(ts.Client(), ts.URL)
	_, err := si.RedeemHandoff(context.Background(), connect.NewRequest(&osadminv1.RedeemHandoffRequest{Code: code}))
	symbolIn(t, err, connect.CodeUnauthenticated, "SETUP_HANDOFF")
}

func newTLSServer(t *testing.T, h http.Handler) *tlsServer {
	t.Helper()
	ts := startTLS(h)
	t.Cleanup(ts.Close)
	return ts
}
