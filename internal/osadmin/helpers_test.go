// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

// sshKey is a generated login key: its authorized_keys line and
// fingerprint.
type sshKey struct {
	line, fp string
}

func newKey(t *testing.T) sshKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshKey{line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), fp: ssh.FingerprintSHA256(pk)}
}

// fakeInit is init's API as osadmin sees it.
type fakeInit struct {
	initv1connect.UnimplementedKeyCustodyServiceHandler
	mu         sync.Mutex
	level      initv1.ProtectionLevel
	escrowFor  []string
	escrowErr  error
	secureBoot *bool
	reboots    int
	poweroffs  int
	forced     bool
	resets     []*initv1.FactoryResetRequest
	arms       []*initv1.ArmFactoryResetRequest
	armErr     error
	cancels    []string
	staged     []string
	stagedVer  string
	activated  int
	rollbacks  int
	// activateErr fails Activate; duringActivate runs inside it, as the
	// box is mid-apply.
	activateErr    error
	duringActivate func()
}

func (f *fakeInit) Protection(context.Context, *connect.Request[initv1.ProtectionRequest]) (*connect.Response[initv1.ProtectionResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &initv1.ProtectionResponse{Level: f.level}
	if f.level == initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED {
		r.Reason = "no-tpm"
	}
	return connect.NewResponse(r), nil
}

func (f *fakeInit) Mode(context.Context, *connect.Request[initv1.ModeRequest]) (*connect.Response[initv1.ModeResponse], error) {
	return connect.NewResponse(&initv1.ModeResponse{Mode: initv1.CustodyMode_CUSTODY_MODE_TPM}), nil
}

func (f *fakeInit) Escrow(_ context.Context, r *connect.Request[initv1.EscrowRequest]) (*connect.Response[initv1.EscrowResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.escrowErr != nil {
		return nil, f.escrowErr
	}
	f.escrowFor = r.Msg.GetRecipients()
	return connect.NewResponse(&initv1.EscrowResponse{Bundle: []byte("fake escrow bundle")}), nil
}

func (f *fakeInit) SetSecureBoot(_ context.Context, r *connect.Request[initv1.SetSecureBootRequest]) (*connect.Response[initv1.SetSecureBootResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	on := r.Msg.GetOn()
	f.secureBoot = &on
	return connect.NewResponse(&initv1.SetSecureBootResponse{}), nil
}

type fakePower struct {
	initv1connect.UnimplementedPowerServiceHandler
	f *fakeInit
}

func (p fakePower) Reboot(_ context.Context, r *connect.Request[initv1.RebootRequest]) (*connect.Response[initv1.RebootResponse], error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.reboots++
	p.f.forced = r.Msg.GetForced()
	return connect.NewResponse(&initv1.RebootResponse{}), nil
}

func (p fakePower) PowerOff(_ context.Context, r *connect.Request[initv1.PowerOffRequest]) (*connect.Response[initv1.PowerOffResponse], error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.poweroffs++
	p.f.forced = r.Msg.GetForced()
	return connect.NewResponse(&initv1.PowerOffResponse{}), nil
}

func (p fakePower) FactoryReset(_ context.Context, r *connect.Request[initv1.FactoryResetRequest]) (*connect.Response[initv1.FactoryResetResponse], error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.resets = append(p.f.resets, r.Msg)
	return connect.NewResponse(&initv1.FactoryResetResponse{}), nil
}

func (p fakePower) ArmFactoryReset(_ context.Context, r *connect.Request[initv1.ArmFactoryResetRequest]) (*connect.Response[initv1.ArmFactoryResetResponse], error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	if p.f.armErr != nil {
		return nil, p.f.armErr
	}
	p.f.arms = append(p.f.arms, r.Msg)
	return connect.NewResponse(&initv1.ArmFactoryResetResponse{}), nil
}

func (p fakePower) CancelFactoryReset(_ context.Context, r *connect.Request[initv1.CancelFactoryResetRequest]) (*connect.Response[initv1.CancelFactoryResetResponse], error) {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.cancels = append(p.f.cancels, r.Msg.GetId())
	return connect.NewResponse(&initv1.CancelFactoryResetResponse{}), nil
}

type fakeImage struct {
	initv1connect.UnimplementedImageServiceHandler
	f *fakeInit
}

func (i fakeImage) Status(context.Context, *connect.Request[initv1.ImageServiceStatusRequest]) (*connect.Response[initv1.ImageServiceStatusResponse], error) {
	i.f.mu.Lock()
	defer i.f.mu.Unlock()
	return connect.NewResponse(&initv1.ImageServiceStatusResponse{RunningVersion: "0.1.0", StagedVersion: i.f.stagedVer}), nil
}

func (i fakeImage) Stage(_ context.Context, r *connect.Request[initv1.StageRequest]) (*connect.Response[initv1.StageResponse], error) {
	i.f.mu.Lock()
	defer i.f.mu.Unlock()
	i.f.staged = append(i.f.staged, r.Msg.GetReference())
	i.f.stagedVer = "0.2.0"
	return connect.NewResponse(&initv1.StageResponse{Version: "0.2.0"}), nil
}

func (i fakeImage) Activate(context.Context, *connect.Request[initv1.ActivateRequest]) (*connect.Response[initv1.ActivateResponse], error) {
	i.f.mu.Lock()
	during, err := i.f.duringActivate, i.f.activateErr
	i.f.mu.Unlock()
	if during != nil {
		during()
	}
	if err != nil {
		return nil, err
	}
	i.f.mu.Lock()
	defer i.f.mu.Unlock()
	i.f.activated++
	return connect.NewResponse(&initv1.ActivateResponse{}), nil
}

func (i fakeImage) Rollback(context.Context, *connect.Request[initv1.RollbackRequest]) (*connect.Response[initv1.RollbackResponse], error) {
	i.f.mu.Lock()
	during := i.f.duringActivate
	i.f.mu.Unlock()
	if during != nil {
		during()
	}
	i.f.mu.Lock()
	defer i.f.mu.Unlock()
	i.f.rollbacks++
	return connect.NewResponse(&initv1.RollbackResponse{}), nil
}

// fakeNetd is netd as osadmin sees it.
type fakeNetd struct {
	netdv1connect.UnimplementedNetworkServiceHandler
	mu        sync.Mutex
	settings  *netdv1.Settings
	pending   string
	confirmed int
	mgmt      []string
	ntp       bool
	// servicePorts are the ports SetServicePorts last opened.
	servicePorts []uint32
}

func (n *fakeNetd) Get(context.Context, *connect.Request[netdv1.GetRequest]) (*connect.Response[netdv1.GetResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return connect.NewResponse(&netdv1.GetResponse{Settings: n.settings, Pending: n.pending != ""}), nil
}

func (n *fakeNetd) Set(_ context.Context, r *connect.Request[netdv1.SetRequest]) (*connect.Response[netdv1.SetResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.settings = r.Msg.GetSettings()
	n.pending = "tok-1"
	return connect.NewResponse(&netdv1.SetResponse{Token: n.pending, RevertAfterSeconds: 120}), nil
}

func (n *fakeNetd) Confirm(_ context.Context, r *connect.Request[netdv1.ConfirmRequest]) (*connect.Response[netdv1.ConfirmResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if r.Msg.GetToken() != n.pending {
		return nil, connect.NewError(connect.CodeInvalidArgument, codes.New(codes.NetInvalid, "token: that isn't the pending change"))
	}
	n.pending = ""
	n.confirmed++
	return connect.NewResponse(&netdv1.ConfirmResponse{}), nil
}

func (n *fakeNetd) Status(context.Context, *connect.Request[netdv1.StatusRequest]) (*connect.Response[netdv1.StatusResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return connect.NewResponse(&netdv1.StatusResponse{ManagementAddresses: n.mgmt, Hostname: "box1.sneakers.example.org", NtpSynced: n.ntp}), nil
}

func (n *fakeNetd) SetServicePorts(_ context.Context, r *connect.Request[netdv1.SetServicePortsRequest]) (*connect.Response[netdv1.SetServicePortsResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.servicePorts = nil
	for _, rule := range r.Msg.GetRules() {
		n.servicePorts = append(n.servicePorts, rule.GetPort())
	}
	return connect.NewResponse(&netdv1.SetServicePortsResponse{}), nil
}

func (n *fakeNetd) Checks(context.Context, *connect.Request[netdv1.ChecksRequest]) (*connect.Response[netdv1.ChecksResponse], error) {
	return connect.NewResponse(&netdv1.ChecksResponse{Checks: []*netdv1.Check{{Name: "link", State: netdv1.CheckState_CHECK_STATE_OK}}}), nil
}

func defaultSettings() *netdv1.Settings {
	return &netdv1.Settings{
		Management: &netdv1.Interface{Name: "eth0", Ipv4: &netdv1.Ipv4{Mode: netdv1.Ipv4Mode_IPV4_MODE_DHCP}, Ipv6: &netdv1.Ipv6{Mode: netdv1.Ipv6Mode_IPV6_MODE_SLAAC}},
		Cluster:    &netdv1.ClusterRanges{Pods: "10.244.0.0/16", Services: "10.96.0.0/12"}, // scrub:allow=private-ip -- the k0s defaults
	}
}

// box is a running osadmin with its fakes.
type box struct {
	t     *testing.T
	clk   *clock.Fake
	state string
	store *access.Store
	log   *osaudit.Log
	init  *fakeInit
	netd  *fakeNetd
	srv   *osadmin.Server
	ts    *httptest.Server
	elev  *elevation.Service
	// shells are the SSH closed-shell sessions.
	shells *fakeShells
	// signals are the elevated sessions' pids the service was told to end.
	signals []int
	// onSignal, when set, runs (outside the elevation service's lock) for
	// each signal, as a session's sneakers-elevated would on SIGTERM.
	onSignal func(pid int)
	keys     map[string]sshKey
	// totp are the admins' TOTP secrets; password is every admin's.
	totp       map[string][]byte
	pwHash     string
	root       *rootkey.Key
	codeSealer *memSealer
	book       *lockout.Book
	sshdUp     int
	done       bool
	// sign and enc are this test's production release and update keys.
	mirror      *httptest.Server
	mirrorFiles map[string][]byte
	sign        testpki.ECKey
	enc         *age.X25519Identity
	keyReads    int
	mirrorHit   int
	services    *fakeServices
}

// fakeServices is init's ServicesService: it records the calls.
type fakeServices struct {
	initv1connect.UnimplementedServicesServiceHandler
	mu      sync.Mutex
	calls   []string
	running bool
}

func (f *fakeServices) Start(_ context.Context, r *connect.Request[initv1.StartRequest]) (*connect.Response[initv1.StartResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "start "+r.Msg.GetName())
	f.running = true
	return connect.NewResponse(&initv1.StartResponse{}), nil
}

func (f *fakeServices) Stop(_ context.Context, r *connect.Request[initv1.StopRequest]) (*connect.Response[initv1.StopResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "stop "+r.Msg.GetName())
	f.running = false
	return connect.NewResponse(&initv1.StopResponse{}), nil
}

func (f *fakeServices) Status(context.Context, *connect.Request[initv1.StatusRequest]) (*connect.Response[initv1.StatusResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return connect.NewResponse(&initv1.StatusResponse{Running: f.running}), nil
}

func (f *fakeServices) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// newBox starts osadmin with an owner alice and, when withBob, an admin
// bob, as a box whose first admin was made already; mods change the options first.
func newBox(t *testing.T, withBob bool, mods ...func(*box, *osadmin.Options)) *box {
	t.Helper()
	return startBox(t, mods, func(b *box) {
		b.addAdmin("alice", access.RoleOwner)
		if withBob {
			b.addAdmin("bob", access.RoleAdmin)
		}
		if err := os.MkdirAll(filepath.Join(b.state, "setup"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(b.state, "setup", osadmin.FirstAdminMarker), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})
}

// newFreshBox starts osadmin on a box with no admin yet: first boot.
func newFreshBox(t *testing.T) *box {
	t.Helper()
	return startBox(t, nil, func(*box) {})
}

func startBox(t *testing.T, mods []func(*box, *osadmin.Options), seed func(*box)) *box {
	t.Helper()
	b := &box{t: t, clk: clock.NewFake(), state: t.TempDir(), keys: map[string]sshKey{}, totp: map[string][]byte{}, shells: &fakeShells{}}
	var err error
	b.root, err = rootkey.Load(newMemSealer(), filepath.Join(b.state, "ssh"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b.pwHash, err = credentials.HashPassword(b.root.Pepper(), testPassword)
	if err != nil {
		t.Fatal(err)
	}
	b.book, err = lockout.Open(filepath.Join(b.state, "access", "lockout.json"))
	if err != nil {
		t.Fatal(err)
	}
	b.store, err = access.Open(filepath.Join(b.state, "access"), access.Options{Stage: func() (bool, bool) { return b.srv != nil && b.srv.FirstAdminDone(), b.done }})
	if err != nil {
		t.Fatal(err)
	}
	seed(b)
	b.log, err = osaudit.Open(filepath.Join(b.state, "os-audit"), osaudit.Options{Now: b.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	b.init = &fakeInit{level: initv1.ProtectionLevel_PROTECTION_LEVEL_FULL}
	b.netd = &fakeNetd{settings: defaultSettings(), mgmt: []string{"192.0.2.10"}, ntp: true}
	mux := http.NewServeMux()
	mux.Handle(initv1connect.NewKeyCustodyServiceHandler(b.init))
	mux.Handle(initv1connect.NewPowerServiceHandler(fakePower{f: b.init}))
	mux.Handle(initv1connect.NewImageServiceHandler(fakeImage{f: b.init}))
	mux.Handle(netdv1connect.NewNetworkServiceHandler(b.netd))
	b.services = &fakeServices{}
	mux.Handle(initv1connect.NewServicesServiceHandler(b.services))
	daemons := httptest.NewServer(mux)
	t.Cleanup(daemons.Close)
	hc := daemons.Client()
	// The fixture product bundles' images are signed with the fixtures'
	// release key, so the box pins that one.
	b.sign = fixtures.LabKeys(t).Cosign
	b.enc, err = age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b.elev, err = elevation.Open(elevation.Options{
		SSHDir: filepath.Join(b.state, "ssh"), StateFile: filepath.Join(b.state, "access", "elevation.json"), RootKey: b.root,
		Clock:       b.clk,
		Maintenance: func() bool { return b.srv != nil && b.srv.Maintenance() },
		Signal: func(pid int) error {
			b.signals = append(b.signals, pid)
			if b.onSignal != nil {
				go b.onSignal(pid)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.mirrorFiles = map[string][]byte{}
	b.mirror = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mirrorHit++
		body, ok := b.mirrorFiles[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(b.mirror.Close)
	mirrorClient := func() *http.Client { return b.mirror.Client() }
	if b.codeSealer == nil {
		b.codeSealer = newMemSealer()
	}
	opts := osadmin.Options{
		Upgrade: osadmin.UpgradeOptions{
			Channel: release.ChannelProduction, ReleaseKeyPEM: b.sign.PublicPEM,
			UpdateKey:        func() (age.Identity, error) { b.keyReads++; return b.enc, nil },
			HTTPClient:       &http.Client{Transport: lazyTransport{get: mirrorClient}},
			ElevationEndWait: 500 * time.Millisecond,
			ProductDir:       filepath.Join(b.state, "product"),
			DirectURL:        b.mirror.URL + "/direct",
		},
		Access: b.store, Audit: b.log, Clock: b.clk,
		KeyCustody: initv1connect.NewKeyCustodyServiceClient(hc, daemons.URL),
		Image:      initv1connect.NewImageServiceClient(hc, daemons.URL),
		Power:      initv1connect.NewPowerServiceClient(hc, daemons.URL),
		Services:   initv1connect.NewServicesServiceClient(hc, daemons.URL),
		Network:    netdv1connect.NewNetworkServiceClient(hc, daemons.URL),
		Paths:      osadmin.Paths{State: b.state},
		Elevation:  b.elev,
		RootKey:    b.root, Lockout: b.book,
		CodeSealer:   b.codeSealer,
		OnFirstAdmin: func() { b.sshdUp++ },
		Shells:       b.shells,
		Cert:         osadmin.CertInfo{Fingerprint: "AA:BB", Expires: b.clk.Now().Add(24 * time.Hour), SelfSigned: true},
	}
	for _, m := range mods {
		m(b, &opts)
	}
	b.srv = osadmin.New(opts)
	b.ts = httptest.NewTLSServer(b.srv.Handler())
	t.Cleanup(b.ts.Close)
	return b
}

// testPassword is every test admin's password.
const testPassword = "correct horse battery staple"

// addAdmin adds an admin who can sign in: the test password, a TOTP
// secret of their own, and an issued key.
func (b *box) addAdmin(name string, role access.Role) {
	b.t.Helper()
	k := newKey(b.t)
	pk, err := access.ParseLoginKey(k.line)
	if err != nil {
		b.t.Fatal(err)
	}
	secret, err := credentials.NewTOTPSecret()
	if err != nil {
		b.t.Fatal(err)
	}
	sealed, err := credentials.SealTOTP(b.root.Pepper(), name, secret)
	if err != nil {
		b.t.Fatal(err)
	}
	if err := b.store.Update(func(st *access.State) error {
		a := st.AddAdmin(name, role, "setup", b.clk.Now())
		a.Keys = append(a.Keys, access.AdminKey{Key: pk, Added: b.clk.Now(), AddedBy: name, Via: access.ViaIssued, Serial: st.NextSerial})
		st.NextSerial++
		a.Password = &access.Password{Hash: b.pwHash, Changed: b.clk.Now()}
		a.TOTP = &access.TOTP{Sealed: sealed, Added: b.clk.Now()}
		return nil
	}); err != nil {
		b.t.Fatal(err)
	}
	b.keys[name], b.totp[name] = k, secret
}

// code is admin's TOTP code for a step not used yet: when this step's code
// was taken already, the clock moves on to the next step first.
func (b *box) code(admin string) string {
	for b.book.LastStep(admin) >= credentials.Step(b.clk.Now()) {
		b.clk.Advance(credentials.Period)
	}
	return credentials.TOTP(b.totp[admin], b.clk.Now())
}

// browser is one browser: its cookie jar and the CSRF token it was given.
type browser struct {
	b    *box
	hc   *http.Client
	csrf string
}

type csrfTransport struct {
	br   *browser
	next http.RoundTripper
}

func (c csrfTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", "TestBrowser/1.0")
	if c.br.csrf != "" {
		r.Header.Set(osadmin.CSRFHeader, c.br.csrf)
	}
	return c.next.RoundTrip(r)
}

func (b *box) browser() *browser {
	jar, _ := cookiejar.New(nil)
	br := &browser{b: b}
	base := b.ts.Client()
	br.hc = &http.Client{Jar: jar, Transport: csrfTransport{br: br, next: base.Transport}}
	return br
}

// signIn signs in as admin with the password and a TOTP code and returns
// the session.
func (br *browser) signIn(admin string) *osadminv1.Session {
	br.b.t.Helper()
	si := osadminv1connect.NewSignInServiceClient(br.hc, br.b.ts.URL)
	out, err := si.SignIn(context.Background(), connect.NewRequest(&osadminv1.SignInRequest{Admin: admin, Password: testPassword, TotpCode: br.b.code(admin)}))
	if err != nil {
		br.b.t.Fatalf("sign in as %s: %v", admin, err)
	}
	br.csrf = out.Msg.GetSession().GetCsrfToken()
	return out.Msg.GetSession()
}

// stepUp gives the session a fresh TOTP code.
func (br *browser) stepUp(admin string) {
	br.b.t.Helper()
	si := osadminv1connect.NewSignInServiceClient(br.hc, br.b.ts.URL)
	if _, err := si.StepUp(context.Background(), connect.NewRequest(&osadminv1.StepUpRequest{TotpCode: br.b.code(admin)})); err != nil {
		br.b.t.Fatalf("step up as %s: %v", admin, err)
	}
}

func (br *browser) access() osadminv1connect.AccessServiceClient {
	return osadminv1connect.NewAccessServiceClient(br.hc, br.b.ts.URL)
}

func symbolIn(t *testing.T, err error, code connect.Code, symbol string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %s, got no error", symbol)
	}
	if connect.CodeOf(err) != code || !strings.Contains(err.Error(), symbol) {
		t.Fatalf("want %v %s, got %v", code, symbol, err)
	}
}

func lastEntry(t *testing.T, l *osaudit.Log, action string) osaudit.Entry {
	t.Helper()
	es, err := l.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Action == action {
			return es[i]
		}
	}
	t.Fatalf("no %s entry", action)
	return osaudit.Entry{}
}

// lazyTransport uses the mirror's client, which exists only after the
// server it trusts starts.
type lazyTransport struct{ get func() *http.Client }

func (l lazyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return l.get().Transport.RoundTrip(r)
}

// memSealer stands in for init's KeyCustody.
type memSealer struct {
	mu    sync.Mutex
	items map[string][]byte
}

func newMemSealer() *memSealer { return &memSealer{items: map[string][]byte{}} }

func (m *memSealer) Seal(name string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[name] = slices.Clone(secret)
	return nil
}

func (m *memSealer) Unseal(name string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.items[name]
	return slices.Clone(b), ok, nil
}
