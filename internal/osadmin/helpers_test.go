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
	"path/filepath"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
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
	// signals are the elevated sessions' pids the service was told to end.
	signals []int
	keys    map[string]sshKey
	done    bool
	// sign and enc are this test's production release and update keys.
	mirror      *httptest.Server
	mirrorFiles map[string][]byte
	sign        testpki.ECKey
	enc         *age.X25519Identity
	keyReads    int
	mirrorHit   int
}

// newBox starts osadmin with an owner alice and, when withBob, an admin
// bob.
func newBox(t *testing.T, withBob bool) *box {
	t.Helper()
	b := &box{t: t, clk: clock.NewFake(), state: t.TempDir(), keys: map[string]sshKey{}}
	var err error
	b.store, err = access.Open(filepath.Join(b.state, "access"), access.Options{Stage: func() (bool, bool) { return true, b.done }})
	if err != nil {
		t.Fatal(err)
	}
	b.addAdmin("alice", access.RoleOwner)
	if withBob {
		b.addAdmin("bob", access.RoleAdmin)
	}
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
	daemons := httptest.NewServer(mux)
	t.Cleanup(daemons.Close)
	hc := daemons.Client()
	b.sign = testpki.ECDSA(t)
	b.enc, err = age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b.elev, err = elevation.Open(elevation.Options{
		SSHDir: filepath.Join(b.state, "ssh"), StateFile: filepath.Join(b.state, "access", "elevation.json"),
		Clock:       b.clk,
		Maintenance: func() bool { return b.srv != nil && b.srv.Maintenance() },
		Signal:      func(pid int) error { b.signals = append(b.signals, pid); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	b.mirrorFiles = map[string][]byte{}
	mirrorClient := func() *http.Client { return b.mirror.Client() }
	b.srv = osadmin.New(osadmin.Options{
		Upgrade: osadmin.UpgradeOptions{
			Channel: release.ChannelProduction, ReleaseKeyPEM: b.sign.PublicPEM,
			UpdateKey:  func() (age.Identity, error) { b.keyReads++; return b.enc, nil },
			HTTPClient: &http.Client{Transport: lazyTransport{get: mirrorClient}},
		},
		Access: b.store, Audit: b.log, Clock: b.clk,
		KeyCustody: initv1connect.NewKeyCustodyServiceClient(hc, daemons.URL),
		Image:      initv1connect.NewImageServiceClient(hc, daemons.URL),
		Power:      initv1connect.NewPowerServiceClient(hc, daemons.URL),
		Network:    netdv1connect.NewNetworkServiceClient(hc, daemons.URL),
		Paths:      osadmin.Paths{State: b.state},
		Elevation:  b.elev,
		Cert:       osadmin.CertInfo{Fingerprint: "AA:BB", Expires: b.clk.Now().Add(24 * time.Hour), SelfSigned: true},
	})
	b.ts = httptest.NewTLSServer(b.srv.Handler())
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
	t.Cleanup(b.ts.Close)
	return b
}

func (b *box) addAdmin(name string, role access.Role) {
	b.t.Helper()
	k := newKey(b.t)
	pk, err := access.ParseLoginKey(k.line)
	if err != nil {
		b.t.Fatal(err)
	}
	if err := b.store.Update(func(st *access.State) error {
		a := st.AddAdmin(name, role, "console", b.clk.Now())
		a.Keys = append(a.Keys, access.AdminKey{Key: pk, Added: b.clk.Now(), AddedBy: "console", Via: access.ViaEnrol})
		return nil
	}); err != nil {
		b.t.Fatal(err)
	}
	b.keys[name] = k
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

// signIn runs the whole SSH-attested sign-in as admin and returns the
// session.
func (br *browser) signIn(admin string) *osadminv1.Session {
	br.b.t.Helper()
	si := osadminv1connect.NewSignInServiceClient(br.hc, br.b.ts.URL)
	ctx := context.Background()
	begin, err := si.BeginSignIn(ctx, connect.NewRequest(&osadminv1.BeginSignInRequest{}))
	if err != nil {
		br.b.t.Fatal(err)
	}
	if err := br.b.srv.ApproveSignIn(0, begin.Msg.GetCode(), admin, br.b.keys[admin].fp, "192.0.2.77"); err != nil {
		br.b.t.Fatal(err)
	}
	poll, err := si.PollSignIn(ctx, connect.NewRequest(&osadminv1.PollSignInRequest{PollToken: begin.Msg.GetPollToken()}))
	if err != nil || poll.Msg.GetState() != osadminv1.SignInState_SIGN_IN_STATE_APPROVED {
		br.b.t.Fatalf("poll: %v %v", poll, err)
	}
	br.csrf = poll.Msg.GetSession().GetCsrfToken()
	return poll.Msg.GetSession()
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
