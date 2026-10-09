// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit/audittest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
)

type sshKey struct{ line, fp string }

// testPassword is every test admin's password.
const testPassword = "correct horse battery staple"

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

type fakeNetd struct {
	netdv1connect.UnimplementedNetworkServiceHandler
	mu       sync.Mutex
	settings *netdv1.Settings
	mgmt     []string
	// down makes Status fail, so sshd's files can't be rendered.
	down bool
}

func (n *fakeNetd) Get(context.Context, *connect.Request[netdv1.GetRequest]) (*connect.Response[netdv1.GetResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return connect.NewResponse(&netdv1.GetResponse{Settings: n.settings}), nil
}

func (n *fakeNetd) Set(_ context.Context, r *connect.Request[netdv1.SetRequest]) (*connect.Response[netdv1.SetResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.settings = r.Msg.GetSettings()
	return connect.NewResponse(&netdv1.SetResponse{Token: "tok-1", RevertAfterSeconds: 120}), nil
}

func (n *fakeNetd) Status(context.Context, *connect.Request[netdv1.StatusRequest]) (*connect.Response[netdv1.StatusResponse], error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("netd is down"))
	}
	return connect.NewResponse(&netdv1.StatusResponse{ManagementAddresses: n.mgmt, Hostname: "box1.sneakers.example.org", NtpSynced: true}), nil
}

func (n *fakeNetd) allowList() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.settings.GetAllowList()
}

// box is accessd with its store, log and fakes, and one HTTP server per
// peer class. Each server sets the peer accessd would read with
// SO_PEERCRED.
type box struct {
	t     *testing.T
	state string
	run   string
	store *access.Store
	log   *osaudit.Log
	netd  *fakeNetd
	api   *osadmin.Server
	d     *accessd.Server
	keys  map[string]sshKey
	uids  map[string]uint32
	totp  map[string][]byte
	elev  *elevation.Service
	root  *rootkey.Key
	book  *lockout.Book
	clk   *clock.Fake
	// pwHash is every admin's password, testPassword.
	pwHash string

	sigMu   sync.Mutex
	signals []int
}

func (b *box) signalled() []int {
	b.sigMu.Lock()
	defer b.sigMu.Unlock()
	return slices.Clone(b.signals)
}

func newBox(t *testing.T) *box {
	t.Helper()
	b := &box{t: t, state: t.TempDir(), run: t.TempDir(), keys: map[string]sshKey{}, uids: map[string]uint32{}, totp: map[string][]byte{}, clk: clock.NewFake()}
	b.netd = &fakeNetd{
		settings: &netdv1.Settings{AllowList: []string{"198.51.100.0/24"}},
		mgmt:     []string{"192.0.2.10/24", "fe80::1/64", "2001:db8::10/64"},
	}
	mux := http.NewServeMux()
	mux.Handle(netdv1connect.NewNetworkServiceHandler(b.netd))
	mux.Handle(initv1connect.NewKeyCustodyServiceHandler(initv1connect.UnimplementedKeyCustodyServiceHandler{}))
	mux.Handle(initv1connect.NewImageServiceHandler(initv1connect.UnimplementedImageServiceHandler{}))
	mux.Handle(initv1connect.NewPowerServiceHandler(initv1connect.UnimplementedPowerServiceHandler{}))
	daemons := httptest.NewServer(mux)
	t.Cleanup(daemons.Close)
	hc := daemons.Client()
	netd := netdv1connect.NewNetworkServiceClient(hc, daemons.URL)
	var err error
	b.log, err = osaudit.Open(filepath.Join(b.state, "os-audit"), osaudit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audittest.CheckTargets(t, b.log) })
	var d *accessd.Server
	rerender := func() {
		if d != nil {
			d.Rerender()
		}
	}
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
	b.elev, err = elevation.Open(elevation.Options{
		SSHDir: filepath.Join(b.state, "ssh"), StateFile: filepath.Join(b.state, "access", "elevation.json"), RootKey: b.root,
		Audit: b.log, OnChange: rerender,
		Signal: func(pid int) error {
			b.sigMu.Lock()
			defer b.sigMu.Unlock()
			b.signals = append(b.signals, pid)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	d = accessd.New(accessd.Options{
		Network:    netd,
		Paths:      accessd.Paths{Run: b.run},
		StatusFile: filepath.Join(b.run, "access", "status.json"),
		Elevation:  b.elev,
		HostKeyDir: filepath.Join(b.state, "ssh"),
		HostCA:     b.root,
		AuditDir:   b.log.Dir(),
	})
	b.d = d
	b.store, err = access.Open(filepath.Join(b.state, "access"), access.Options{Stage: func() (bool, bool) { return true, false }, OnChange: b.d.Changed, Revoke: b.elev.RevokeLoginKeys})
	if err != nil {
		t.Fatal(err)
	}
	b.api = osadmin.New(osadmin.Options{
		Access: b.store, Audit: b.log, Clock: b.clk,
		KeyCustody: initv1connect.NewKeyCustodyServiceClient(hc, daemons.URL),
		Image:      initv1connect.NewImageServiceClient(hc, daemons.URL),
		Power:      initv1connect.NewPowerServiceClient(hc, daemons.URL),
		Network:    netd,
		Paths:      osadmin.Paths{State: b.state},
		Elevation:  b.elev,
		RootKey:    b.root, Lockout: b.book,
		OnConsoleChange: b.d.ConsoleChanged,
	})
	b.d.Attach(b.store, b.api)
	b.addAdmin("alice", access.RoleOwner)
	b.addAdmin("bob", access.RoleAdmin)
	return b
}

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
		a := st.AddAdmin(name, role, "setup", time.Now())
		a.Keys = append(a.Keys, access.AdminKey{Key: pk, Added: time.Now(), AddedBy: name, Via: access.ViaIssued, Serial: st.NextSerial})
		st.NextSerial++
		a.Password = &access.Password{Hash: b.pwHash, Changed: time.Now()}
		a.TOTP = &access.TOTP{Sealed: sealed, Added: time.Now()}
		b.uids[name] = uint32(a.UID) // #nosec G115 -- admin uids start at 20000
		return nil
	}); err != nil {
		b.t.Fatal(err)
	}
	b.keys[name], b.totp[name] = k, secret
}

// code is name's TOTP code for a step not used yet: the clock moves on a
// step when this one's code was taken.
func (b *box) code(name string) string {
	for b.book.LastStep(name) >= credentials.Step(b.clk.Now()) {
		b.clk.Advance(credentials.Period)
	}
	return credentials.TOTP(b.totp[name], b.clk.Now())
}

// as is an HTTP client whose requests reach accessd from uid.
func (b *box) as(uid uint32) (*http.Client, string) {
	h := b.d.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(initapi.WithPeer(r.Context(), initapi.Peer{UID: uid, GID: uid, PID: 1})))
	}))
	b.t.Cleanup(ts.Close)
	return ts.Client(), ts.URL
}

// shell is the closed shell of name's login: its uid and the key sshd
// says signed it in.
func (b *box) shell(name string) accessv1connect.AccessServiceClient {
	hc, url := b.as(b.uids[name])
	return accessv1connect.NewAccessServiceClient(hc, url, connect.WithInterceptors(keyHeader(b.keys[name].fp)))
}

func (b *box) console() (*http.Client, string) { return b.as(0) }

func (b *box) osadmin() (*http.Client, string) { return b.as(accounts.OsadminUID) }

func (b *box) osadminAccess() osadminv1connect.AccessServiceClient {
	hc, url := b.osadmin()
	return osadminv1connect.NewAccessServiceClient(hc, url)
}

func keyHeader(fp string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, r connect.AnyRequest) (connect.AnyResponse, error) {
			r.Header().Set(accessapi.KeyHeader, fp)
			r.Header().Set(accessapi.SourceHeader, "192.0.2.50")
			return next(ctx, r)
		}
	}
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
