// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

type sshKey struct{ line, fp string }

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
}

func newBox(t *testing.T) *box {
	t.Helper()
	b := &box{t: t, state: t.TempDir(), run: t.TempDir(), keys: map[string]sshKey{}, uids: map[string]uint32{}}
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
	b.d = accessd.New(accessd.Options{
		Network:    netd,
		Paths:      accessd.Paths{Run: b.run},
		StatusFile: filepath.Join(b.run, "access", "status.json"),
	})
	b.store, err = access.Open(filepath.Join(b.state, "access"), access.Options{Stage: func() (bool, bool) { return true, false }, OnChange: b.d.Changed})
	if err != nil {
		t.Fatal(err)
	}
	b.log, err = osaudit.Open(filepath.Join(b.state, "os-audit"), osaudit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b.api = osadmin.New(osadmin.Options{
		Access: b.store, Audit: b.log, Clock: clock.Real{},
		KeyCustody: initv1connect.NewKeyCustodyServiceClient(hc, daemons.URL),
		Image:      initv1connect.NewImageServiceClient(hc, daemons.URL),
		Power:      initv1connect.NewPowerServiceClient(hc, daemons.URL),
		Network:    netd,
		Paths:      osadmin.Paths{State: b.state},
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
	if err := b.store.Update(func(st *access.State) error {
		a := st.AddAdmin(name, role, "console", time.Now())
		a.Keys = append(a.Keys, access.AdminKey{Key: pk, Added: time.Now(), AddedBy: "console", Via: access.ViaEnrol})
		b.uids[name] = uint32(a.UID) // #nosec G115 -- admin uids start at 20000
		return nil
	}); err != nil {
		b.t.Fatal(err)
	}
	b.keys[name] = k
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
