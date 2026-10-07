// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// fakeAccessd is accessd's local API as the shell sees it.
type fakeAccessd struct {
	accessv1connect.UnimplementedAccessServiceHandler
	accessv1connect.UnimplementedNetworkServiceHandler
	mu       sync.Mutex
	headers  []http.Header
	added    []*accessv1.AddAdminRequest
	settings *netdv1.Settings
	set      []*netdv1.Settings
}

func (f *fakeAccessd) saw(h http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headers = append(f.headers, h.Clone())
}

func (f *fakeAccessd) GetStatus(_ context.Context, r *connect.Request[accessv1.GetStatusRequest]) (*connect.Response[accessv1.GetStatusResponse], error) {
	f.saw(r.Header())
	return connect.NewResponse(&accessv1.GetStatusResponse{Status: &osadminv1.GetStatusResponse{
		Hostname: "box1.sneakers.example.org", Version: "0.1.0", Phase: "normal", ManagementAddresses: []string{"192.0.2.10"},
		Warnings: []*osadminv1.Warning{{Detail: "The clock isn't synchronised with an NTP server."}},
	}}), nil
}

func (f *fakeAccessd) ListKeys(_ context.Context, r *connect.Request[accessv1.ListKeysRequest]) (*connect.Response[accessv1.ListKeysResponse], error) {
	f.saw(r.Header())
	if r.Msg.GetAdmin() == "bob" {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("ACCESS_FORBIDDEN (3009): an admin sees only their own keys"))
	}
	return connect.NewResponse(&accessv1.ListKeysResponse{Admin: "alice", Keys: []*osadminv1.Key{{Fingerprint: "SHA256:abc", Type: "ssh-ed25519", Comment: "laptop"}}}), nil
}

func (f *fakeAccessd) AddAdmin(_ context.Context, r *connect.Request[accessv1.AddAdminRequest]) (*connect.Response[accessv1.AddAdminResponse], error) {
	f.mu.Lock()
	f.added = append(f.added, r.Msg)
	f.mu.Unlock()
	return connect.NewResponse(&accessv1.AddAdminResponse{Admin: &osadminv1.Admin{Name: r.Msg.GetName(), Role: r.Msg.GetRole(), Uid: 20002}}), nil
}

func (f *fakeAccessd) GetNetwork(context.Context, *connect.Request[accessv1.GetNetworkRequest]) (*connect.Response[accessv1.GetNetworkResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return connect.NewResponse(&accessv1.GetNetworkResponse{Settings: f.settings, ManagementAddresses: []string{"192.0.2.10/24"}, NtpSynced: true}), nil
}

func (f *fakeAccessd) SetNetwork(_ context.Context, r *connect.Request[accessv1.SetNetworkRequest]) (*connect.Response[accessv1.SetNetworkResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set = append(f.set, r.Msg.GetSettings())
	return connect.NewResponse(&accessv1.SetNetworkResponse{Token: "tok-1", RevertAfterSeconds: 120}), nil
}

func withAccessd(t *testing.T, f *fakeAccessd) (*shell.Services, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	mux.Handle(accessv1connect.NewNetworkServiceHandler(f))
	mux.Handle(accessv1connect.NewElevationServiceHandler(accessv1connect.UnimplementedElevationServiceHandler{}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{
		Session:    shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"},
		StatusFile: filepath.Join(t.TempDir(), "status.json"),
	}
	s.UseAccessd(http.DefaultClient, srv.URL)
	return s, srv
}

// The shell's accessd commands reach accessd, each with the key that
// signed the login in and the SSH client's address.
func TestAccessdCommandsReachAccessd(t *testing.T) {
	f := &fakeAccessd{}
	s, _ := withAccessd(t, f)
	out, _, err := runWith(t, s, "keys list", "")
	if err != nil || !strings.Contains(out, "SHA256:abc") || !strings.Contains(out, "laptop") {
		t.Fatalf("%v %q", err, out)
	}
	if h := f.headers[0]; h.Get(accessapi.KeyHeader) != "SHA256:abc" || h.Get(accessapi.SourceHeader) != "192.0.2.60" {
		t.Fatalf("%v", h)
	}
	_, stderr, err := runWith(t, s, "keys list --admin bob", "")
	if !codes.Is(err, codes.AccessForbidden) || !strings.Contains(stderr, "only their own keys") {
		t.Fatalf("%v %q", err, stderr)
	}
	if _, _, err := runWith(t, s, "admins add carol --role owner", ""); err != nil {
		t.Fatal(err)
	}
	if len(f.added) != 1 || f.added[0].GetName() != "carol" || f.added[0].GetRole() != osadminv1.Role_ROLE_OWNER {
		t.Fatalf("%v", f.added)
	}
	_, _, err = runWith(t, s, "admins add dave --role boss", "")
	if !codes.Is(err, codes.ShellParse) {
		t.Fatalf("%v", err)
	}
}

func TestStatusFromAccessd(t *testing.T) {
	s, _ := withAccessd(t, &fakeAccessd{})
	out, _, err := runWith(t, s, "status", "")
	if err != nil || !strings.Contains(out, "box1.sneakers.example.org") || !strings.Contains(out, "0.1.0") || !strings.Contains(out, "NTP server") {
		t.Fatalf("%v %q", err, out)
	}
}

// With accessd down, status shows the last one accessd kept, saying so,
// and every other accessd command says the services are unavailable.
func TestAccessdDownLeavesCachedStatus(t *testing.T) {
	s, srv := withAccessd(t, &fakeAccessd{})
	srv.Close()
	_, stderr, err := runWith(t, s, "status", "")
	if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, accessapi.Unavailable) {
		t.Fatalf("no cache yet: %v %q", err, stderr)
	}
	saved := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	if err := accessapi.WriteStatusCache(s.StatusFile, &osadminv1.GetStatusResponse{Hostname: "box1.sneakers.example.org", Version: "0.1.0"}, saved); err != nil {
		t.Fatal(err)
	}
	out, _, err := runWith(t, s, "status", "")
	if err != nil || !strings.Contains(out, "appliance services are unavailable") || !strings.Contains(out, "2026-10-07T14:00:00Z") || !strings.Contains(out, "box1.sneakers.example.org") {
		t.Fatalf("%v %q", err, out)
	}
	for _, line := range []string{"keys list", "admins list", "network show", "login ABCD-EFGH"} {
		_, stderr, err := runWith(t, s, line, "y\n")
		if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "appliance services are unavailable") {
			t.Errorf("%q: %v %q", line, err, stderr)
		}
	}
}

// network set changes only the keys given, on top of the current settings.
func TestNetworkSet(t *testing.T) {
	f := &fakeAccessd{settings: &netdv1.Settings{Hostname: "old.sneakers.example.org", Ntp: []string{"192.0.2.1"}}}
	s, _ := withAccessd(t, f)
	out, _, err := runWith(t, s, "network set hostname=box2.sneakers.example.org dns=192.0.2.53,192.0.2.54", "n\n")
	if err != nil || !strings.Contains(out, "network confirm tok-1") {
		t.Fatalf("%v %q", err, out)
	}
	got := f.set[0]
	if got.GetHostname() != "box2.sneakers.example.org" || strings.Join(got.GetDns(), ",") != "192.0.2.53,192.0.2.54" || strings.Join(got.GetNtp(), ",") != "192.0.2.1" {
		t.Fatalf("%v", got)
	}
	_, _, err = runWith(t, s, "network set mtu=9000", "")
	if !codes.Is(err, codes.ShellParse) {
		t.Fatalf("%v", err)
	}
}

func TestElevationIsNotInThisRelease(t *testing.T) {
	s, _ := withAccessd(t, &fakeAccessd{})
	_, stderr, err := runWith(t, s, "elevation status", "")
	if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "Not available in this release") {
		t.Fatalf("%v %q", err, stderr)
	}
}

// LocalService is on access.sock too; its client comes with UseAccessd.
func TestUseAccessdWiresTheSignInApproval(t *testing.T) {
	f := &fakeLocal{ua: "TestBrowser/1.0"}
	mux := http.NewServeMux()
	mux.Handle(osadminv1connect.NewLocalServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	if _, _, err := runWith(t, s, "login ABCD-EFGH", "y\n"); err != nil || len(f.approved) != 1 {
		t.Fatalf("%v %d", err, len(f.approved))
	}
}
