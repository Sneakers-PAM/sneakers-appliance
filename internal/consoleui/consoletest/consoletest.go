// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package consoletest is a box for the console's tests: accessd's admins
// and setup state over the real access store, and fakes of init's services
// and netd.
package consoletest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// Box is the access side of a box: the store, served as accessd serves it
// to the console.
type Box struct {
	Store *access.Store
	Clock *clock.Fake

	mu       sync.Mutex
	recovery []*osadminv1.RecoveryKey
	signedIn bool
	acked    bool
	done     bool
}

// SignIn records the first :8443 sign-in.
func (b *Box) SignIn() {
	b.mu.Lock()
	b.signedIn = true
	b.mu.Unlock()
}

// IsDone reports whether setup/done was written.
func (b *Box) IsDone() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.done
}

// NewBox is a box with the named owners, none of them with a key yet.
func NewBox(t *testing.T, owners ...string) *Box {
	t.Helper()
	st, err := access.Open(filepath.Join(t.TempDir(), "access"), access.Options{Stage: func() (bool, bool) { return false, false }})
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake()
	if err := st.Update(func(s *access.State) error {
		for _, o := range owners {
			s.AddAdmin(o, access.RoleOwner, "console", clk.Now())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return &Box{Store: st, Clock: clk}
}

// AddOwner adds an owner, as the :8443 setup page makes the first admin.
func (b *Box) AddOwner(name string) {
	if err := b.Store.Update(func(s *access.State) error {
		s.AddAdmin(name, access.RoleOwner, "setup", b.Clock.Now())
		return nil
	}); err != nil {
		panic(err)
	}
}

// SetRecovery sets the recovery keys GetSetup reports.
func (b *Box) SetRecovery(keys ...*osadminv1.RecoveryKey) {
	b.mu.Lock()
	b.recovery = keys
	b.mu.Unlock()
}

// Finish marks setup done, as :8443 does after the first sign-in.
func (b *Box) Finish() {
	b.mu.Lock()
	b.done = true
	b.mu.Unlock()
}

// Key makes an ed25519 key line and its fingerprint.
func Key(t *testing.T, comment string) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comment, ssh.FingerprintSHA256(pk)
}

func coded(err error) error {
	if err == nil {
		return nil
	}
	return connect.NewError(connect.CodeFailedPrecondition, errors.New(codes.Describe(err)))
}

// Access is accessd's AccessService: the admins.
func (b *Box) Access() accessv1connect.AccessServiceClient { return accessSvc{b: b} }

type accessSvc struct {
	accessv1connect.UnimplementedAccessServiceHandler
	b *Box
}

var roles = map[access.Role]osadminv1.Role{access.RoleOwner: osadminv1.Role_ROLE_OWNER, access.RoleAdmin: osadminv1.Role_ROLE_ADMIN}

func (a accessSvc) ListAdmins(context.Context, *connect.Request[accessv1.ListAdminsRequest]) (*connect.Response[accessv1.ListAdminsResponse], error) {
	var out []*osadminv1.Admin
	for _, ad := range a.b.Store.Read().Admins {
		w := &osadminv1.Admin{Name: ad.Name, Role: roles[ad.Role]}
		for _, k := range ad.Keys {
			w.Keys = append(w.Keys, &osadminv1.Key{Fingerprint: k.Fingerprint, Type: k.Type, Comment: k.Comment})
		}
		out = append(out, w)
	}
	return connect.NewResponse(&accessv1.ListAdminsResponse{Admins: out}), nil
}

func (a accessSvc) AddAdmin(_ context.Context, r *connect.Request[accessv1.AddAdminRequest]) (*connect.Response[accessv1.AddAdminResponse], error) {
	role := access.RoleAdmin
	if r.Msg.GetRole() == osadminv1.Role_ROLE_OWNER {
		role = access.RoleOwner
	}
	err := a.b.Store.Update(func(st *access.State) error {
		if _, taken := st.Admin(r.Msg.GetName()); taken {
			return codes.New(codes.AccessName, "there is already an admin named %q", r.Msg.GetName())
		}
		st.AddAdmin(r.Msg.GetName(), role, "console", a.b.Clock.Now())
		return nil
	})
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.AddAdminResponse{Admin: &osadminv1.Admin{Name: r.Msg.GetName(), Role: r.Msg.GetRole()}}), nil
}

// Setup is accessd's SetupService.
func (b *Box) Setup() accessv1connect.SetupServiceClient { return setupSvc{b: b} }

type setupSvc struct {
	accessv1connect.UnimplementedSetupServiceHandler
	b *Box
}

// BeginRecoverAccess issues a Recover access code, as accessd does.
func (s setupSvc) BeginRecoverAccess(context.Context, *connect.Request[accessv1.BeginRecoverAccessRequest]) (*connect.Response[accessv1.BeginRecoverAccessResponse], error) {
	return connect.NewResponse(&accessv1.BeginRecoverAccessResponse{Recover: &accessv1.RecoverAccess{
		Code: RecoverCode, Url: "https://192.0.2.10:8443/recover", Expires: timestamppb.New(s.b.Clock.Now().Add(30 * time.Minute)), AttemptsLeft: 5,
	}}), nil
}

// RecoverCode is the fake's Recover access code.
const RecoverCode = "7PQK-NMS9"

// WatchConsoleInfo is the client side of the stream, which the fake
// doesn't serve.
func (s setupSvc) WatchConsoleInfo(context.Context, *connect.Request[accessv1.WatchConsoleInfoRequest]) (*connect.ServerStreamForClient[accessv1.WatchConsoleInfoResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (s setupSvc) GetSetup(context.Context, *connect.Request[accessv1.GetSetupRequest]) (*connect.Response[accessv1.GetSetupResponse], error) {
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	admins := len(s.b.Store.Read().Admins)
	return connect.NewResponse(&accessv1.GetSetupResponse{Setup: &osadminv1.GetSetupResponse{
		Done: s.b.done, RecoveryKeys: s.b.recovery, MaxRecoveryKeys: int32(access.MaxRecoveryKeys), ProductSetupUrl: "https://sneakers.example.org/setup",
		SignedIn: s.b.signedIn, SingleAdminWarning: admins == 1, SingleAdminAcknowledged: s.b.acked, AdminCount: int32(admins), // #nosec G115 -- a few admins
	}}), nil
}

func (s setupSvc) AcknowledgeSingleAdmin(context.Context, *connect.Request[accessv1.AcknowledgeSingleAdminRequest]) (*connect.Response[accessv1.AcknowledgeSingleAdminResponse], error) {
	s.b.mu.Lock()
	s.b.acked = true
	s.b.mu.Unlock()
	return connect.NewResponse(&accessv1.AcknowledgeSingleAdminResponse{}), nil
}

// Complete checks the steps as accessd does: a recovery key, the first
// sign-in, and the single-admin warning confirmed when it applies.
func (s setupSvc) Complete(context.Context, *connect.Request[accessv1.CompleteRequest]) (*connect.Response[accessv1.CompleteResponse], error) {
	admins := len(s.b.Store.Read().Admins)
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	switch {
	case len(s.b.recovery) == 0:
		return nil, coded(codes.New(codes.SetupIncomplete, "a step is still open: a recovery key"))
	case !s.b.signedIn:
		return nil, coded(codes.New(codes.SetupIncomplete, "a step is still open: the first sign-in on :8443"))
	case admins == 1 && !s.b.acked:
		return nil, coded(codes.New(codes.SetupIncomplete, "a step is still open: confirm the single-admin warning, or add a second admin"))
	}
	s.b.done = true
	return connect.NewResponse(&accessv1.CompleteResponse{ProductSetupUrl: "https://sneakers.example.org/setup"}), nil
}

// Services is init's on-demand services: it records each start.
type Services struct {
	mu      sync.Mutex
	Started []string
	// Missing are services the table doesn't have.
	Missing map[string]bool
}

// Start starts name; like init, starting a running service does nothing.
func (s *Services) Start(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Missing[name] {
		return sources.NotInstalled{What: "The " + map[string]string{"sshd": "SSH service", "netd": "network service"}[name]}
	}
	if !slices.Contains(s.Started, name) {
		s.Started = append(s.Started, name)
	}
	return nil
}

// Running reports whether name was started.
func (s *Services) Running(_ context.Context, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Missing[name] {
		return false, sources.NotInstalled{What: "The service"}
	}
	for _, n := range s.Started {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

// Starts is what was started so far.
func (s *Services) Starts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Started...)
}

// Network is netd for the wizard: two NICs, and checks that report what
// Results says.
type Network struct {
	mu       sync.Mutex
	Applied  []network.Settings
	Kept     []string
	Results  []sources.Check
	Addrs    []string
	NoNetd   bool
	NICs     []sources.NIC
	Ports    []string
	checkRun int
}

// Installed reports whether this netd is installed.
func (n *Network) Installed() bool { return !n.NoNetd }

var errNoNetd = sources.NotInstalled{What: "The network service"}

// Interfaces lists the NICs.
func (n *Network) Interfaces(context.Context) ([]sources.NIC, error) {
	if n.NICs != nil {
		return n.NICs, nil
	}
	return []sources.NIC{{Name: "ens192", MAC: "00:50:56:00:00:01", Driver: "vmxnet3", Up: true, Link: true}, {Name: "ens224", MAC: "00:50:56:00:00:02", Driver: "vmxnet3", Up: true}}, nil
}

// Get has no settings yet.
func (n *Network) Get(context.Context) (network.Settings, error) {
	if n.NoNetd {
		return network.Settings{}, errNoNetd
	}
	return network.Settings{}, nil
}

// Set records s.
func (n *Network) Set(_ context.Context, s network.Settings) (string, int, error) {
	if n.NoNetd {
		return "", 0, errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Applied = append(n.Applied, s)
	n.checkRun = 0
	return "T1", 120, nil
}

// Confirm records the kept token.
func (n *Network) Confirm(_ context.Context, token string) error {
	if n.NoNetd {
		return errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Kept = append(n.Kept, token)
	return nil
}

// Checks reports running once, then Results.
func (n *Network) Checks(context.Context) ([]sources.Check, error) {
	if n.NoNetd {
		return nil, errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.checkRun++
	if n.checkRun == 1 {
		return []sources.Check{{Name: "link", State: sources.CheckRunning}}, nil
	}
	return n.Results, nil
}

// Status has the addresses.
func (n *Network) Status(context.Context) (sources.Addresses, error) {
	if n.NoNetd {
		return sources.Addresses{}, errNoNetd
	}
	return sources.Addresses{Management: n.Addrs, Hostname: "sneakers.example.org", NTPSynced: true}, nil
}

// Settle is a short wait for a background change to land.
func Settle() { time.Sleep(20 * time.Millisecond) }

// SetManagementPorts records each opening, as "ssh" or "ssh+https".
func (n *Network) SetManagementPorts(_ context.Context, ssh, https bool) error {
	if n.NoNetd {
		return errNoNetd
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var p []string
	if ssh {
		p = append(p, "ssh")
	}
	if https {
		p = append(p, "https")
	}
	n.Ports = append(n.Ports, strings.Join(p, "+"))
	return nil
}

// Opened is every port opening so far.
func (n *Network) Opened() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.Ports...)
}

// Settings are the settings applied so far.
func (n *Network) Settings() []network.Settings {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]network.Settings(nil), n.Applied...)
}

// Tokens are the tokens kept so far.
func (n *Network) Tokens() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.Kept...)
}

// SetResults changes what the checks report.
func (n *Network) SetResults(cs []sources.Check) {
	n.mu.Lock()
	n.Results = cs
	n.mu.Unlock()
}
