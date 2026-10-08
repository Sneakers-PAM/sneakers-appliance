// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// table writes a service table with the named entries.
func table(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n+".yaml"), []byte("exec: /usr/bin/x\nphases: [normal]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestInstalledReadsTheServiceTable(t *testing.T) {
	dir := table(t, "accessd", "osadmin")
	if !sources.Installed(dir, "accessd") || sources.Installed(dir, "netd") || sources.Installed(dir, "../x") {
		t.Fatal("Installed")
	}
}

type fakeNetd struct {
	netdv1connect.UnimplementedNetworkServiceHandler
	calls []string
}

func (f *fakeNetd) Get(context.Context, *connect.Request[netdv1.GetRequest]) (*connect.Response[netdv1.GetResponse], error) {
	f.calls = append(f.calls, "get")
	return connect.NewResponse(&netdv1.GetResponse{Settings: network.ToWire(network.Defaults("ens192"))}), nil
}

func (f *fakeNetd) Set(_ context.Context, r *connect.Request[netdv1.SetRequest]) (*connect.Response[netdv1.SetResponse], error) {
	f.calls = append(f.calls, "set "+r.Msg.GetSettings().GetManagement().GetName())
	return connect.NewResponse(&netdv1.SetResponse{Token: "T1", RevertAfterSeconds: 120}), nil
}

func (f *fakeNetd) Checks(context.Context, *connect.Request[netdv1.ChecksRequest]) (*connect.Response[netdv1.ChecksResponse], error) {
	f.calls = append(f.calls, "checks")
	return connect.NewResponse(&netdv1.ChecksResponse{Checks: []*netdv1.Check{
		{Name: "address", State: netdv1.CheckState_CHECK_STATE_OK},
		{Name: "ntp", State: netdv1.CheckState_CHECK_STATE_FAILED, Code: "NET_NTP", Detail: "no answer", Skippable: true},
	}}), nil
}

func (f *fakeNetd) Status(context.Context, *connect.Request[netdv1.StatusRequest]) (*connect.Response[netdv1.StatusResponse], error) {
	f.calls = append(f.calls, "status")
	return connect.NewResponse(&netdv1.StatusResponse{ManagementAddresses: []string{"192.0.2.10/24"}, Hostname: "sneakers.example.org", NtpSynced: true}), nil
}

// netdClient serves a handler in-process, as a client.
type netdClient struct{ h *fakeNetd }

func (c netdClient) Get(ctx context.Context, r *connect.Request[netdv1.GetRequest]) (*connect.Response[netdv1.GetResponse], error) {
	return c.h.Get(ctx, r)
}
func (c netdClient) Set(ctx context.Context, r *connect.Request[netdv1.SetRequest]) (*connect.Response[netdv1.SetResponse], error) {
	return c.h.Set(ctx, r)
}
func (c netdClient) Confirm(ctx context.Context, r *connect.Request[netdv1.ConfirmRequest]) (*connect.Response[netdv1.ConfirmResponse], error) {
	c.h.calls = append(c.h.calls, "confirm "+r.Msg.GetToken())
	return connect.NewResponse(&netdv1.ConfirmResponse{}), nil
}
func (c netdClient) Checks(ctx context.Context, r *connect.Request[netdv1.ChecksRequest]) (*connect.Response[netdv1.ChecksResponse], error) {
	return c.h.Checks(ctx, r)
}
func (c netdClient) SetServicePorts(ctx context.Context, r *connect.Request[netdv1.SetServicePortsRequest]) (*connect.Response[netdv1.SetServicePortsResponse], error) {
	return c.h.SetServicePorts(ctx, r)
}
func (c netdClient) Status(ctx context.Context, r *connect.Request[netdv1.StatusRequest]) (*connect.Response[netdv1.StatusResponse], error) {
	return c.h.Status(ctx, r)
}
func (c netdClient) ListInterfaces(context.Context, *connect.Request[netdv1.ListInterfacesRequest]) (*connect.Response[netdv1.ListInterfacesResponse], error) {
	c.h.calls = append(c.h.calls, "interfaces")
	return connect.NewResponse(&netdv1.ListInterfacesResponse{Interfaces: []*netdv1.Nic{{Name: "eth0", Mac: "52:54:00:12:34:56", LinkUp: true, Driver: "virtio_net"}}}), nil
}
func (c netdClient) SetManagementPorts(_ context.Context, r *connect.Request[netdv1.SetManagementPortsRequest]) (*connect.Response[netdv1.SetManagementPortsResponse], error) {
	c.h.calls = append(c.h.calls, fmt.Sprintf("ports ssh=%v https=%v", r.Msg.GetSsh(), r.Msg.GetHttps()))
	return connect.NewResponse(&netdv1.SetManagementPortsResponse{}), nil
}
func (c netdClient) Watch(context.Context, *connect.Request[netdv1.WatchRequest]) (*connect.ServerStreamForClient[netdv1.WatchResponse], error) {
	return nil, errors.New("not watched here")
}

// sysfs makes /sys/class/net with two NICs and the loopback.
func sysfs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, v := range map[string][4]string{"ens192": {"00:50:56:00:00:01", "up", "vmxnet3", "0x1003"}, "ens224": {"00:50:56:00:00:02", "down", "vmxnet3", "0x1003"}, "ens256": {"00:50:56:00:00:03", "down", "vmxnet3", "0x1002"}, "lo": {"00:00:00:00:00:00", "unknown", "", "0x9"}} {
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(d, "address"), []byte(v[0]+"\n"), 0o600)
		_ = os.WriteFile(filepath.Join(d, "operstate"), []byte(v[1]+"\n"), 0o600)
		_ = os.WriteFile(filepath.Join(d, "flags"), []byte(v[3]+"\n"), 0o600)
		if v[2] != "" {
			drv := filepath.Join(t.TempDir(), v[2])
			_ = os.MkdirAll(drv, 0o755)
			_ = os.MkdirAll(filepath.Join(d, "device"), 0o755)
			_ = os.Symlink(drv, filepath.Join(d, "device", "driver"))
		}
	}
	return dir
}

// Without netd in the service table the network is the stub: the NIC list
// is read from sysfs, and everything netd does says plainly that it isn't
// installed, never that it worked. With netd installed, the same calls go
// to netd.
func TestTheNetworkSwitchesFromTheStubToNetd(t *testing.T) {
	ctx := context.Background()
	sys := sysfs(t)
	f := &fakeNetd{}
	stub := sources.NewNetwork(table(t, "accessd"), netdClient{f}, sys)
	if err := stub.SetManagementPorts(ctx, true, false); !sources.IsNotInstalled(err) {
		t.Fatalf("ports through the stub: %v", err)
	}
	nics, err := stub.Interfaces(ctx)
	// ens256 isn't brought up, so its link is unknown, not missing.
	if err != nil || len(nics) != 3 || nics[0].Name != "ens192" || !nics[0].Link || nics[0].Driver != "vmxnet3" || nics[1].Link || !nics[1].Up || nics[2].Up {
		t.Fatalf("%+v %v", nics, err)
	}
	if !stub.Installed() {
		for _, err := range []error{
			func() error { _, err := stub.Get(ctx); return err }(),
			func() error { _, _, err := stub.Set(ctx, network.Defaults("ens192")); return err }(),
			func() error { _, err := stub.Checks(ctx); return err }(),
			func() error { _, err := stub.Status(ctx); return err }(),
			stub.Confirm(ctx, "T1"),
		} {
			var ni sources.NotInstalled
			if !errors.As(err, &ni) || ni.Error() != "The network service isn't installed in this build yet" {
				t.Fatalf("stub said %v", err)
			}
		}
	} else {
		t.Fatal("the stub says netd is installed")
	}
	if len(f.calls) != 0 {
		t.Fatalf("the stub called netd: %v", f.calls)
	}

	real := sources.NewNetwork(table(t, "accessd", "netd"), netdClient{f}, sys)
	if !real.Installed() {
		t.Fatal("netd is in the table")
	}
	if _, err := real.Get(ctx); err != nil {
		t.Fatal(err)
	}
	tok, after, err := real.Set(ctx, network.Defaults("ens192"))
	if err != nil || tok != "T1" || after != 120 {
		t.Fatalf("%q %d %v", tok, after, err)
	}
	cs, err := real.Checks(ctx)
	if err != nil || len(cs) != 2 || cs[1].State != sources.CheckFailed || !cs[1].Skippable {
		t.Fatalf("%+v %v", cs, err)
	}
	st, err := real.Status(ctx)
	if err != nil || st.Hostname != "sneakers.example.org" || st.Management[0] != "192.0.2.10/24" {
		t.Fatalf("%+v %v", st, err)
	}
	if err := real.Confirm(ctx, "T1"); err != nil {
		t.Fatal(err)
	}
	ns, err := real.Interfaces(ctx)
	if err != nil || len(ns) != 1 || ns[0].Name != "eth0" || !ns[0].Up || !ns[0].Link {
		t.Fatalf("netd's interfaces: %+v %v", ns, err)
	}
	if err := real.SetManagementPorts(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	if got := f.calls; len(got) != 7 || got[1] != "set ens192" || got[6] != "ports ssh=true https=true" {
		t.Fatalf("netd calls %v", got)
	}
}

type fakeServices struct {
	initv1connect.UnimplementedServicesServiceHandler
	started []string
}

func (f *fakeServices) Start(_ context.Context, r *connect.Request[initv1.StartRequest]) (*connect.Response[initv1.StartResponse], error) {
	f.started = append(f.started, r.Msg.GetName())
	return connect.NewResponse(&initv1.StartResponse{}), nil
}

type servicesClient struct{ h *fakeServices }

func (c servicesClient) Start(ctx context.Context, r *connect.Request[initv1.StartRequest]) (*connect.Response[initv1.StartResponse], error) {
	return c.h.Start(ctx, r)
}
func (c servicesClient) Stop(ctx context.Context, r *connect.Request[initv1.StopRequest]) (*connect.Response[initv1.StopResponse], error) {
	return c.h.Stop(ctx, r)
}
func (c servicesClient) Status(context.Context, *connect.Request[initv1.StatusRequest]) (*connect.Response[initv1.StatusResponse], error) {
	return connect.NewResponse(&initv1.StatusResponse{Running: true}), nil
}

// A service the table doesn't have (sshd before its runner is in the
// build) isn't asked for; the console says it isn't installed.
func TestServicesSayWhatIsntInstalled(t *testing.T) {
	ctx := context.Background()
	f := &fakeServices{}
	s := sources.NewServices(table(t, "osadmin"), servicesClient{f})
	err := s.Start(ctx, "sshd")
	var ni sources.NotInstalled
	if !errors.As(err, &ni) || ni.Error() != "The SSH service isn't installed in this build yet" {
		t.Fatalf("sshd: %v", err)
	}
	if err := s.Start(ctx, "osadmin"); err != nil {
		t.Fatal(err)
	}
	if len(f.started) != 1 || f.started[0] != "osadmin" {
		t.Fatalf("started %v", f.started)
	}
	if up, err := s.Running(ctx, "osadmin"); err != nil || !up {
		t.Fatalf("%v %v", up, err)
	}
	if _, err := s.Running(ctx, "sshd"); !errors.As(err, &ni) {
		t.Fatalf("sshd status: %v", err)
	}
}

func TestTheStubsForLaterServices(t *testing.T) {
	_, err := sources.NoPlatform{}.State(context.Background())
	var ni sources.NotInstalled
	if !errors.As(err, &ni) || ni.Error() != "The platform isn't installed in this build yet" {
		t.Fatalf("platform: %v", err)
	}
}

func TestHostKeys(t *testing.T) {
	dir := t.TempDir()
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl host"
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ks := sources.HostKeys(dir)
	if len(ks) != 1 || ks[0].Type != "ssh-ed25519" || len(ks[0].Fingerprint) != len("SHA256:")+43 {
		t.Fatalf("%+v", ks)
	}
	if ks := sources.HostKeys(filepath.Join(dir, "none")); len(ks) != 0 {
		t.Fatalf("%+v", ks)
	}
}

type fakeAccess struct {
	accessv1connect.UnimplementedAccessServiceHandler
	err error
}

func (f fakeAccess) GetStatus(context.Context, *connect.Request[accessv1.GetStatusRequest]) (*connect.Response[accessv1.GetStatusResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&accessv1.GetStatusResponse{Status: &osadminv1.GetStatusResponse{Version: "0.1.0"}}), nil
}

// The status comes live from accessd, or, while accessd is down, from the
// cache it keeps, marked with when it was saved.
func TestStatusFallsBackToTheCache(t *testing.T) {
	ctx := context.Background()
	cache := filepath.Join(t.TempDir(), "status.json")
	saved := time.Date(2026, 10, 7, 18, 0, 0, 0, time.UTC)
	if err := accessapi.WriteStatusCache(cache, &osadminv1.GetStatusResponse{Version: "0.0.9"}, saved); err != nil {
		t.Fatal(err)
	}
	live := sources.Status{Access: fakeAccess{}, CacheFile: cache}
	v := live.Read(ctx)
	if v.Err != nil || v.Status.GetVersion() != "0.1.0" || !v.Saved.IsZero() {
		t.Fatalf("%+v", v)
	}
	down := sources.Status{Access: fakeAccess{err: errors.New("connection refused")}, CacheFile: cache}
	v = down.Read(ctx)
	if v.Err == nil || v.Status.GetVersion() != "0.0.9" || !v.Saved.Equal(saved) {
		t.Fatalf("%+v", v)
	}
	none := sources.Status{Access: fakeAccess{err: errors.New("connection refused")}, CacheFile: filepath.Join(t.TempDir(), "x")}
	if v := none.Read(ctx); v.Err == nil || v.Status != nil {
		t.Fatalf("%+v", v)
	}
}

type fakeCustody struct {
	initv1connect.UnimplementedKeyCustodyServiceHandler
}

func (fakeCustody) Protection(context.Context, *connect.Request[initv1.ProtectionRequest]) (*connect.Response[initv1.ProtectionResponse], error) {
	return connect.NewResponse(&initv1.ProtectionResponse{Level: initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED, Reason: "secure-boot-off"}), nil
}

func (fakeCustody) Mode(context.Context, *connect.Request[initv1.ModeRequest]) (*connect.Response[initv1.ModeResponse], error) {
	return connect.NewResponse(&initv1.ModeResponse{Mode: initv1.CustodyMode_CUSTODY_MODE_KEYFILE}), nil
}

func TestCustodyReadsInit(t *testing.T) {
	p, m, err := sources.Custody{C: fakeCustody{}}.Read(context.Background())
	if err != nil || p != keycustody.Reduced(keycustody.ReasonSecureBootOff) || m != keycustody.ModeKeyfile {
		t.Fatalf("%v %v %v", p, m, err)
	}
}

func TestURLHosts(t *testing.T) {
	got := sources.URLHosts([]string{"192.0.2.10/24", "fe80::1", "2001:db8::10/64", "junk"})
	if strings.Join(got, " ") != "192.0.2.10 [2001:db8::10]" {
		t.Fatalf("%q", got)
	}
	if h := sources.Hosts([]string{"2001:db8::10/64"}); len(h) != 1 || h[0] != "2001:db8::10" {
		t.Fatalf("%q", h)
	}
}
