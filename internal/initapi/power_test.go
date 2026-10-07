// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
)

type machine struct {
	mu    sync.Mutex
	steps []string
	audit []osaudit.Entry
}

func (m *machine) add(s string) { m.mu.Lock(); m.steps = append(m.steps, s); m.mu.Unlock() }

func (m *machine) Drain(context.Context, ...string) error                   { m.add("drain"); return nil }
func (m *machine) Sync()                                                    { m.add("sync") }
func (m *machine) CloseVolumes(context.Context) error                       { m.add("close"); return nil }
func (m *machine) UnmountESP() error                                        { return nil }
func (m *machine) Reboot() error                                            { m.add("reboot"); return nil }
func (m *machine) PowerOff() error                                          { m.add("poweroff"); return nil }
func (m *machine) Begin(r factoryreset.Record) (factoryreset.Record, error) { return r, nil }
func (m *machine) Run(context.Context, func(context.Context) error) (factoryreset.Record, error) {
	return factoryreset.Record{}, nil
}
func (m *machine) Append(e osaudit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = append(m.audit, e)
	return nil
}

func (m *machine) did(s string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.steps, s)
}

func (m *machine) last() osaudit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.audit[len(m.audit)-1]
}

func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func controller(m *machine) *power.Controller {
	return power.New(power.Options{
		Machine: m, Drainer: m, Audit: func() (power.Auditor, error) { return m, nil },
		Roster: func() (access.State, error) { return access.State{}, nil },
		Reset:  m, Clock: clock.NewFake(), Go: func(f func()) { f() },
	})
}

// servePower serves init.sock with the test binary taken for kind.
func servePower(t *testing.T, kind power.Kind) (*machine, initv1connect.PowerServiceClient) {
	t.Helper()
	m := &machine{}
	callers := map[string]power.Kind{}
	if kind != "" {
		callers[testExe(t)] = kind
	}
	sock := filepath.Join(t.TempDir(), "init.sock")
	srv, err := initapi.Listen(sock, initapi.Options{
		Allow: func(uid uint32) bool { return uid == me() }, Power: controller(m), Callers: callers,
		AdminName: func(uid uint32) (string, bool) { return "alice", uid == me() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return m, initv1connect.NewPowerServiceClient(client(sock), "http://init.sock")
}

func TestAForgedPowerRequestIsRefusedAndAudited(t *testing.T) {
	m, c := servePower(t, "")
	_, err := c.Reboot(context.Background(), connect.NewRequest(&initv1.RebootRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "POWER_CALLER") {
		t.Fatalf("got %v", err)
	}
	if m.did("reboot") {
		t.Fatal("a program that isn't osadmin or the shell rebooted the box")
	}
	if e := m.last(); e.Outcome != "refused" || e.Code != "POWER_CALLER" || e.Actor != testExe(t) {
		t.Fatalf("%+v", e)
	}
	_, err = c.FactoryReset(context.Background(), connect.NewRequest(&initv1.FactoryResetRequest{Id: "R-ABC123", StartedBy: "alice", Approvals: []string{"alice", "bob"}}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a forged factory reset: %v", err)
	}
}

func TestOsadminReboots(t *testing.T) {
	m, c := servePower(t, power.KindOsadmin)
	if _, err := c.Reboot(context.Background(), connect.NewRequest(&initv1.RebootRequest{Forced: true})); err != nil {
		t.Fatal(err)
	}
	if !m.did("reboot") || m.did("drain") {
		t.Fatalf("%v", m.steps)
	}
	if e := m.last(); e.Actor != "osadmin" || e.Detail["mode"] != "forced" || e.Outcome != "ok" {
		t.Fatalf("%+v", e)
	}
}

func TestTheShellPowersOffButCantReset(t *testing.T) {
	m, c := servePower(t, power.KindShell)
	_, err := c.ArmFactoryReset(context.Background(), connect.NewRequest(&initv1.ArmFactoryResetRequest{Id: "R-ABC123", StartedBy: "alice", Approvals: []string{"alice", "bob"}}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("the shell armed a reset: %v", err)
	}
	if _, err := c.PowerOff(context.Background(), connect.NewRequest(&initv1.PowerOffRequest{})); err != nil {
		t.Fatal(err)
	}
	if !m.did("drain") || !m.did("poweroff") {
		t.Fatalf("%v", m.steps)
	}
	if e := m.last(); e.Actor != "alice" || e.Detail["caller"] != "shell" {
		t.Fatalf("%+v", e)
	}
}

func TestThePowerSocketServesOnlyPower(t *testing.T) {
	m := &machine{}
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "power.sock")
	srv, err := initapi.ListenPower(sock, initapi.Options{
		Allow: func(uid uint32) bool { return uid == me() }, Power: controller(m),
		Callers:   map[string]power.Kind{testExe(t): power.KindShell},
		AdminName: func(uint32) (string, bool) { return "alice", true },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o666 {
		t.Fatalf("the power socket's mode %v %v", st.Mode(), err)
	}
	if d, err := os.Stat(dir); err != nil || d.Mode().Perm() != 0o755 {
		t.Fatalf("admin logins can't reach the power socket's directory: %v %v", d.Mode(), err)
	}
	hc := client(sock)
	if _, err := initv1connect.NewPowerServiceClient(hc, "http://power.sock").Reboot(context.Background(), connect.NewRequest(&initv1.RebootRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = initv1connect.NewServicesServiceClient(hc, "http://power.sock").Status(context.Background(), connect.NewRequest(&initv1.StatusRequest{Name: "sshd"}))
	if err == nil {
		t.Fatal("the power socket answered the Services API")
	}
	if !initapi.PowerPeerAllowed(0) || !initapi.PowerPeerAllowed(access.FirstUID) || initapi.PowerPeerAllowed(1000) {
		t.Fatal("the power socket admits root and admin uids only")
	}
}

// The dashboard and the setup wizard reboot and power off as the console,
// with the closed shell's rules (graceful by default, never a reset).
func TestTheConsoleProgramsAreShellCallers(t *testing.T) {
	for _, exe := range []string{initapi.ConsolePath, initapi.FirstbootPath} {
		if initapi.DefaultCallers[exe] != power.KindShell {
			t.Errorf("%s: %v", exe, initapi.DefaultCallers[exe])
		}
	}
}
