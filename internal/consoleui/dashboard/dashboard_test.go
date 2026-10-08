// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package dashboard_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/consoletest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/dashboard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

var now = time.Date(2026, 10, 7, 18, 3, 0, 0, time.UTC)

var (
	full  = keycustody.Full()
	sbOff = keycustody.Reduced(keycustody.ReasonSecureBootOff)
	noSB  = keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware)
	tlsFP = "7C:2E:91:AB:4F:06:D3:E8:B1:5A:6C:90:2E:7F:0A:4D:E3:8B:5C:21:9F:D0:76:A4:C1:E9:0B:3F:8D:62:A7:C5"
	keys  = []sources.HostKey{{Type: "ssh-rsa", Fingerprint: "SHA256:ZE49MXHIq3Pj+N4nEUoUfua0dqGgtmXYcekpDgbLqbw"}, {Type: "ssh-ed25519", Fingerprint: "SHA256:ysknevuNI/Ng13w+vvxlQW6FcH76LnuVdAfLHqOrZRw"}}
)

func chrome(p keycustody.Protection, m keycustody.Mode) consoleui.Chrome {
	return consoleui.Chrome{Version: "0.1.0", Host: "sneakers.example.org", NTP: consoleui.NTPSynced, Now: func() time.Time { return now }, Known: true, Protection: p, Mode: m}
}

func status() *osadminv1.GetStatusResponse {
	return &osadminv1.GetStatusResponse{Version: "0.1.0", Channel: "stable", Hostname: "sneakers.example.org", Phase: "normal",
		ManagementAddresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, NtpSynced: true, TlsFingerprint: tlsFP, TlsSelfSigned: true,
		Health: []*osadminv1.Component{{Name: "netd", Ok: true}, {Name: "init", Ok: true}, {Name: "accessd", Ok: true}}}
}

func data(st *osadminv1.GetStatusResponse) dashboard.Data {
	return dashboard.Data{Status: sources.StatusView{Status: st}, Slot: "A", HostKeys: keys, Platform: sources.PlatformState{State: "running", Nodes: 1}}
}

// Every dashboard state, at the large font and at 80x24, in colour and
// plain.
func TestDashboardScreens(t *testing.T) {
	warned := status()
	warned.ManagementAddresses = []string{"198.51.100.7/24"}
	warned.Warnings = []*osadminv1.Warning{
		{Kind: osadminv1.WarningKind_WARNING_KIND_EXPOSURE, Detail: "The admin page can be reached from the internet. Limit who can connect on the admin page, Network."},
		{Kind: osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION, Detail: "shown on the protection line"},
		{Kind: osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS, Detail: "shown by the fingerprint"},
		{Kind: osadminv1.WarningKind_WARNING_KIND_NTP_UNSYNCED, Detail: "shown on the clock line"},
	}
	warnedData := data(warned)
	unsynced := chrome(sbOff, keycustody.ModeKeyfile)
	unsynced.NTP = consoleui.NTPUnsynced
	degraded := status()
	degraded.Health = []*osadminv1.Component{{Name: "netd", Ok: false, Detail: "connection refused"}, {Name: "init", Ok: true}, {Name: "accessd", Ok: true}}
	degData := data(degraded)
	degData.PlatformErr = errors.New("platformd: connection refused")
	countdown := status()
	countdown.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN, StartedBy: "alice", RunsAt: timestamppb.New(now.Add(23*time.Hour + 59*time.Minute)), Required: 2, Approvals: []string{"alice", "carol"}}
	pending := status()
	pending.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_PENDING, StartedBy: "alice", Required: 2, Approvals: []string{"alice"}}
	staged := status()
	staged.StagedVersion = "0.1.1"
	rolled := status()
	rolled.FailedVersion = "0.1.1"
	reverted := status()
	reverted.RevertedVersion, reverted.RevertedBy, reverted.RevertedAt = "0.1.1", "alice", timestamppb.New(now.Add(-20*time.Minute))
	three := data(status())
	three.Platform.Nodes = 3
	lab := dashboard.Data{Status: sources.StatusView{Status: &osadminv1.GetStatusResponse{Version: "0.0.0-lab.20261007d", Channel: "lab", Phase: "normal",
		Health: []*osadminv1.Component{{Name: "netd", Detail: "connection refused"}, {Name: "init", Ok: true}}}}, Slot: "A",
		NetErr: sources.NotInstalled{What: "The network service"}, PlatformErr: sources.NotInstalled{What: "The platform"}}
	noAddr := data(status())
	noAddr.Status.Status.ManagementAddresses = nil
	cached := data(status())
	cached.Status.Err, cached.Status.Saved = errors.New("connection refused"), now.Add(-7*time.Minute)
	nothing := dashboard.Data{Status: sources.StatusView{Err: errors.New("connection refused")}, Slot: "B"}
	recovering := data(status())
	recovering.Recover = &sources.RecoverCode{Code: "6HDW-2RTE-KM8Q-0VXA", Expires: now.Add(time.Hour)}
	code := sources.RecoverCode{Code: "6HDW-2RTE-KM8Q-0VXA", Expires: now.Add(time.Hour), AttemptsLeft: 5, URL: "https://192.0.2.10:8443/recover"}
	inUse := code
	inUse.InUse, inUse.Source = true, "192.0.2.50"
	cases := map[string]tui.Page{
		"normal":                 dashboard.Page(chrome(full, keycustody.ModeTPM), data(status()), now),
		"reduced-sb-off":         dashboard.Page(chrome(sbOff, keycustody.ModeKeyfile), data(status()), now),
		"reduced-no-sb-no-tpm":   dashboard.Page(chrome(noSB, keycustody.ModeKeyfile), data(status()), now),
		"reduced-no-tpm":         dashboard.Page(chrome(keycustody.Reduced(keycustody.ReasonNoTPM), keycustody.ModeKeyfile), data(status()), now),
		"warnings":               dashboard.Page(unsynced, warnedData, now),
		"three-nodes":            dashboard.Page(chrome(full, keycustody.ModeTPM), three, now),
		"platform-degraded":      dashboard.Page(chrome(full, keycustody.ModeTPM), degData, now),
		"factory-reset":          dashboard.Page(chrome(full, keycustody.ModeTPM), data(countdown), now),
		"factory-reset-pending":  dashboard.Page(chrome(full, keycustody.ModeTPM), data(pending), now),
		"upgrade-staged":         dashboard.Page(chrome(full, keycustody.ModeTPM), data(staged), now),
		"upgrade-rolled-back":    dashboard.Page(chrome(full, keycustody.ModeTPM), data(rolled), now),
		"upgrade-reverted":       dashboard.Page(chrome(full, keycustody.ModeTPM), data(reverted), now),
		"no-address":             dashboard.Page(chrome(full, keycustody.ModeTPM), noAddr, now),
		"accessd-down":           dashboard.Page(chrome(full, keycustody.ModeTPM), cached, now),
		"accessd-down-no-status": dashboard.Page(consoleui.Chrome{Version: "0.1.0", Now: func() time.Time { return now }}, nothing, now),
		"lab-no-netd":            dashboard.Page(chrome(sbOff, keycustody.ModeKeyfile), lab, now),
		"recover-code-out":       dashboard.Page(chrome(full, keycustody.ModeTPM), recovering, now),
		"maintenance":            dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), sources.Upgrade{InProgress: true, Version: "0.1.1", Step: "restarting into 0.1.1"}),
		"maintenance-rolled":     dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), sources.Upgrade{Version: "0.1.1", Failed: "UPGRADE_HEALTH: the platform didn't come up within 10 minutes; booted 0.1.0 again"}),
		"recover":                dashboard.RecoverPage(chrome(full, keycustody.ModeTPM), ""),
		"recover-not-installed":  dashboard.RecoverPage(chrome(full, keycustody.ModeTPM), "No code was made: Recover access by code isn't installed in this build yet"),
		"recover-allow-list":     dashboard.AllowListPage(chrome(full, keycustody.ModeTPM), 2*time.Minute, ""),
		"recover-code":           dashboard.RecoverCodePage(chrome(full, keycustody.ModeTPM), code, tlsFP, now),
		"recover-code-in-use":    dashboard.RecoverCodePage(chrome(full, keycustody.ModeTPM), inUse, tlsFP, now),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) { tuitest.Golden(t, "dashboard-"+name, p) })
	}
}

func TestSlot(t *testing.T) {
	for in, want := range map[string]string{"sneakers-root-a": "A", "sneakers-root-b": "B", "install": "the install medium", "": "unknown"} {
		if got := dashboard.Slot(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// The FQDN's address goes directly under the IP one, and only once the
// box has a name.
func TestTheFQDNFollowsTheIPAddress(t *testing.T) {
	st := status()
	st.Hostname = ""
	if text := dashboard.Page(chrome(full, keycustody.ModeTPM), data(st), now).Frame(64, 24).Text(); strings.Contains(text, "example.org:8443") {
		t.Fatalf("an FQDN line before a name is set:\n%s", text)
	}
	text := dashboard.Page(chrome(full, keycustody.ModeTPM), data(status()), now).Frame(64, 24).Text()
	ip := strings.Index(text, "https://192.0.2.10:8443")
	name := strings.Index(text, "https://sneakers.example.org:8443")
	if ip < 0 || name < ip || strings.Count(text[ip:name], "\n") != 1 {
		t.Fatalf("the FQDN isn't on the line under the IP:\n%s", text)
	}
}

// The node count comes from the platform; the box alone is one.
func TestInfoCountsTheNodes(t *testing.T) {
	d := data(status())
	if got := dashboard.Info(d); got != "slot A  1 node" {
		t.Fatal(got)
	}
	d.Platform.Nodes = 3
	if got := dashboard.Info(d); got != "slot A  3 nodes" {
		t.Fatal(got)
	}
	d.Platform.Nodes = 0
	if got := dashboard.Info(d); got != "slot A  1 node" {
		t.Fatal(got)
	}
}

// The dashboard offers only Recover access, the network editor without an
// address, and cancelling a factory reset counting down.
func TestTheDashboardOffersOnlyItsKeys(t *testing.T) {
	d := data(status())
	if got := dashboard.Keys(d).String(); got != "R  Recover access" {
		t.Fatalf("%q", got)
	}
	d.Status.Status.ManagementAddresses = nil
	if got := dashboard.Keys(d).String(); !strings.Contains(got, "N  Network") {
		t.Fatalf("%q", got)
	}
	cd := status()
	cd.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN}
	if got := dashboard.Keys(data(cd)).String(); !strings.Contains(got, "C  Cancel the reset") {
		t.Fatalf("%q", got)
	}
	text := dashboard.Page(chrome(full, keycustody.ModeTPM), data(status()), now).Frame(64, 24).Text()
	for _, bad := range []string{"menu", "keys list", "console command"} {
		if strings.Contains(text, bad) {
			t.Errorf("the dashboard mentions %q:\n%s", bad, text)
		}
	}
}

type local struct {
	osadminv1connect.UnimplementedLocalServiceHandler
	mu      sync.Mutex
	cancels []string
}

func (l *local) LocalCancelFactoryReset(_ context.Context, r *connect.Request[osadminv1.LocalCancelFactoryResetRequest]) (*connect.Response[osadminv1.LocalCancelFactoryResetResponse], error) {
	l.mu.Lock()
	l.cancels = append(l.cancels, r.Msg.GetActor())
	l.mu.Unlock()
	return connect.NewResponse(&osadminv1.LocalCancelFactoryResetResponse{}), nil
}

// accessNet is accessd's NetworkService: the allow-list reset and its
// confirmation.
type accessNet struct {
	accessv1connect.UnimplementedNetworkServiceHandler
	mu    sync.Mutex
	calls []string
}

func (a *accessNet) ResetAllowList(context.Context, *connect.Request[accessv1.ResetAllowListRequest]) (*connect.Response[accessv1.ResetAllowListResponse], error) {
	a.mu.Lock()
	a.calls = append(a.calls, "reset")
	a.mu.Unlock()
	return connect.NewResponse(&accessv1.ResetAllowListResponse{Token: "T7", RevertAfterSeconds: 120}), nil
}

func (a *accessNet) ConfirmNetwork(_ context.Context, r *connect.Request[accessv1.ConfirmNetworkRequest]) (*connect.Response[accessv1.ConfirmNetworkResponse], error) {
	a.mu.Lock()
	a.calls = append(a.calls, "confirm "+r.Msg.GetToken())
	a.mu.Unlock()
	return connect.NewResponse(&accessv1.ConfirmNetworkResponse{}), nil
}

func (a *accessNet) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

type env struct {
	local   *local
	net     *accessNet
	console *consoletest.Console
	mu      sync.Mutex
	st      *osadminv1.GetStatusResponse
	deps    dashboard.Deps
}

func newEnv() *env {
	e := &env{local: &local{}, net: &accessNet{}, console: consoletest.NewConsole(), st: status()}
	e.deps = dashboard.Deps{
		Chrome: consoleui.Chrome{Version: "0.1.0", Now: func() time.Time { return now }},
		Custody: func(context.Context) (keycustody.Protection, keycustody.Mode, error) {
			return sbOff, keycustody.ModeKeyfile, nil
		},
		Status: func(context.Context) sources.StatusView {
			e.mu.Lock()
			defer e.mu.Unlock()
			return sources.StatusView{Status: e.st}
		},
		Network:   &consoletest.Network{},
		HostKeys:  func() []sources.HostKey { return keys },
		Slot:      "A",
		Upgrades:  sources.NoUpgrades{},
		Platform:  sources.NoPlatform{},
		Console:   e.console,
		AccessNet: e.net,
		Local:     e.local,
		Refresh:   time.Millisecond,
		Now:       func() time.Time { return now },
	}
	return e
}

// setStatus changes a copy, so a status already handed out stays as it
// was.
func (e *env) setStatus(f func(*osadminv1.GetStatusResponse)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, _ := proto.Clone(e.st).(*osadminv1.GetStatusResponse)
	f(st)
	e.st = st
}

func start(t *testing.T, e *env) *tuitest.Driver {
	d := tuitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tuitest.Run(ctx, func(ctx context.Context) error { return dashboard.Run(ctx, d.UI, e.deps) })
	return d
}

// The status view follows the box: a change on Status shows without a key
// pressed.
func TestTheStatusViewRefreshes(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "REDUCED")
	d.Expect(t, "https://192.0.2.10:8443")
	e.setStatus(func(s *osadminv1.GetStatusResponse) { s.StagedVersion = "0.1.1" })
	d.Expect(t, "0.1.1 is staged.")
}

// Recover access, option 1: who can connect is reset, and kept with K.
func TestRecoverAccessResetsWhoCanConnect(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "R  Recover access")
	d.Type(t, "r")
	d.Expect(t, "Use this only when no admin can sign in.")
	d.Type(t, "1")
	d.Expect(t, "press K to keep the change")
	d.Type(t, "k")
	d.Expect(t, "all services running")
	if got := e.net.list(); !slices.Equal(got, []string{"reset", "confirm T7"}) {
		t.Fatalf("calls %v", got)
	}
}

// Recover access, option 2: a one-time code for :8443/recover, which the
// console withdraws on C.
func TestRecoverAccessShowsACode(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "R  Recover access")
	d.Type(t, "r")
	d.Expect(t, "Use this only when no admin can sign in.")
	d.Type(t, "2")
	d.Expect(t, "6HDW-2RTE-KM8Q-0VXA")
	d.Expect(t, "https://192.0.2.10:8443/recover")
	d.Type(t, "c")
	d.Expect(t, "all services running")
	if _, recovers, cancels := e.console.Counts(); recovers != 1 || cancels != 1 {
		t.Fatalf("recovers %d cancels %d", recovers, cancels)
	}
}

// Without the access backend's Recover access, the screen says so and
// stays put.
func TestRecoverAccessWithoutTheBackend(t *testing.T) {
	e := newEnv()
	e.console.RecoverErr = sources.NotInstalled{What: "Recover access by code"}
	d := start(t, e)
	d.Expect(t, "R  Recover access")
	d.Type(t, "r")
	d.Expect(t, "Use this only when no admin can sign in.")
	d.Type(t, "2")
	d.Expect(t, "Recover access by code isn't installed")
	d.Type(t, "")
	d.Expect(t, "all services running")
}

// A factory reset counting down shows, and C cancels it as the console.
func TestAFactoryResetCanBeCancelledOnTheConsole(t *testing.T) {
	e := newEnv()
	e.setStatus(func(s *osadminv1.GetStatusResponse) {
		s.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN, StartedBy: "alice", RunsAt: timestamppb.New(now.Add(time.Hour))}
	})
	d := start(t, e)
	d.Expect(t, "runs in 1h00m")
	d.Type(t, "c")
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.local.mu.Lock()
		got := slices.Clone(e.local.cancels)
		e.local.mu.Unlock()
		if slices.Equal(got, []string{"console"}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancels %v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Keys that aren't offered do nothing.
func TestOtherKeysDoNothing(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "R  Recover access")
	d.Type(t, "reboot")
	d.Type(t, "n")
	d.Type(t, "c")
	d.Expect(t, "all services running")
	if len(e.net.list()) != 0 {
		t.Fatal("a call was made")
	}
}

// The cursor and function keys do nothing in Recover access, and every
// way back (Enter, Esc, 0, b and back) returns to the status view.
func TestRecoverAccessIgnoresCursorKeysAndGoesBack(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "R  Recover access")
	d.Type(t, "r")
	d.Expect(t, "Use this only when no admin can sign in.")
	for _, key := range []string{"\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D", "\x1b[H", "\x1b[F", "\x1b[1~", "\x1b[4~", "\x1bOH", "\x1b[[A", "\x1bOP", "\x1b[15~"} {
		d.Type(t, key)
	}
	// Still on Recover access, with nothing said: 2 is taken there.
	if strings.Contains(d.Last(), "Type 1 or 2") {
		t.Fatalf("a cursor key was taken for a choice:\n%s", d.Last())
	}
	d.Type(t, "2")
	d.Expect(t, "6HDW-2RTE-KM8Q-0VXA")
	d.Type(t, "")
	d.Expect(t, "all services running")
	for _, back := range []string{"", "\x1b", "0", "b", "back"} {
		d.Type(t, "r")
		d.Expect(t, "Use this only when no admin can sign in.")
		d.Type(t, back)
		d.Expect(t, "all services running")
	}
	if len(e.net.list()) != 0 {
		t.Fatal("a call was made")
	}
}

// Back is an item of its own on Recover access, beside 1 and 2.
func TestRecoverAccessListsBack(t *testing.T) {
	text := dashboard.RecoverPage(chrome(full, keycustody.ModeTPM), "").Frame(64, 24).Text()
	if !strings.Contains(text, "0  Back") {
		t.Fatalf("no Back item:\n%s", text)
	}
}

// From the allow-list reset and the code screen, 0, b and Esc go back as
// Enter does.
func TestRecoverSubScreensGoBack(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "R  Recover access")
	d.Type(t, "r")
	d.Expect(t, "Use this only when no admin can sign in.")
	d.Type(t, "1")
	d.Expect(t, "press K to keep the change")
	d.Type(t, "\x1b[C")
	d.Type(t, "0")
	d.Expect(t, "all services running")
	d.Type(t, "r")
	d.Expect(t, "Use this only when no admin can sign in.")
	d.Type(t, "2")
	d.Expect(t, "6HDW-2RTE-KM8Q-0VXA")
	d.Type(t, "\x1b[D")
	d.Type(t, "\x1b")
	d.Expect(t, "all services running")
}
