// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package firstboot_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"google.golang.org/protobuf/proto"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/consoletest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/firstboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/netedit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

func at() time.Time { return time.Date(2026, 10, 7, 14, 3, 0, 0, time.UTC) }

func chrome(p keycustody.Protection, m keycustody.Mode) consoleui.Chrome {
	return consoleui.Chrome{Version: "0.1.0", Host: "sneakers.example.org", NTP: consoleui.NTPSynced, Now: at, Known: true, Protection: p, Mode: m}
}

func full() consoleui.Chrome { return chrome(keycustody.Full(), keycustody.ModeTPM) }

func reduced() consoleui.Chrome {
	return chrome(keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware), keycustody.ModeKeyfile)
}

func info() sources.ConsoleInfo {
	i, _ := consoletest.NewConsole().Read(context.Background())
	return i
}

func TestGoldenScreens(t *testing.T) {
	c := full()
	tuitest.Golden(t, "starting", firstboot.StartingPage(c, []firstboot.Item{
		{Name: "system image verified", State: "ok"}, {Name: "encrypted data disk", State: "ok"},
		{Name: "network", State: "busy", Took: 42 * time.Second}, {Name: "setup page"},
	}))
	tuitest.Golden(t, "info-full", firstboot.InfoPage(c, info(), at(), ""))
	tuitest.Golden(t, "info-reduced", firstboot.InfoPage(reduced(), info(), at(), ""))
	two := info()
	two.URLs = append(two.URLs, "https://[2001:db8::10]:8443")
	tuitest.Golden(t, "info-two-addresses", firstboot.InfoPage(c, two, at(), ""))
	named := two
	named.FQDN = "sneakers.example.org"
	tuitest.Golden(t, "info-fqdn", firstboot.InfoPage(reduced(), named, at(), ""))
	waiting := info()
	waiting.URL, waiting.URLs, waiting.CertFingerprint = "", nil, ""
	tuitest.Golden(t, "info-waiting", firstboot.InfoPage(c, waiting, at(), "The access service isn't answering yet: connection refused"))
	unknown := consoleui.Chrome{Version: "0.1.0", Now: at}
	locked := info()
	locked.CodeLocked, locked.SetupCode = true, ""
	tuitest.Golden(t, "info-locked", firstboot.InfoPage(c, locked, at(), ""))
	tuitest.Golden(t, "info-protection-unknown", firstboot.InfoPage(unknown, info(), at(), ""))
	busy := info()
	busy.State, busy.SetupSource, busy.SetupStarted, busy.SetupStep, busy.StepName = sources.SetupInProgress, "192.0.2.50", at(), 2, "Create the first admin"
	tuitest.Golden(t, "setting-up", firstboot.SettingUpPage(c, busy, ""))
	busy.FirstAdmin, busy.SetupStep, busy.StepName = "alice", 3, "Recovery keys"
	tuitest.Golden(t, "setting-up-admin", firstboot.SettingUpPage(c, busy, ""))
	tuitest.Golden(t, "finish", firstboot.FinishPage(c, false, ""))
	tuitest.Golden(t, "finish-restart", firstboot.FinishPage(c, true, ""))
	tuitest.Golden(t, "finish-restart-refused", firstboot.FinishPage(c, true, "The restart was refused: init isn't answering. It's tried again in 30 seconds."))
	nics := []sources.NIC{{Name: "ens192", MAC: "00:50:56:00:00:01", Link: true}, {Name: "ens224", MAC: "00:50:56:00:00:02"}}
	tuitest.Golden(t, "no-address", netedit.NoAddressPage(c, nics, ""))
}

// The FQDN's address goes directly under the IP one, and only once the
// box has a name.
func TestTheFQDNFollowsTheIPAddress(t *testing.T) {
	i := info()
	if text := firstboot.InfoPage(full(), i, at(), "").Frame(64, 24).Text(); strings.Contains(text, "example.org") {
		t.Fatalf("an FQDN line before a name is set:\n%s", text)
	}
	i.FQDN = "sneakers.example.org"
	text := firstboot.InfoPage(full(), i, at(), "").Frame(64, 24).Text()
	ip := strings.Index(text, "https://192.0.2.10:8443")
	name := strings.Index(text, "https://sneakers.example.org:8443")
	if ip < 0 || name < ip || strings.Count(text[ip:name], "\n") != 1 {
		t.Fatalf("the FQDN isn't on the line under the IP:\n%s", text)
	}
}

// The info screen has what the admin needs and nothing to answer: the
// address, the fingerprint in groups of four, the code and the protection.
func TestTheInfoScreenHasEverythingAndAsksNothing(t *testing.T) {
	p := firstboot.InfoPage(reduced(), info(), at(), "")
	text := p.Frame(64, 24).Text()
	for _, want := range []string{"https://192.0.2.10:8443", "7C2E 91AB 4F06 D3E8 B15A 6C90 2E7F 0A4D", "E38B 5C21 9FD0 76A4 C1E9 0B3F 8D62 A7C5", "7PQK-NMS9-XD2A-4KJW", "expires in 59 min", "REDUCED", "no TPM, no Secure Boot"} {
		if !strings.Contains(text, want) {
			t.Errorf("the info screen lacks %q:\n%s", want, text)
		}
	}
	if p.Prompt != "" || len(p.Keys) != 0 {
		t.Errorf("the info screen asks for something: %q %v", p.Prompt, p.Keys)
	}
	for _, bad := range []string{"yes", "enrol", "SSH key", "press D"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(bad)) {
			t.Errorf("the info screen mentions %q:\n%s", bad, text)
		}
	}
}

// setupSvc is accessd's setup state: what :8443 has done, and Complete.
type setupSvc struct {
	mu        sync.Mutex
	state     *osadminv1.GetSetupResponse
	completes int
}

func (s *setupSvc) set(f func(*osadminv1.GetSetupResponse)) {
	s.mu.Lock()
	f(s.state)
	s.mu.Unlock()
}

func (s *setupSvc) GetSetup(context.Context, *connect.Request[accessv1.GetSetupRequest]) (*connect.Response[accessv1.GetSetupResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, _ := proto.Clone(s.state).(*osadminv1.GetSetupResponse)
	return connect.NewResponse(&accessv1.GetSetupResponse{Setup: st}), nil
}

func (s *setupSvc) Complete(context.Context, *connect.Request[accessv1.CompleteRequest]) (*connect.Response[accessv1.CompleteResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completes++
	s.state.Done = true
	return connect.NewResponse(&accessv1.CompleteResponse{}), nil
}

func (s *setupSvc) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.completes
}

// power is init's PowerService: it records each reboot.
type power struct {
	initv1connect.UnimplementedPowerServiceHandler
	mu      sync.Mutex
	reboots int
}

func (p *power) Reboot(context.Context, *connect.Request[initv1.RebootRequest]) (*connect.Response[initv1.RebootResponse], error) {
	p.mu.Lock()
	p.reboots++
	p.mu.Unlock()
	return connect.NewResponse(&initv1.RebootResponse{}), nil
}

func (p *power) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reboots
}

type box struct {
	net     *consoletest.Network
	svc     *consoletest.Services
	console *consoletest.Console
	power   *power
	setup   *setupSvc
	m       *setup.Machine
	deps    firstboot.Deps
}

func newBox(t *testing.T) *box {
	t.Helper()
	dir := t.TempDir()
	m, err := setup.Open(setup.Paths{Tmp: filepath.Join(dir, "tmp"), State: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	b := &box{net: &consoletest.Network{}, svc: &consoletest.Services{}, console: consoletest.NewConsole(), power: &power{}, setup: &setupSvc{state: &osadminv1.GetSetupResponse{SingleAdminWarning: true}}, m: m}
	b.deps = firstboot.Deps{
		Chrome: consoleui.Chrome{Version: "0.1.0", Now: at},
		Custody: func(context.Context) (keycustody.Protection, keycustody.Mode, error) {
			return keycustody.Full(), keycustody.ModeTPM, nil
		},
		Network: b.net, Services: b.svc, Console: b.console, Setup: b.setup, Steps: firstboot.MachineSteps{M: m}, Power: b.power,
		DHCPWait: 50 * time.Millisecond, RestartAfter: time.Millisecond,
	}
	return b
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// With a DHCP address the console asks nothing: the start-up, then the
// info screen with :8443 open and SSH still closed; the first admin turns
// SSH on, setup done restarts the box into normal operation.
func TestFirstBootWithDHCPAsksNothing(t *testing.T) {
	b := newBox(t)
	b.net.SetAddrs("192.0.2.10/24")
	d := tuitest.New(t)
	b.deps.Console = b.console
	d.UI.Wake = b.console.Changed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := tuitest.Run(ctx, func(ctx context.Context) error { return firstboot.Run(ctx, d.UI, b.deps) })
	d.Expect(t, "7PQK-NMS9-XD2A-4KJW")
	if !b.m.Done(setup.StepNetwork) || !b.m.Done(setup.StepProtection) || b.m.Done(setup.StepAdmin) {
		t.Fatalf("steps: network %v protection %v admin %v", b.m.Done(setup.StepNetwork), b.m.Done(setup.StepProtection), b.m.Done(setup.StepAdmin))
	}
	if got := strings.Join(b.net.Opened(), ","); got != "https" {
		t.Fatalf("ports %q", got)
	}
	if got := strings.Join(b.svc.Starts(), ","); got != "osadmin" {
		t.Fatalf("started %q", got)
	}
	b.console.Set(func(i *sources.ConsoleInfo) {
		i.State, i.SetupSource, i.SetupStep, i.StepName = sources.SetupInProgress, "192.0.2.50", 2, "Create the first admin"
	})
	d.Expect(t, "Setup is running in a browser.")
	b.console.Set(func(i *sources.ConsoleInfo) { i.FirstAdmin, i.SSHOn = "alice", true })
	d.Expect(t, "alice")
	waitFor(t, "sshd", func() bool { return strings.Contains(strings.Join(b.svc.Starts(), ","), "sshd") })
	if got := strings.Join(b.net.Opened(), ","); got != "https,ssh+https" {
		t.Fatalf("ports %q", got)
	}
	if !b.m.Done(setup.StepAdmin) {
		t.Fatal("the admin step isn't done")
	}
	b.console.Set(func(i *sources.ConsoleInfo) { i.State = sources.SetupDone })
	d.Expect(t, "Setup is done.")
	waitFor(t, "the restart", func() bool { return b.power.count() == 1 })
	if !b.m.Done(setup.StepDone) {
		t.Fatal("setup isn't done")
	}
	cancel()
	<-res
}

// First boot follows :8443's steps: a recovery key, then the first
// sign-in, then, once the single admin is confirmed on the page, it asks
// accessd to complete setup and restarts into normal operation.
func TestFirstBootCompletesSetupAfterTheSteps(t *testing.T) {
	b := newBox(t)
	b.net.SetAddrs("192.0.2.10/24")
	d := tuitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := tuitest.Run(ctx, func(ctx context.Context) error { return firstboot.Run(ctx, d.UI, b.deps) })
	b.console.Set(func(i *sources.ConsoleInfo) { i.State, i.FirstAdmin = sources.SetupInProgress, "alice" })
	waitFor(t, "the admin step", func() bool { return b.m.Done(setup.StepAdmin) })
	b.setup.set(func(s *osadminv1.GetSetupResponse) {
		s.RecoveryKeys = []*osadminv1.RecoveryKey{{Fingerprint: "SHA256:x"}}
	})
	waitFor(t, "the recovery step", func() bool { return b.m.Done(setup.StepRecovery) })
	b.setup.set(func(s *osadminv1.GetSetupResponse) { s.SignedIn = true })
	waitFor(t, "the sign-in step", func() bool { return b.m.Done(setup.StepSignIn) })
	consoletest.Settle()
	if b.setup.count() != 0 {
		t.Fatal("setup completed before the single admin was confirmed")
	}
	b.setup.set(func(s *osadminv1.GetSetupResponse) { s.SingleAdminAcknowledged = true })
	d.Expect(t, "Setup is done.")
	waitFor(t, "the restart", func() bool { return b.power.count() == 1 })
	if b.setup.count() != 1 || !b.m.Done(setup.StepDone) {
		t.Fatalf("completes %d, done %v", b.setup.count(), b.m.Done(setup.StepDone))
	}
	cancel()
	<-res
}

// X while a browser sets the box up (before the first admin) stops it and
// shows a new code.
func TestXStopsABrowserSetup(t *testing.T) {
	b := newBox(t)
	b.net.SetAddrs("192.0.2.10/24")
	b.console.Set(func(i *sources.ConsoleInfo) { i.State, i.SetupSource = sources.SetupInProgress, "192.0.2.50" })
	d := tuitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := tuitest.Run(ctx, func(ctx context.Context) error { return firstboot.Run(ctx, d.UI, b.deps) })
	d.Expect(t, "Stop this setup")
	d.Type(t, "x")
	d.Expect(t, "4KJW-XD2A-7PQK-NMS9")
	if resets, _, _ := b.console.Counts(); resets != 1 {
		t.Fatalf("%d resets", resets)
	}
	cancel()
	<-res
}

// A setup code locked by wrong tries works no more; N asks for a new one.
func TestNAsksForANewCodeWhenLocked(t *testing.T) {
	b := newBox(t)
	b.net.SetAddrs("192.0.2.10/24")
	b.console.Set(func(i *sources.ConsoleInfo) { i.CodeLocked, i.SetupCode = true, "" })
	d := tuitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := tuitest.Run(ctx, func(ctx context.Context) error { return firstboot.Run(ctx, d.UI, b.deps) })
	d.Expect(t, "Show a new setup code")
	d.Type(t, "n")
	d.Expect(t, "4KJW-XD2A-7PQK-NMS9")
	if resets, _, _ := b.console.Counts(); resets != 1 {
		t.Fatalf("%d resets", resets)
	}
	cancel()
	<-res
}

// No DHCP address: after the wait the console offers the editor, and an
// address set by hand is checked, then kept.
func TestNoDHCPOffersTheEditor(t *testing.T) {
	b := newBox(t)
	b.net.SetResults([]sources.Check{{Name: "link", State: sources.CheckOK}, {Name: "gateway", State: sources.CheckOK}})
	d := tuitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := tuitest.Run(ctx, func(ctx context.Context) error { return firstboot.Run(ctx, d.UI, b.deps) })
	d.Expect(t, "Starting up.")
	d.Expect(t, "This box has no network address yet.")
	d.Type(t, "n")
	d.Expect(t, "field 1 of 4")
	d.Type(t, "")
	d.Expect(t, "field 2 of 4")
	d.Type(t, "192.0.2.10")
	d.Expect(t, "isn't an address with its prefix")
	d.Type(t, "192.0.2.10/24")
	d.Expect(t, "field 3 of 4")
	d.Type(t, "192.0.2.1")
	d.Expect(t, "field 4 of 4")
	d.Type(t, "192.0.2.53")
	d.Expect(t, "Use these settings")
	b.net.SetAddrs("192.0.2.10/24")
	d.Type(t, "")
	d.Expect(t, "7PQK-NMS9-XD2A-4KJW")
	s := b.net.Settings()
	if len(s) != 1 || s[0].Management.Name != "ens192" || s[0].Management.IPv4.Mode != network.V4Static ||
		s[0].Management.IPv4.Address.String() != "192.0.2.10/24" || s[0].Management.IPv4.Gateway.String() != "192.0.2.1" || len(s[0].DNS) != 1 {
		t.Fatalf("settings %+v", s)
	}
	if got := b.net.Tokens(); len(got) != 1 || got[0] != "T1" {
		t.Fatalf("kept %q", got)
	}
	cancel()
	<-res
}

// R waits for DHCP again; an address arriving then moves on by itself.
func TestTryDHCPAgain(t *testing.T) {
	b := newBox(t)
	d := tuitest.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := tuitest.Run(ctx, func(ctx context.Context) error { return firstboot.Run(ctx, d.UI, b.deps) })
	d.Expect(t, "This box has no network address yet.")
	d.Type(t, "r")
	d.Expect(t, "Starting up.")
	b.net.SetAddrs("192.0.2.10/24")
	d.Expect(t, "7PQK-NMS9-XD2A-4KJW")
	cancel()
	<-res
}
