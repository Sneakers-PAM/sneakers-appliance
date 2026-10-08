// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wizard_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/consoletest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/wizard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

var now = time.Date(2026, 10, 7, 18, 3, 0, 0, time.UTC)

func frame(step wizard.Step, p keycustody.Protection, m keycustody.Mode) wizard.Frame {
	return wizard.Frame{Step: step, Done: make([]bool, 5), Chrome: consoleui.Chrome{Version: "0.1.0", Phase: "firstboot", Host: "sneakers.example.org",
		NTP: consoleui.NTPUnknown, Now: func() time.Time { return now }, Known: true, Protection: p, Mode: m}}
}

var (
	full      = keycustody.Full()
	sbOff     = keycustody.Reduced(keycustody.ReasonSecureBootOff)
	noSB      = keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware)
	noTPM     = keycustody.Reduced(keycustody.ReasonNoTPM)
	nics      = []sources.NIC{{Name: "ens192", MAC: "00:50:56:00:00:01", Driver: "vmxnet3", Up: true, Link: true}, {Name: "ens224", MAC: "00:50:56:00:00:02", Driver: "vmxnet3", Up: true}}
	notUp     = []sources.NIC{{Name: "enp0s2", MAC: "52:54:00:12:34:56", Driver: "virtio_net"}}
	tlsFP     = strings.TrimSuffix(strings.Repeat("3F:A1:", 16), ":")
	errNoNetd = sources.NotInstalled{What: "The network service"}
)

// Every first-boot screen and state of Section 2.11, reduced protection
// included.
func TestWizardScreens(t *testing.T) {
	f := frame(wizard.StepNetwork, sbOff, keycustody.ModeKeyfile)
	s := network.Defaults("ens192")
	static := s
	static.Management.IPv4 = network.Family4{Mode: network.V4Static, Address: netip.MustParsePrefix("192.0.2.10/24"), Gateway: netip.MustParseAddr("192.0.2.1")}
	static.Hostname, static.DNS, static.NTP = "sneakers.example.org", []netip.Addr{netip.MustParseAddr("192.0.2.53")}, []string{"ntp.example.org"}
	svc := s
	svc.Service = &network.Interface{Name: "ens224"}
	checks := []sources.Check{
		{Name: "link", State: sources.CheckOK, Detail: "ens192 is up"},
		{Name: "address", State: sources.CheckOK, Detail: "192.0.2.10/24"},
		{Name: "gateway", State: sources.CheckWarn, Detail: "192.0.2.1 answered slowly", Code: "NET_GATEWAY_SLOW", Skippable: true},
		{Name: "dns", State: sources.CheckOK, Detail: "192.0.2.53 answered"},
		{Name: "ntp", State: sources.CheckFailed, Detail: "no answer from ntp.example.org", Code: "NET_NTP", Skippable: true},
	}
	noAddr := []sources.Check{{Name: "link", State: sources.CheckOK, Detail: "ens192 is up"}, {Name: "address", State: sources.CheckFailed, Detail: "no address after 30 s", Code: "NET_NO_ADDRESS"}}
	allOK := []sources.Check{{Name: "link", State: sources.CheckOK}, {Name: "address", State: sources.CheckOK, Detail: "192.0.2.10/24"}, {Name: "ntp", State: sources.CheckOK, Detail: "offset 3 ms"}}
	running := []sources.Check{{Name: "link", State: sources.CheckOK}, {Name: "address", State: sources.CheckRunning}}
	cont := wizard.Continue{Addresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, TLS: tlsFP, Max: 3, Admin: "alice"}
	one := cont
	one.Recovery = []*osadminv1.RecoveryKey{{Fingerprint: "SHA256:ysknevuNI/Ng13w+vvxlQW6FcH76LnuVdAfLHqOrZRw", Type: "ssh-ed25519", Label: "offline safe"}}
	three := one
	three.Recovery = append(append([]*osadminv1.RecoveryKey(nil), one.Recovery...),
		&osadminv1.RecoveryKey{Fingerprint: "SHA256:ZE49MXHIq3Pj+N4nEUoUfua0dqGgtmXYcekpDgbLqbw", Type: "ssh-ed25519", Label: "carol"},
		&osadminv1.RecoveryKey{Fingerprint: "SHA256:3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "ssh-rsa", Label: "bank vault"})
	pf := func(step wizard.Step, p keycustody.Protection, m keycustody.Mode) wizard.Frame {
		fr := frame(step, p, m)
		for i := 0; i < int(step)-1 && i < 5; i++ {
			fr.Done[i] = true
		}
		return fr
	}
	cases := map[string]tui.Page{
		"network-current":         wizard.CurrentPage(f, sources.Addresses{Management: []string{"192.0.2.10/24", "2001:db8::10/64", "fe80::1/64"}, Hostname: "sneakers.example.org"}, nil),
		"network-current-waiting": wizard.CurrentPage(f, sources.Addresses{}, nil),
		"network-current-error":   wizard.CurrentPage(f, sources.Addresses{}, errors.New("dial unix /run/sneakers/netd.sock: connect: connection refused")),
		"network-checks-current":  wizard.ChecksPage(f, allOK, 0, ""),
		"network-list":            wizard.NICsPage(f, nics, false, "", ""),
		"network-list-bad-number": wizard.NICsPage(f, nics, false, "", "Type a number from 1 to 2."),
		"network-no-link":         wizard.NICsPage(f, []sources.NIC{{Name: "ens192", MAC: "00:50:56:00:00:01", Driver: "vmxnet3", Up: true}}, false, "", ""),
		"network-not-up":          wizard.NICsPage(f, notUp, false, "", ""),
		"network-service":         wizard.NICsPage(f, nics, true, "ens192", ""),
		"network-settings":        wizard.SettingsPage(f, wizard.Form{S: s}, ""),
		"network-settings-static": wizard.SettingsPage(f, wizard.Form{S: static}, ""),
		"network-settings-error":  wizard.SettingsPage(f, wizard.Form{S: svc}, "NET_INVALID: service.ipv4: turn on IPv4 or IPv6 for the service interface"),
		"network-field-ipv4":      wizard.FieldPage(f, 1, ""),
		"network-field-error":     wizard.FieldPage(f, 4, `"192.0.2" isn't an IPv4 or IPv6 address`),
		"network-not-installed":   wizard.NotInstalledPage(f, errNoNetd),
		"network-checks-running":  wizard.ChecksPage(f, running, 120, ""),
		"network-checks-failed":   wizard.ChecksPage(f, checks, 120, ""),
		"network-checks-no-addr":  wizard.ChecksPage(f, noAddr, 120, ""),
		"network-checks-ok":       wizard.ChecksPage(f, allOK, 120, ""),
		"protection-full-tpm":     wizard.ProtectionPage(pf(wizard.StepProtection, full, keycustody.ModeTPM), full, keycustody.ModeTPM),
		"protection-keyfile":      wizard.ProtectionPage(pf(wizard.StepProtection, noTPM, keycustody.ModeKeyfile), noTPM, keycustody.ModeKeyfile),
		"protection-sb-off-tpm":   wizard.ProtectionPage(pf(wizard.StepProtection, sbOff, keycustody.ModeTPM), sbOff, keycustody.ModeTPM),
		"protection-sb-off":       wizard.ProtectionPage(pf(wizard.StepProtection, sbOff, keycustody.ModeKeyfile), sbOff, keycustody.ModeKeyfile),
		"protection-no-sb-no-tpm": wizard.ProtectionPage(pf(wizard.StepProtection, noSB, keycustody.ModeKeyfile), noSB, keycustody.ModeKeyfile),
		"admin":                   wizard.AdminPage(pf(wizard.StepAdmin, sbOff, keycustody.ModeKeyfile), ""),
		"admin-invalid":           wizard.AdminPage(pf(wizard.StepAdmin, sbOff, keycustody.ModeKeyfile), `"Alice!" can't be an admin name: use 2 to 31 lowercase letters, digits, _ or -, starting with a letter, and not a reserved name.`),
		"admin-reserved":          wizard.AdminPage(pf(wizard.StepAdmin, sbOff, keycustody.ModeKeyfile), `"root" can't be an admin name: use 2 to 31 lowercase letters, digits, _ or -, starting with a letter, and not a reserved name.`),
		"continue-waiting":        wizard.ContinuePage(pf(wizard.StepRecovery, sbOff, keycustody.ModeKeyfile), cont),
		"continue-one-key":        wizard.ContinuePage(pf(wizard.StepRecovery, sbOff, keycustody.ModeKeyfile), one),
		"continue-three-keys":     wizard.ContinuePage(pf(wizard.StepRecovery, full, keycustody.ModeTPM), three),
		"continue-no-address":     wizard.ContinuePage(pf(wizard.StepRecovery, sbOff, keycustody.ModeKeyfile), wizard.Continue{AddrErr: errNoNetd, Max: 3, Admin: "alice", OsadminErr: errors.New("exit status 1")}),
		"complete-starting":       wizard.CompletePage(pf(wizard.StepDone, full, keycustody.ModeTPM), wizard.Complete{Starting: true, ProductURL: "https://sneakers.example.org/setup"}),
		"complete-ready":          wizard.CompletePage(pf(wizard.StepDone, full, keycustody.ModeTPM), wizard.Complete{Ready: true, ProductURL: "https://sneakers.example.org/setup"}),
		"single-admin":            wizard.SingleAdminPage(pf(wizard.StepSignIn, sbOff, keycustody.ModeKeyfile), ""),
		"single-admin-retype":     wizard.SingleAdminPage(pf(wizard.StepSignIn, sbOff, keycustody.ModeKeyfile), "Type one admin to go on with one admin, or add a second admin on :8443 first."),
		"continue-complete-error": wizard.ContinuePage(pf(wizard.StepSignIn, sbOff, keycustody.ModeKeyfile), func() wizard.Continue {
			c := one
			c.Err = "Setup can't complete yet: SETUP_INCOMPLETE: a step is still open: the escrow hasn't been written"
			return c
		}()),
		"complete-restart": wizard.CompletePage(pf(wizard.StepDone, sbOff, keycustody.ModeKeyfile), wizard.Complete{HandoverErr: sources.NotInstalled{What: "Moving to normal operation without a restart"}, ProductURL: "https://sneakers.example.org/setup"}),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) { tuitest.Golden(t, "wizard-"+name, p) })
	}
}

// The plan's protection screen: Secure Boot off by choice says so, and
// that turning it on later needs no reinstall.
func TestTheReducedProtectionScreenSaysHowToRaiseIt(t *testing.T) {
	text := wizard.ProtectionPage(frame(wizard.StepProtection, sbOff, keycustody.ModeTPM), sbOff, keycustody.ModeTPM).Frame(80, 24).Text()
	flat := strings.Join(strings.Fields(text), " ")
	for _, want := range []string{"Protection: reduced (Secure Boot off)", "no reinstall"} {
		if !strings.Contains(flat, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
}

type power struct {
	initv1connect.UnimplementedPowerServiceHandler
	reboots atomic.Int32
}

func (p *power) Reboot(context.Context, *connect.Request[initv1.RebootRequest]) (*connect.Response[initv1.RebootResponse], error) {
	p.reboots.Add(1)
	return connect.NewResponse(&initv1.RebootResponse{}), nil
}

type env struct {
	machine *setup.Machine
	paths   setup.Paths
	box     *consoletest.Box
	svcs    *consoletest.Services
	net     *consoletest.Network
	pw      *power
	deps    wizard.Deps
}

func newEnv(t *testing.T) *env {
	paths := setup.Paths{Tmp: t.TempDir(), State: t.TempDir()}
	m, err := setup.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{machine: m, paths: paths, box: consoletest.NewBox(t), svcs: &consoletest.Services{Missing: map[string]bool{}}, pw: &power{},
		net: &consoletest.Network{Addrs: []string{"192.0.2.10/24"}, Results: []sources.Check{{Name: "link", State: sources.CheckOK}, {Name: "address", State: sources.CheckOK, Detail: "192.0.2.10/24"}}}}
	e.deps = wizard.Deps{
		Chrome: consoleui.Chrome{Version: "0.1.0", Phase: "firstboot", Now: func() time.Time { return now }},
		Custody: func(context.Context) (keycustody.Protection, keycustody.Mode, error) {
			return sbOff, keycustody.ModeKeyfile, nil
		},
		Network:  e.net,
		Services: e.svcs,
		Access:   e.box.Access(),
		Setup:    e.box.Setup(),
		Status: func(context.Context) sources.StatusView {
			return sources.StatusView{Status: &osadminv1.GetStatusResponse{TlsFingerprint: tlsFP}}
		},
		Steps: wizard.MachineSteps{M: e.machine},
		Power: e.pw,
	}
	return e
}

// The whole first boot on the console: the network and the protection,
// then :8443, where the first admin is made (accessd starts sshd then),
// and the end asks for a restart while the hand-over to normal isn't
// installed.
func TestFirstBootOpensTheListenersAtTheirSteps(t *testing.T) {
	e := newEnv(t)
	d := tuitest.New(t)
	tuitest.Run(context.Background(), func(ctx context.Context) error { return wizard.Run(ctx, d.UI, e.deps) })
	d.Expect(t, "The box took an address by itself")
	d.Type(t, "e")
	d.Expect(t, "Choose the management interface")
	d.Type(t, "")
	d.Expect(t, "The service interface carries the product")
	d.Type(t, "")
	d.Expect(t, "Management interface ens192")
	d.Type(t, "3")
	d.Expect(t, "host name:")
	d.Type(t, "not a name")
	d.Expect(t, "isn't a fully qualified host name")
	d.Type(t, "sneakers.example.org")
	d.Expect(t, "Host name  sneakers.example.org")
	if got := e.svcs.Starts(); len(got) != 0 {
		t.Fatalf("started before the protection step: %v", got)
	}
	d.Type(t, "")
	d.Expect(t, "Every check passed.")
	d.Type(t, "")
	d.Expect(t, "Protection: reduced (Secure Boot off)")
	d.Type(t, "")
	e.box.AddOwner("alice")
	d.Expect(t, "https://192.0.2.10:8443/")
	if got := e.svcs.Starts(); !slices.Equal(got, []string{"osadmin"}) || !slices.Equal(e.net.Opened(), []string{"ssh+https"}) {
		t.Fatalf("after the protection step: %v, ports %v", got, e.net.Opened())
	}
	e.box.SetRecovery(&osadminv1.RecoveryKey{Fingerprint: "SHA256:ysknevuNI/Ng13w+vvxlQW6FcH76LnuVdAfLHqOrZRw", Type: "ssh-ed25519", Label: "offline safe"})
	d.Expect(t, "offline safe")
	d.Expect(t, "[x] 4 Recovery")
	if e.box.IsDone() {
		t.Fatal("setup completed before the first sign-in")
	}
	e.box.SignIn()
	d.Expect(t, "This box has one admin.")
	d.Type(t, "yes")
	d.Expect(t, "Type one admin to go on with one admin")
	d.Type(t, "one admin")
	d.Expect(t, "Restart to start normal operation")
	if !e.box.IsDone() || !e.machine.Done(setup.StepDone) {
		t.Fatal("setup/done wasn't written")
	}
	if p := setup.ReadProgress(setup.Paths{State: e.paths.State}); !p.Done(setup.StepDone) {
		t.Fatalf("the state volume's progress: %+v", p)
	}
	d.Type(t, "reboot")
	consoletest.Settle()
	applied := e.net.Settings()
	if len(applied) != 1 || applied[0].Hostname != "sneakers.example.org" || !slices.Equal(e.net.Tokens(), []string{"T1"}) || e.pw.reboots.Load() != 1 {
		t.Fatalf("applied %+v kept %v reboots %d", applied, e.net.Tokens(), e.pw.reboots.Load())
	}
}

// netd took an address by itself: Enter keeps it once the checks pass,
// with nothing set or confirmed.
func TestTheAddressNetdTookIsKept(t *testing.T) {
	e := newEnv(t)
	d := tuitest.New(t)
	tuitest.Run(context.Background(), func(ctx context.Context) error { return wizard.Run(ctx, d.UI, e.deps) })
	d.Expect(t, "192.0.2.10/24")
	d.Type(t, "")
	d.Expect(t, "Every check passed.")
	d.Type(t, "")
	d.Expect(t, "Protection: reduced (Secure Boot off)")
	if len(e.net.Settings()) != 0 || len(e.net.Tokens()) != 0 || !e.machine.Done(setup.StepNetwork) {
		t.Fatalf("set %v kept %v", e.net.Settings(), e.net.Tokens())
	}
}

// Without netd the network step says so and goes no further: nothing is
// applied, nothing opens, and no later step is offered.
func TestWithoutNetdSetupStopsAtTheNetwork(t *testing.T) {
	e := newEnv(t)
	e.net.NoNetd = true
	d := tuitest.New(t)
	tuitest.Run(context.Background(), func(ctx context.Context) error { return wizard.Run(ctx, d.UI, e.deps) })
	d.Expect(t, "Choose the management interface")
	d.Type(t, "1")
	d.Type(t, "")
	d.Expect(t, "Management interface ens192")
	d.Type(t, "")
	d.Expect(t, "The network service isn't installed in this build yet.")
	d.Type(t, "r")
	d.Expect(t, "The network service isn't installed in this build yet.")
	d.Type(t, "e")
	d.Expect(t, "Management interface ens192")
	if got := e.svcs.Starts(); len(got) != 0 {
		t.Fatalf("started %v", got)
	}
}

// Checks that fail can be skipped, except a missing address.
func TestAFailedCheckIsSkippedButNoAddressIsNot(t *testing.T) {
	e := newEnv(t)
	e.net.NICs = nics[:1]
	e.net.Results = []sources.Check{{Name: "address", State: sources.CheckFailed, Code: "NET_NO_ADDRESS"}}
	d := tuitest.New(t)
	tuitest.Run(context.Background(), func(ctx context.Context) error { return wizard.Run(ctx, d.UI, e.deps) })
	d.Expect(t, "The box took an address by itself")
	d.Type(t, "e")
	d.Expect(t, "Choose the management interface")
	d.Type(t, "")
	d.Type(t, "")
	d.Expect(t, "This can't be skipped")
	d.Type(t, "c")
	d.Expect(t, "This can't be skipped")
	d.Type(t, "e")
	d.Expect(t, "Management interface ens192")
	e.net.SetResults([]sources.Check{{Name: "address", State: sources.CheckOK}, {Name: "ntp", State: sources.CheckFailed, Code: "NET_NTP", Skippable: true}})
	d.Type(t, "")
	d.Expect(t, "continue anyway")
	d.Type(t, "c")
	d.Expect(t, "Protection: reduced")
	if !slices.Equal(e.net.Tokens(), []string{"T1"}) {
		t.Fatalf("kept %v", e.net.Tokens())
	}
}
