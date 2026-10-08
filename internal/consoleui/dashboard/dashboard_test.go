// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package dashboard_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/consoletest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/dashboard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

var now = time.Date(2026, 10, 7, 18, 3, 0, 0, time.UTC)

var (
	full  = keycustody.Full()
	sbOff = keycustody.Reduced(keycustody.ReasonSecureBootOff)
	noSB  = keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware)
	tlsFP = strings.TrimSuffix(strings.Repeat("3F:A1:", 16), ":")
	keys  = []sources.HostKey{{Type: "ssh-ed25519", Fingerprint: "SHA256:ysknevuNI/Ng13w+vvxlQW6FcH76LnuVdAfLHqOrZRw"}, {Type: "ssh-rsa", Fingerprint: "SHA256:ZE49MXHIq3Pj+N4nEUoUfua0dqGgtmXYcekpDgbLqbw"}}
)

func chrome(p keycustody.Protection, m keycustody.Mode) consoleui.Chrome {
	return consoleui.Chrome{Version: "0.1.0", Phase: "normal", Host: "sneakers.example.org", NTP: consoleui.NTPSynced, Now: func() time.Time { return now }, Known: true, Protection: p, Mode: m}
}

func status() *osadminv1.GetStatusResponse {
	return &osadminv1.GetStatusResponse{Version: "0.1.0", Channel: "stable", Hostname: "sneakers.example.org", Phase: "normal",
		ManagementAddresses: []string{"192.0.2.10/24", "2001:db8::10/64"}, NtpSynced: true, TlsFingerprint: tlsFP, TlsSelfSigned: true,
		Health: []*osadminv1.Component{{Name: "netd", Ok: true}, {Name: "init", Ok: true}}}
}

func data(st *osadminv1.GetStatusResponse) dashboard.Data {
	return dashboard.Data{Status: sources.StatusView{Status: st}, Slot: "A", HostKeys: keys, Platform: sources.PlatformState{State: "running", Nodes: 1}}
}

// Every dashboard state of Section 2.11, reduced protection included.
func TestDashboardScreens(t *testing.T) {
	warned := status()
	warned.ManagementAddresses = []string{"198.51.100.7/24"}
	warned.NtpSynced = false
	warned.Warnings = []*osadminv1.Warning{
		{Kind: osadminv1.WarningKind_WARNING_KIND_EXPOSURE, Detail: "The management interface has a public address and the allow-list lets any source reach ports 22 and 8443."},
		{Kind: osadminv1.WarningKind_WARNING_KIND_REDUCED_PROTECTION, Detail: "shown in the banner"},
		{Kind: osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS, Detail: "shown by the fingerprint"},
		{Kind: osadminv1.WarningKind_WARNING_KIND_NTP_UNSYNCED, Detail: "The clock isn't synchronised with an NTP server."},
		{Kind: osadminv1.WarningKind_WARNING_KIND_CONSOLE_RECOVERY, Detail: "A key for carol was added on the console with Recover access."},
	}
	degraded := status()
	degraded.Health = []*osadminv1.Component{{Name: "netd", Ok: false, Detail: "dial unix /run/sneakers/netd.sock: connect: connection refused"}, {Name: "init", Ok: true}}
	countdown := status()
	countdown.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN, StartedBy: "alice", RunsAt: timestamppb.New(now.Add(23*time.Hour + 59*time.Minute)), Required: 2, Approvals: []string{"alice", "carol"}}
	pending := status()
	pending.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_PENDING, StartedBy: "alice", Required: 2, Approvals: []string{"alice"}}
	staged := status()
	staged.StagedVersion = "0.1.1"
	rolled := status()
	rolled.FailedVersion = "0.1.1"
	degData := data(degraded)
	degData.PlatformErr = errors.New("platformd: connection refused")
	lab := dashboard.Data{Status: sources.StatusView{Status: &osadminv1.GetStatusResponse{Version: "0.0.0-lab.20261007d", Channel: "lab", Phase: "normal",
		Health: []*osadminv1.Component{{Name: "netd", Detail: "connection refused"}, {Name: "init", Ok: true}}}}, Slot: "A",
		NetErr: sources.NotInstalled{What: "The network service"}, PlatformErr: sources.NotInstalled{What: "The platform"}}
	cached := data(status())
	cached.Status.Err, cached.Status.Saved = errors.New("connection refused"), now.Add(-7*time.Minute)
	nothing := dashboard.Data{Status: sources.StatusView{Err: errors.New("connection refused")}, Slot: "B"}
	labChrome := chrome(sbOff, keycustody.ModeKeyfile)
	labChrome.Host, labChrome.NTP = "", consoleui.NTPUnknown
	items := []dashboard.Item{}
	for i, c := range shell.Commands(shell.OriginConsole) {
		items = append(items, dashboard.Item{Key: itoa(i + 1), Label: c.Path})
	}
	items = append(items, dashboard.Item{Key: itoa(len(items) + 1), Label: "Recover access"}, dashboard.Item{Key: itoa(len(items) + 2), Label: "Recent messages"})
	withReset := append(append([]dashboard.Item(nil), items...), dashboard.Item{Key: "c", Label: "Cancel the factory reset"})
	info := map[string]shell.Info{}
	for _, c := range shell.Commands(shell.OriginConsole) {
		info[c.Path] = c
	}
	cases := map[string]tui.Page{
		"normal":                 dashboard.Page(chrome(full, keycustody.ModeTPM), data(status()), now),
		"reduced-sb-off":         dashboard.Page(chrome(sbOff, keycustody.ModeKeyfile), data(status()), now),
		"reduced-sb-off-tpm":     dashboard.Page(chrome(sbOff, keycustody.ModeTPM), data(status()), now),
		"reduced-no-sb-no-tpm":   dashboard.Page(chrome(noSB, keycustody.ModeKeyfile), data(status()), now),
		"reduced-no-tpm":         dashboard.Page(chrome(keycustody.Reduced(keycustody.ReasonNoTPM), keycustody.ModeKeyfile), data(status()), now),
		"warnings":               dashboard.Page(chrome(sbOff, keycustody.ModeKeyfile), data(warned), now),
		"platform-degraded":      dashboard.Page(chrome(full, keycustody.ModeTPM), degData, now),
		"factory-reset":          dashboard.Page(chrome(full, keycustody.ModeTPM), data(countdown), now),
		"factory-reset-pending":  dashboard.Page(chrome(full, keycustody.ModeTPM), data(pending), now),
		"upgrade-staged":         dashboard.Page(chrome(full, keycustody.ModeTPM), data(staged), now),
		"upgrade-rolled-back":    dashboard.Page(chrome(full, keycustody.ModeTPM), data(rolled), now),
		"accessd-down":           dashboard.Page(chrome(full, keycustody.ModeTPM), cached, now),
		"accessd-down-no-status": dashboard.Page(consoleui.Chrome{Version: "0.1.0", Phase: "normal", Now: func() time.Time { return now }}, nothing, now),
		"lab-no-netd":            dashboard.Page(labChrome, lab, now),
		"maintenance":            dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), sources.Upgrade{InProgress: true, Version: "0.1.1", Step: "staging the release into slot B"}),
		"maintenance-rolled":     dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), sources.Upgrade{Version: "0.1.1", Failed: "UPGRADE_HEALTH: the platform didn't come up within 10 minutes; booted 0.1.0 again"}),
		"menu":                   dashboard.MenuPage(chrome(sbOff, keycustody.ModeKeyfile), items, ""),
		"menu-reset":             dashboard.MenuPage(chrome(full, keycustody.ModeTPM), withReset, `"99" isn't on the menu.`),
		"args":                   dashboard.ArgsPage(chrome(full, keycustody.ModeTPM), info["keys list"]),
		"args-key":               dashboard.ArgsPage(chrome(full, keycustody.ModeTPM), info["recovery-key add"]),
		"command-confirm":        dashboard.CommandPage(chrome(sbOff, keycustody.ModeKeyfile), "reboot", nil, "Type reboot to confirm: ", false),
		"command-done":           dashboard.CommandPage(chrome(full, keycustody.ModeTPM), "admins list", []string{"alice  owner  2 keys", "carol  owner  1 key", "bob    admin  1 key"}, "> ", true),
		"messages":               dashboard.MessagesPage(chrome(full, keycustody.ModeTPM), []string{"2026-10-07T18:01:02Z INF services: started service=osadmin", "2026-10-07T18:02:44Z WRN accessd: status refresh failed error=\"netd: connection refused\""}),
		"recover":                dashboard.RecoverPage(chrome(full, keycustody.ModeTPM), []string{"alice", "carol"}, ""),
		"recover-invalid":        dashboard.RecoverPage(chrome(full, keycustody.ModeTPM), []string{"alice"}, `"Root" can't be an admin name: use 2 to 31 lowercase letters, digits, _ or -, starting with a letter, and not a reserved name.`),
		"recover-done":           dashboard.RecoverDonePage(chrome(full, keycustody.ModeTPM), "alice", 1, now.Add(24*time.Hour)),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) { tuitest.Golden(t, "dashboard-"+name, p) })
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestSlot(t *testing.T) {
	for in, want := range map[string]string{"sneakers-root-a": "A", "sneakers-root-b": "B", "install": "the install medium", "": "unknown"} {
		if got := dashboard.Slot(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// backend is the shell's backend: it records each call.
type backend struct {
	mu    sync.Mutex
	calls []string
}

func (b *backend) Call(_ context.Context, r shell.Request) (shell.Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, strings.TrimSpace(r.Action+" "+strings.Join(r.Args, " ")))
	switch r.Action {
	case "admins.list":
		return shell.Result{Text: "alice  owner  1 key"}, nil
	case "network.allowlist.reset":
		return shell.Result{Text: "The allow-list is back to the on-link default. Confirm within 120 s: network confirm T1"}, nil
	}
	return shell.Result{Text: "done"}, nil
}

func (b *backend) actions() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.calls...)
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

type env struct {
	box   *consoletest.Box
	be    *backend
	local *local
	mu    sync.Mutex
	st    *osadminv1.GetStatusResponse
	deps  dashboard.Deps
}

func newEnv(t *testing.T) *env {
	e := &env{box: consoletest.NewBox(t, "alice", "carol"), be: &backend{}, local: &local{}, st: status()}
	msgs := filepath.Join(t.TempDir(), "console.log")
	if err := os.WriteFile(msgs, []byte("services: started service=osadmin\n\x1b[2Jservices: exited service=sshd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.deps = dashboard.Deps{
		Chrome: consoleui.Chrome{Version: "0.1.0", Phase: "normal", Now: func() time.Time { return now }},
		Custody: func(context.Context) (keycustody.Protection, keycustody.Mode, error) {
			return sbOff, keycustody.ModeKeyfile, nil
		},
		Status: func(context.Context) sources.StatusView {
			e.mu.Lock()
			defer e.mu.Unlock()
			return sources.StatusView{Status: e.st}
		},
		Network:      &consoletest.Network{},
		HostKeys:     func() []sources.HostKey { return keys },
		Slot:         "A",
		Upgrades:     sources.NoUpgrades{},
		Platform:     sources.NoPlatform{},
		Shell:        e.be,
		Access:       e.box.Access(),
		Local:        e.local,
		Setup:        e.box.Setup(),
		MessagesFile: msgs,
		Refresh:      time.Millisecond,
		Now:          func() time.Time { return now },
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
	tuitest.Run(context.Background(), func(ctx context.Context) error { return dashboard.Run(ctx, d.UI, e.deps) })
	return d
}

// The status view follows the box: a change on Status shows without a key
// pressed.
func TestTheStatusViewRefreshes(t *testing.T) {
	e := newEnv(t)
	d := start(t, e)
	d.Expect(t, "!! Protection: reduced (Secure Boot off)")
	d.Expect(t, "https://192.0.2.10:8443/")
	e.setStatus(func(s *osadminv1.GetStatusResponse) { s.StagedVersion = "0.1.1" })
	d.Expect(t, "0.1.1 staged")
}

// The menu runs the console's commands through the closed shell's table,
// with their typed confirmations.
func TestTheMenuRunsConsoleCommands(t *testing.T) {
	e := newEnv(t)
	d := start(t, e)
	d.Expect(t, "Enter: menu")
	d.Type(t, "")
	menu := d.Expect(t, "Recover access")
	if strings.Contains(menu, " login") || !strings.Contains(menu, "network allow-list reset") {
		t.Fatalf("menu:\n%s", menu)
	}
	d.Type(t, "7")
	d.Expect(t, "alice  owner  1 key")
	d.Type(t, "")
	d.Expect(t, "Recover access")
	d.Type(t, "5")
	d.Expect(t, "Type reset to confirm:")
	d.Type(t, "reset")
	d.Expect(t, "on-link default")
	d.Type(t, "")
	d.Type(t, "")
	d.Expect(t, "Enter: menu")
	d.Type(t, "reboot")
	d.Expect(t, "Type reboot to confirm:")
	d.Type(t, "no")
	d.Expect(t, "not confirmed")
	d.Type(t, "")
	if got := e.be.actions(); !slices.Equal(got, []string{"admins.list", "network.allowlist.reset"}) {
		t.Fatalf("calls %v", got)
	}
}

// The plan's console-only command: the allow-list reset is the console's
// lockout recovery, and the SSH shell doesn't have it.
func TestAllowListResetConsoleOnly(t *testing.T) {
	var console, ssh bool
	for _, c := range shell.Commands(shell.OriginConsole) {
		console = console || c.Path == "network allow-list reset"
	}
	for _, c := range shell.Commands(shell.OriginSSH) {
		ssh = ssh || c.Path == "network allow-list reset"
	}
	if !console || ssh {
		t.Fatalf("console %v ssh %v", console, ssh)
	}
}

// Recover access shows a one-time code and the page it opens on :8443.
func TestRecoverAccessShowsACode(t *testing.T) {
	e := newEnv(t)
	d := start(t, e)
	d.Expect(t, "Enter: menu")
	d.Type(t, "")
	d.Expect(t, "Recover access")
	d.Type(t, itoa(len(shell.Commands(shell.OriginConsole))+1))
	d.Expect(t, consoletest.RecoverCode)
	d.Expect(t, "https://192.0.2.10:8443/recover")
}

// A factory reset counting down shows on the status view and can be
// cancelled from the menu, as the console.
func TestAFactoryResetCanBeCancelledOnTheConsole(t *testing.T) {
	e := newEnv(t)
	e.setStatus(func(s *osadminv1.GetStatusResponse) {
		s.FactoryReset = &osadminv1.FactoryReset{State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN, StartedBy: "alice", RunsAt: timestamppb.New(now.Add(time.Hour))}
	})
	d := start(t, e)
	d.Expect(t, "Factory reset requested by alice runs in 1h00m")
	d.Type(t, "")
	d.Expect(t, "Cancel the factory reset")
	d.Type(t, "c")
	d.Expect(t, "Type cancel to stop the factory reset:")
	d.Type(t, "cancel")
	d.Expect(t, "The factory reset is cancelled.")
	e.local.mu.Lock()
	defer e.local.mu.Unlock()
	if !slices.Equal(e.local.cancels, []string{"console"}) {
		t.Fatalf("cancels %v", e.local.cancels)
	}
}

// Recent messages shows the shared output as plain text: nothing in it can
// drive the screen.
func TestRecentMessagesArePlainText(t *testing.T) {
	e := newEnv(t)
	d := start(t, e)
	d.Expect(t, "Enter: menu")
	d.Type(t, "")
	d.Expect(t, "Recent messages")
	d.Type(t, itoa(len(shell.Commands(shell.OriginConsole))+2))
	got := d.Expect(t, "services: exited service=sshd")
	if strings.Contains(got, "\x1b") {
		t.Fatalf("an escape reached the screen:\n%q", got)
	}
}
