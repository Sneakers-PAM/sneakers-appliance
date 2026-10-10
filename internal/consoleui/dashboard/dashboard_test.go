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
	staging := progress("stage", "0.1.1", "stage", "Writing the release into slot B.")
	staging.Steps[1].DoneBytes, staging.Steps[1].TotalBytes = 734003200, 1468006400
	rebooting := progress("apply", "0.1.1", "reboot", "The box restarts into 0.1.1.")
	checking := progress("apply", "0.1.1", "health", "Waiting for netd to answer: connection refused")
	reverting := progress("revert", "0.0.9", "reboot", "The box restarts into 0.0.9.")
	reverting.Steps = reverting.Steps[2:]
	productUp := productProgress("pods", "2 of 5 pods ready")
	stepFailed := status()
	stepFailed.UpgradeProgress = progress("stage", "0.1.1", "verify", "")
	stepFailed.UpgradeProgress.InProgress, stepFailed.UpgradeProgress.Failed, stepFailed.UpgradeProgress.Code = false, true, "UPGRADE_SIGNATURE"
	stepFailed.UpgradeProgress.Steps[0].State = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED
	stepFailed.UpgradeProgress.Steps[0].Detail = "UPGRADE_SIGNATURE (2505): the package isn't signed by this box's release key"
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
	hello := status()
	hello.RunningVersion, hello.PreviousVersion, hello.PreviousSlot = "0.1.0", "0.0.9", "B"
	hello.Product = &osadminv1.ProductSlots{InstalledVersion: "0.1.0-lab.hello.1", Running: true}
	helloData := data(hello)
	helloData.Platform, helloData.PlatformErr = sources.PlatformState{}, sources.NotInstalled{What: "The platform"}
	cases := map[string]tui.Page{
		"normal":                 dashboard.Page(chrome(full, keycustody.ModeTPM), data(status()), now),
		"product-installed":      dashboard.Page(chrome(full, keycustody.ModeTPM), helloData, now),
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
		"maintenance-staging":    dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), staging),
		"maintenance-rebooting":  dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), rebooting),
		"maintenance-health":     dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), checking),
		"maintenance-revert":     dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), reverting),
		"maintenance-product":    dashboard.MaintenancePage(chrome(full, keycustody.ModeTPM), productUp),
		"upgrade-step-failed":    dashboard.Page(chrome(full, keycustody.ModeTPM), data(stepFailed), now),
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

// progress is an update on step at, the steps before it done and the rest
// pending.
func progress(action, version, at, detail string) *osadminv1.UpgradeProgress {
	ids := []string{"verify", "stage", "switch", "reboot", "health", "mark_good"}
	labels := []string{"Verifying (signature, channel, SHA-256)", "Staging into slot B", "Switching slots", "Rebooting", "Checking health", "Marking good"}
	p := &osadminv1.UpgradeProgress{Action: action, Version: version, InProgress: true, UpdatedAt: timestamppb.New(now.Add(-time.Minute))}
	state := osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_DONE
	for i, id := range ids {
		st := &osadminv1.UpgradeStep{Id: id, Label: labels[i], State: state}
		if id == at {
			st.State, st.Detail = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_ACTIVE, detail
			state = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_PENDING
		}
		p.Steps = append(p.Steps, st)
	}
	return p
}

// productProgress is a product apply coming up, on step at.
func productProgress(at, detail string) *osadminv1.UpgradeProgress {
	ids := []string{"verify", "stage", "switch", "restart", "k0s", "images", "manifests", "pods", "edge"}
	labels := []string{"Verifying (signature, channel, SHA-256)", "Staging into the free product slot", "Switching slots", "Restarting the product", "Starting k0s", "Importing the images", "Applying the product's stacks", "Waiting for the pods to be ready", "Opening the product on 443"}
	p := &osadminv1.UpgradeProgress{Action: "apply", Target: osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, Version: "0.2.0", InProgress: true, UpdatedAt: timestamppb.New(now.Add(-time.Minute))}
	state := osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_DONE
	for i, id := range ids {
		st := &osadminv1.UpgradeStep{Id: id, Label: labels[i], State: state}
		if id == at {
			st.State, st.Detail = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_ACTIVE, detail
			state = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_PENDING
		}
		p.Steps = append(p.Steps, st)
	}
	return p
}

// An update in progress takes over the status view with its steps; once
// it's done the status view comes back.
func TestTheMaintenanceViewFollowsAnUpdate(t *testing.T) {
	e := newEnv()
	d := start(t, e)
	d.Expect(t, "https://192.0.2.10:8443")
	e.setStatus(func(s *osadminv1.GetStatusResponse) { s.UpgradeProgress = progress("apply", "0.1.1", "reboot", "") })
	d.Expect(t, "Updating to 0.1.1. Leave it powered on.")
	d.Expect(t, "Rebooting")
	e.setStatus(func(s *osadminv1.GetStatusResponse) { s.UpgradeProgress = progress("apply", "0.1.1", "mark_good", "") })
	d.Expect(t, "Marking good")
	e.setStatus(func(s *osadminv1.GetStatusResponse) { s.UpgradeProgress.InProgress = false })
	d.Expect(t, "https://192.0.2.10:8443")
}

// A failed step shows on the status view for a day, then goes.
func TestAFailedStepWarnsForADay(t *testing.T) {
	st := status()
	st.UpgradeProgress = progress("stage", "0.1.1", "stage", "")
	st.UpgradeProgress.InProgress, st.UpgradeProgress.Failed = false, true
	st.UpgradeProgress.Steps[1].State, st.UpgradeProgress.Steps[1].Detail = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED, "the disk is full"
	text := func(ls []tui.Line) string {
		var b strings.Builder
		for _, l := range ls {
			b.WriteString(l.String() + "\n")
		}
		return b.String()
	}
	got := text(dashboard.Warnings(chrome(full, keycustody.ModeTPM), data(st), now))
	if !strings.Contains(got, "The update to 0.1.1 failed.") || !strings.Contains(got, "Staging into slot B: the disk is full") {
		t.Fatalf("warnings:\n%s", got)
	}
	if got := text(dashboard.Warnings(chrome(full, keycustody.ModeTPM), data(st), now.Add(25*time.Hour))); strings.Contains(got, "failed") {
		t.Fatalf("a day later:\n%s", got)
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

// The SSH line says where the key comes from: SSH takes only a key the
// box issued on :8443, then a TOTP code.
func TestTheSSHLineSaysTheKeyComesFromTheAdminPage(t *testing.T) {
	text := dashboard.Page(chrome(full, keycustody.ModeTPM), data(status()), now).Frame(64, 24).Text()
	if !strings.Contains(text, "key from :8443 Access, then TOTP") {
		t.Fatalf("the SSH line doesn't say where the key comes from:\n%s", text)
	}
}

// The status view shows the maintenance screen only while a step is
// active: once a reboot that never came is given up on, it's back on the
// status screen with the failure as a warning.
func TestTheStatusViewLeavesMaintenanceWhenTheRebootIsGivenUp(t *testing.T) {
	c := chrome(full, keycustody.ModeTPM)
	waiting := status()
	waiting.UpgradeProgress = progress("apply", "0.1.1", "reboot", "The box restarts into 0.1.1.")
	if got, want := dashboard.Screen(c, data(waiting), now).Frame(80, 24).Text(), dashboard.MaintenancePage(c, waiting.UpgradeProgress).Frame(80, 24).Text(); got != want {
		t.Fatalf("while rebooting the status view shows:\n%s", got)
	}
	missed := status()
	missed.UpgradeProgress = progress("apply", "0.1.1", "reboot", "")
	missed.UpgradeProgress.InProgress, missed.UpgradeProgress.Failed, missed.UpgradeProgress.Code = false, true, "UPGRADE_NO_REBOOT"
	missed.UpgradeProgress.Steps[3].State = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED
	missed.UpgradeProgress.Steps[3].Detail = "The box didn't reboot into 0.1.1 within 10 minutes. Apply again, or restart the box."
	p := dashboard.Screen(c, data(missed), now)
	if txt := p.Frame(120, 60).Text(); !strings.Contains(txt, "didn't reboot into 0.1.1") || strings.Contains(txt, "Leave it powered on") {
		t.Fatalf("after the reboot was given up on the status view shows:\n%s", txt)
	}
	tuitest.Golden(t, "dashboard-upgrade-reboot-missed", p)
}

// A Base Web switch leaves the box and the product alone and takes
// seconds: the status view stays on the status screen while it runs.
func TestABaseWebSwitchKeepsTheStatusScreen(t *testing.T) {
	c := chrome(full, keycustody.ModeTPM)
	st := status()
	st.UpgradeProgress = progress("apply", "0.1.2", "switch", "")
	st.UpgradeProgress.Target = osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB
	if got, want := dashboard.Screen(c, data(st), now).Frame(80, 24).Text(), dashboard.Page(c, data(st), now).Frame(80, 24).Text(); got != want {
		t.Fatalf("during a Base Web switch the status view shows:\n%s", got)
	}
}

// Until platformd is in the build, the Product line reads the product's
// slots from Status, and the Base line the base's: the version running,
// its slot, and what's staged or kept to go back to.
func TestTheBaseAndProductLines(t *testing.T) {
	noPlatform := func(st *osadminv1.GetStatusResponse) dashboard.Data {
		d := data(st)
		d.Platform, d.PlatformErr = sources.PlatformState{}, sources.NotInstalled{What: "The platform"}
		return d
	}
	withProduct := func(p *osadminv1.ProductSlots) *osadminv1.GetStatusResponse {
		st := status()
		st.RunningVersion, st.Product = "0.1.0", p
		return st
	}
	failedProduct := withProduct(&osadminv1.ProductSlots{InstalledVersion: "0.1.0-lab.hello.1", StagedVersion: "0.2.0"})
	failedProduct.UpgradeProgress = progress("apply", "0.2.0", "switch", "")
	failedProduct.UpgradeProgress.Target = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
	failedProduct.UpgradeProgress.InProgress, failedProduct.UpgradeProgress.Failed = false, true
	failedProduct.UpgradeProgress.Steps[2].State = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED
	// A bundle refused while it was staged never touched the running
	// product: its line stays OK.
	refused := withProduct(&osadminv1.ProductSlots{InstalledVersion: "0.1.0-lab.hello.1", Running: true})
	refused.UpgradeProgress = progress("stage", "0.2.0", "verify", "")
	refused.UpgradeProgress.Target = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
	refused.UpgradeProgress.InProgress, refused.UpgradeProgress.Failed, refused.UpgradeProgress.Code = false, true, "UPGRADE_SIGNATURE"
	refused.UpgradeProgress.Steps[0].State = osadminv1.UpgradeStepState_UPGRADE_STEP_STATE_FAILED
	baseStaged := withProduct(nil)
	baseStaged.StagedVersion = "0.1.1"
	baseBack := withProduct(nil)
	baseBack.PreviousVersion, baseBack.PreviousSlot = "0.0.9", "B"
	cases := []struct {
		name string
		d    dashboard.Data
		want []string
	}{
		{"no product", noPlatform(withProduct(nil)), []string{"Base          OK      0.1.0 in slot A", "Product       NONE    installed from the admin page, Updates"}},
		{"product staged, none installed", noPlatform(withProduct(&osadminv1.ProductSlots{StagedVersion: "0.2.0"})), []string{"Product       NONE    0.2.0 staged; install it from Updates"}},
		{"installed and running", noPlatform(withProduct(&osadminv1.ProductSlots{InstalledVersion: "0.1.0-lab.hello.1", Running: true})), []string{"Product       OK      0.1.0-lab.hello.1 running"}},
		{"running with an upgrade staged", noPlatform(withProduct(&osadminv1.ProductSlots{InstalledVersion: "0.1.0", StagedVersion: "0.2.0", Running: true})), []string{"Product       OK      0.1.0 running; 0.2.0 staged"}},
		{"running with a way back", noPlatform(withProduct(&osadminv1.ProductSlots{InstalledVersion: "0.2.0", PreviousVersion: "0.1.0", Running: true})), []string{"Product       OK      0.2.0 running; 0.1.0 to go back"}},
		{"installed, stopped", noPlatform(withProduct(&osadminv1.ProductSlots{InstalledVersion: "0.1.0"})), []string{"Product       STOPPED 0.1.0 isn't running"}},
		{"the last product update failed", noPlatform(failedProduct), []string{"Product       FAILED  the update to 0.2.0 failed"}},
		{"a refused bundle leaves the product alone", noPlatform(refused), []string{"Product       OK      0.1.0-lab.hello.1 running"}},
		{"base staged", noPlatform(baseStaged), []string{"Base          OK      0.1.0 in slot A; 0.1.1 staged"}},
		{"base with a way back", noPlatform(baseBack), []string{"Base          OK      0.1.0 in slot A; 0.0.9 to go back"}},
		{"no status", dashboard.Data{Status: sources.StatusView{Err: errors.New("connection refused")}, Slot: "A", PlatformErr: sources.NotInstalled{What: "The platform"}}, []string{"Base          UNKNOWN no status yet", "Product       UNKNOWN no status yet"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			screen := dashboard.Page(chrome(full, keycustody.ModeTPM), c.d, now).Frame(80, 24).Text()
			for _, w := range c.want {
				if !strings.Contains(screen, w) {
					t.Errorf("no %q in\n%s", w, screen)
				}
			}
		})
	}
}

// The disk guard's warnings show on the status view; a critical one (a
// volume 90% full) in the alert colour, a plain one in the warning
// colour.
func TestDiskWarningsShowOnTheStatusView(t *testing.T) {
	st := status()
	st.Warnings = append(st.Warnings,
		&osadminv1.Warning{Kind: osadminv1.WarningKind_WARNING_KIND_DISK_SPACE, Critical: true, Detail: "The state volume is 92% full (58.9 GiB of 64.0 GiB). Free space or grow the disk now."},
		&osadminv1.Warning{Kind: osadminv1.WarningKind_WARNING_KIND_DATA_WAL, Detail: "The database's write-ahead log is 1.5 GiB, over its 1.0 GiB limit."})
	ls := dashboard.Warnings(chrome(full, keycustody.ModeTPM), data(st), now)
	var crit, warn bool
	for _, l := range ls {
		if len(l) < 3 || l[0].Text != "!" {
			continue
		}
		switch {
		case strings.Contains(l.String(), "92% full"):
			crit = l[0].Style == tui.Alert
		case strings.Contains(l.String(), "write-ahead log"):
			warn = l[0].Style == tui.Warn
		}
	}
	if !crit || !warn {
		t.Fatalf("critical in the alert colour %v, plain in the warning colour %v", crit, warn)
	}
}
