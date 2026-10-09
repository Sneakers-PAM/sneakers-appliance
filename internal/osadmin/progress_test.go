// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

func (br *browser) progress(t *testing.T) *osadminv1.UpgradeProgress {
	t.Helper()
	g, err := br.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg.GetUpgradeProgress()
}

func (br *browser) statusProgress(t *testing.T) *osadminv1.UpgradeProgress {
	t.Helper()
	st, err := osadminv1connect.NewStatusServiceClient(br.hc, br.b.ts.URL).GetStatus(context.Background(), connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return st.Msg.GetUpgradeProgress()
}

// publicProgress is what the public GetPhase says, with no session.
func (b *box) publicProgress(t *testing.T) *osadminv1.UpgradeProgress {
	t.Helper()
	p, err := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL).GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return p.Msg.GetUpgradeProgress()
}

// steps writes the steps as "id:state" for comparing.
func steps(p *osadminv1.UpgradeProgress) string {
	var out []string
	for _, s := range p.GetSteps() {
		out = append(out, s.GetId()+":"+strings.TrimPrefix(s.GetState().String(), "UPGRADE_STEP_STATE_"))
	}
	return strings.Join(out, " ")
}

func step(t *testing.T, p *osadminv1.UpgradeProgress, id string) *osadminv1.UpgradeStep {
	t.Helper()
	for _, s := range p.GetSteps() {
		if s.GetId() == id {
			return s
		}
	}
	t.Fatalf("no step %s in %s", id, steps(p))
	return nil
}

func markSetupDone(t *testing.T, b *box) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(b.state, "setup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.state, "setup", osadmin.DoneMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rebootInto is the box after the reboot an apply or revert ends in: a new
// osadmin on the same state, the box running version.
func rebootInto(t *testing.T, from *box, version string) *box {
	t.Helper()
	return rebootIntoBoot(t, from, version, "")
}

// rebootIntoBoot is rebootInto with the new osadmin seeing bootID as the
// kernel's boot ID: the old one when only osadmin restarted.
func rebootIntoBoot(t *testing.T, from *box, version, bootID string) *box {
	t.Helper()
	after := newBox(t, false, func(_ *box, o *osadmin.Options) { o.BootID = bootID })
	b, err := os.ReadFile(filepath.Join(from.state, "osadmin-api", "upgrade-progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(after.state, "osadmin-api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(after.state, "osadmin-api", "upgrade-progress.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	after.init.running = version
	markSetupDone(t, after)
	return after
}

// While a base update stages, Updates and Status name the step it's on,
// with the bytes written into the slot; once staged, verifying and staging
// are done and the rest wait for Apply.
func TestStagingReportsEachStep(t *testing.T) {
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.RootSource = switchroot.LabelRootA })
	alice := b.browser()
	alice.signIn("alice")
	var during *osadminv1.UpgradeProgress
	b.init.duringStage = func() {
		b.init.mu.Lock()
		b.init.written, b.init.total = 512, 2048
		b.init.mu.Unlock()
		during = alice.progress(t)
	}
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if got := steps(during); got != "verify:DONE stage:ACTIVE switch:PENDING reboot:PENDING health:PENDING mark_good:PENDING" {
		t.Fatalf("while staging: %s", got)
	}
	s := step(t, during, "stage")
	if s.GetLabel() != "Staging into slot B" || s.GetDoneBytes() != 512 || s.GetTotalBytes() != 2048 {
		t.Fatalf("the staging step %+v", s)
	}
	if !during.GetInProgress() || during.GetVersion() != "0.2.0" || during.GetAction() != "stage" {
		t.Fatalf("while staging %+v", during)
	}
	if step(t, during, "verify").GetLabel() != "Verifying (signature, channel, SHA-256)" {
		t.Fatalf("the verify step %+v", step(t, during, "verify"))
	}
	after := alice.progress(t)
	if got := steps(after); got != "verify:DONE stage:DONE switch:PENDING reboot:PENDING health:PENDING mark_good:PENDING" {
		t.Fatalf("after the stage: %s", got)
	}
	if after.GetInProgress() || after.GetFailed() {
		t.Fatalf("after the stage %+v", after)
	}
	if got := steps(alice.statusProgress(t)); got != steps(after) {
		t.Fatalf("Status says %s, Updates %s", got, steps(after))
	}
}

// A refused file fails at verifying, and a stage init refuses fails at
// staging, each saying why.
func TestAFailedStageSaysWhichStepAndWhy(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, bin(t, testpki.ECDSA(t), b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err == nil {
		t.Fatal("a file signed by another key staged")
	}
	p := alice.progress(t)
	if got := steps(p); got != "verify:FAILED stage:PENDING switch:PENDING reboot:PENDING health:PENDING mark_good:PENDING" {
		t.Fatalf("a refused signature: %s", got)
	}
	if !p.GetFailed() || p.GetInProgress() || p.GetCode() != "UPGRADE_SIGNATURE" || step(t, p, "verify").GetDetail() == "" {
		t.Fatalf("a refused signature %+v", p)
	}

	// init sends a coded refusal as its description, as initapi does.
	b.init.stageErr = connect.NewError(connect.CodeFailedPrecondition, errors.New(codes.Describe(codes.New(codes.UpgradeUnpredictable, "PCR 4 can't be predicted"))))
	id, _ = alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err == nil {
		t.Fatal("init refused the stage, but it staged")
	}
	p = alice.progress(t)
	if got := steps(p); got != "verify:DONE stage:FAILED switch:PENDING reboot:PENDING health:PENDING mark_good:PENDING" {
		t.Fatalf("init refused: %s", got)
	}
	if p.GetCode() != "UPGRADE_UNPREDICTABLE" || !strings.Contains(step(t, p, "stage").GetDetail(), "PCR 4") {
		t.Fatalf("init refused %+v", p)
	}
}

// Apply goes on from the stage: switching, then rebooting, which holds
// until the box comes back. The public GetPhase carries the steps for the
// restart page, without the version or any detail.
func TestApplyReportsSwitchingThenRebooting(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	var during *osadminv1.UpgradeProgress
	b.init.duringActivate = func() { during = alice.progress(t) }
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if got := steps(during); got != "verify:DONE stage:DONE switch:ACTIVE reboot:PENDING health:PENDING mark_good:PENDING" {
		t.Fatalf("while switching: %s", got)
	}
	p := alice.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE reboot:ACTIVE health:PENDING mark_good:PENDING" {
		t.Fatalf("after the apply: %s", got)
	}
	if !p.GetInProgress() || p.GetAction() != "apply" || p.GetVersion() != "0.2.0" {
		t.Fatalf("after the apply %+v", p)
	}
	pub := b.publicProgress(t)
	if steps(pub) != steps(p) || !pub.GetInProgress() {
		t.Fatalf("GetPhase says %s, Updates %s", steps(pub), steps(p))
	}
	if pub.GetVersion() != "" || pub.GetCode() != "" || pub.GetStartedAt() != nil {
		t.Fatalf("GetPhase gives away more than the steps: %+v", pub)
	}
	for _, s := range pub.GetSteps() {
		if s.GetDetail() != "" {
			t.Fatalf("GetPhase gives a step's detail: %+v", s)
		}
	}
}

// An apply init refuses fails at switching; a reboot that's refused fails
// at rebooting.
func TestAFailedApplySaysWhichStep(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		set        func(*fakeInit)
	}{
		{"activate", "verify:DONE stage:DONE switch:FAILED reboot:PENDING health:PENDING mark_good:PENDING", func(f *fakeInit) {
			f.activateErr = connect.NewError(connect.CodeFailedPrecondition, errors.New(codes.Describe(codes.New(codes.UpgradeNotStaged, "no release is staged"))))
		}},
		{"reboot", "verify:DONE stage:DONE switch:DONE reboot:FAILED health:PENDING mark_good:PENDING", func(f *fakeInit) {
			f.rebootErr = connect.NewError(connect.CodeUnavailable, errors.New("init is shutting down"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBox(t, false)
			alice := b.browser()
			alice.signIn("alice")
			id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
			if err := stage(alice, id); err != nil {
				t.Fatal(err)
			}
			tc.set(b.init)
			if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err == nil {
				t.Fatal("the apply went through")
			}
			p := alice.progress(t)
			if got := steps(p); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if !p.GetFailed() || p.GetInProgress() {
				t.Fatalf("%+v", p)
			}
		})
	}
}

// After the reboot the booted release's MarkGood loop carries the steps
// on: checking health while it waits for the box to be healthy, marking
// good, then done.
func TestTheBootedReleaseFinishesTheSteps(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	after := rebootInto(t, b, "0.2.0")
	ctx := context.Background()
	if got := steps(after.publicProgress(t)); got != "verify:DONE stage:DONE switch:DONE reboot:ACTIVE health:PENDING mark_good:PENDING" {
		t.Fatalf("before MarkGood runs: %s", got)
	}
	after.netd.down = true
	if err := after.srv.MarkGood(ctx); err == nil {
		t.Fatal("marked good with netd down")
	}
	owner := after.browser()
	owner.signIn("alice")
	p := owner.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE reboot:DONE health:ACTIVE mark_good:PENDING" {
		t.Fatalf("netd down: %s", got)
	}
	if !p.GetInProgress() || !strings.Contains(step(t, p, "health").GetDetail(), "netd") {
		t.Fatalf("netd down %+v", p)
	}
	after.netd.down = false
	after.init.markGoodErr = connect.NewError(connect.CodeInternal, errors.New("the ESP is read-only"))
	if err := after.srv.MarkGood(ctx); err == nil {
		t.Fatal("MarkGood failed in init, but succeeded")
	}
	p = owner.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE reboot:DONE health:DONE mark_good:ACTIVE" {
		t.Fatalf("init's MarkGood failed: %s", got)
	}
	if !p.GetInProgress() || !strings.Contains(step(t, p, "mark_good").GetDetail(), "read-only") {
		t.Fatalf("init's MarkGood failed %+v", p)
	}
	after.init.markGoodErr = nil
	if err := after.srv.MarkGood(ctx); err != nil {
		t.Fatal(err)
	}
	p = owner.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE reboot:DONE health:DONE mark_good:DONE" {
		t.Fatalf("marked good: %s", got)
	}
	if p.GetInProgress() || p.GetFailed() {
		t.Fatalf("marked good %+v", p)
	}
}

// A release the box didn't come up healthy on fails at checking health,
// naming both releases; the fallback itself is boot counting's, as before.
func TestABootThatFellBackSaysSo(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	after := rebootInto(t, b, "0.1.0")
	after.init.failedVer = "0.2.0"
	if err := after.srv.MarkGood(context.Background()); err != nil {
		t.Fatal(err)
	}
	if after.init.markedGood != 1 {
		t.Fatal("the release the box fell back to is marked good as before")
	}
	owner := after.browser()
	owner.signIn("alice")
	p := owner.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE reboot:DONE health:FAILED mark_good:PENDING" {
		t.Fatalf("fell back: %s", got)
	}
	d := step(t, p, "health").GetDetail()
	if !p.GetFailed() || p.GetInProgress() || !strings.Contains(d, "0.2.0") || !strings.Contains(d, "0.1.0") {
		t.Fatalf("fell back %+v", p)
	}
}

// A revert has no file to verify or stage: switching back, rebooting,
// then the same checks on the release it went back to.
func TestARevertReportsItsSteps(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	b.init.previousVer = "0.0.9"
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	p := alice.progress(t)
	if got := steps(p); got != "switch:DONE reboot:ACTIVE health:PENDING mark_good:PENDING" {
		t.Fatalf("after the revert: %s", got)
	}
	if p.GetAction() != "revert" || p.GetVersion() != "0.0.9" || !p.GetInProgress() {
		t.Fatalf("after the revert %+v", p)
	}
	after := rebootInto(t, b, "0.0.9")
	if err := after.srv.MarkGood(context.Background()); err != nil {
		t.Fatal(err)
	}
	owner := after.browser()
	owner.signIn("alice")
	if got := steps(owner.progress(t)); got != "switch:DONE reboot:DONE health:DONE mark_good:DONE" {
		t.Fatalf("back on 0.0.9: %s", got)
	}
}

// A stage osadmin didn't live to finish (accessd restarted under it)
// isn't left in progress for ever.
func TestAStageCutOffByARestartFails(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	var after *box
	b.init.duringStage = func() { after = rebootInto(t, b, "0.1.0") }
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	owner := after.browser()
	owner.signIn("alice")
	p := owner.progress(t)
	if got := steps(p); got != "verify:DONE stage:FAILED switch:PENDING reboot:PENDING health:PENDING mark_good:PENDING" {
		t.Fatalf("cut off: %s", got)
	}
	if p.GetInProgress() || !p.GetFailed() {
		t.Fatalf("cut off %+v", p)
	}
}

// A product bundle has no reboot: verifying, staging, switching and
// restarting the product, all done once the apply answers.
func TestAProductUpdateReportsItsSteps(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	p := alice.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:PENDING restart:PENDING" {
		t.Fatalf("staged: %s", got)
	}
	if p.GetTarget() != product || p.GetVersion() != "0.2.0" {
		t.Fatalf("staged %+v", p)
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	p = alice.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE restart:DONE" {
		t.Fatalf("applied: %s", got)
	}
	if p.GetInProgress() || p.GetFailed() || p.GetAction() != "apply" {
		t.Fatalf("applied %+v", p)
	}
}

// applyWithBootID stages and applies on a box whose boot ID is bootID,
// leaving the reboot step active.
func applyWithBootID(t *testing.T, bootID string) (*box, *browser) {
	t.Helper()
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.BootID = bootID })
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	return b, alice
}

// An apply whose reboot never comes, the box still on the same boot, fails
// at rebooting once RebootBound has passed: the console and Updates leave
// the maintenance state, the failure is audited, and maintenance ends.
func TestARebootThatNeverComesFails(t *testing.T) {
	b, alice := applyWithBootID(t, "boot-1")
	b.clk.Advance(osadmin.RebootBound - time.Minute)
	b.srv.RebootWatchdog()
	if got := steps(alice.progress(t)); got != "verify:DONE stage:DONE switch:DONE reboot:ACTIVE health:PENDING mark_good:PENDING" {
		t.Fatalf("within the bound: %s", got)
	}
	if !b.srv.Maintenance() {
		t.Fatal("maintenance ended within the bound")
	}
	b.clk.Advance(2 * time.Minute)
	b.srv.RebootWatchdog()
	p := alice.progress(t)
	if got := steps(p); got != "verify:DONE stage:DONE switch:DONE reboot:FAILED health:PENDING mark_good:PENDING" {
		t.Fatalf("past the bound: %s", got)
	}
	if p.GetInProgress() || !p.GetFailed() || p.GetCode() != "UPGRADE_NO_REBOOT" {
		t.Fatalf("past the bound %+v", p)
	}
	if d := step(t, p, "reboot").GetDetail(); !strings.Contains(d, "didn't reboot into 0.2.0") {
		t.Fatalf("the reboot step's detail %q", d)
	}
	if pub := b.publicProgress(t); pub.GetInProgress() || !pub.GetFailed() {
		t.Fatalf("GetPhase still says in progress: %+v", pub)
	}
	if b.srv.Maintenance() {
		t.Fatal("maintenance holds after the reboot was given up on")
	}
	e := lastEntry(t, b.log, "upgrade.reboot-missed")
	if e.Code != "UPGRADE_NO_REBOOT" || e.Detail["version"] != "0.2.0" || e.Detail["waited"] == "" {
		t.Fatalf("audit %+v", e)
	}
	// A second tick changes nothing.
	b.srv.RebootWatchdog()
	if n := countEntries(t, b, "upgrade.reboot-missed"); n != 1 {
		t.Fatalf("%d reboot-missed entries", n)
	}
	g, err := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	h := g.Msg.GetHistory()
	if len(h) == 0 || h[0].GetCode() != "UPGRADE_NO_REBOOT" {
		t.Fatalf("history %+v", h)
	}
}

func countEntries(t *testing.T, b *box, action string) int {
	t.Helper()
	es, err := b.log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range es {
		if e.Action == action {
			n++
		}
	}
	return n
}

// The reboot came (a new boot ID): the watchdog leaves the steps to the
// booted release, however long the box took.
func TestTheWatchdogLeavesARebootThatCameAlone(t *testing.T) {
	b, _ := applyWithBootID(t, "boot-1")
	after := rebootIntoBoot(t, b, "0.2.0", "boot-2")
	after.clk.Advance(osadmin.RebootBound + time.Hour)
	after.srv.RebootWatchdog()
	if err := after.srv.MarkGood(context.Background()); err != nil {
		t.Fatal(err)
	}
	owner := after.browser()
	owner.signIn("alice")
	if got := steps(owner.progress(t)); got != "verify:DONE stage:DONE switch:DONE reboot:DONE health:DONE mark_good:DONE" {
		t.Fatalf("after the reboot: %s", got)
	}
}

// osadmin restarting on the same boot isn't the reboot: MarkGood doesn't
// read the old release as a fallback, and the watchdog still waits.
func TestAnOsadminRestartIsNotTheReboot(t *testing.T) {
	b, _ := applyWithBootID(t, "boot-1")
	again := rebootIntoBoot(t, b, "0.1.0", "boot-1")
	if err := again.srv.MarkGood(context.Background()); err != nil {
		t.Fatal(err)
	}
	owner := again.browser()
	owner.signIn("alice")
	if got := steps(owner.progress(t)); got != "verify:DONE stage:DONE switch:DONE reboot:ACTIVE health:PENDING mark_good:PENDING" {
		t.Fatalf("after osadmin restarted: %s", got)
	}
	again.clk.Advance(osadmin.RebootBound + time.Minute)
	again.srv.RebootWatchdog()
	if got := steps(owner.progress(t)); got != "verify:DONE stage:DONE switch:DONE reboot:FAILED health:PENDING mark_good:PENDING" {
		t.Fatalf("past the bound: %s", got)
	}
}

// savingClock reads the progress record each time osadmin asks the time:
// osadmin stamps the record before every save, so the reads see each
// record a poll of GetUpgrades could have seen.
type savingClock struct {
	*clock.Fake
	file  string
	mu    sync.Mutex
	saved []string
}

func (c *savingClock) Now() time.Time {
	if b, err := os.ReadFile(c.file); err == nil {
		var r struct {
			Target string `json:"target"`
			Steps  []struct {
				ID string `json:"id"`
			} `json:"steps"`
		}
		if json.Unmarshal(b, &r) == nil {
			var ids []string
			for _, s := range r.Steps {
				ids = append(ids, s.ID)
			}
			c.mu.Lock()
			if rec := r.Target + ": " + strings.Join(ids, " "); len(c.saved) == 0 || c.saved[len(c.saved)-1] != rec {
				c.saved = append(c.saved, rec)
			}
			c.mu.Unlock()
		}
	}
	return c.Fake.Now()
}

// A product stage never shows a base update's steps: until the file's
// header is read, the record has the verify step alone.
func TestAProductStageNeverReportsBaseSteps(t *testing.T) {
	var clk *savingClock
	b := newBox(t, false, func(b *box, o *osadmin.Options) {
		clk = &savingClock{Fake: b.clk, file: filepath.Join(b.state, "osadmin-api", "upgrade-progress.json")}
		o.Clock = clk
	})
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	clk.Now()
	clk.mu.Lock()
	saved := append([]string(nil), clk.saved...)
	clk.mu.Unlock()
	if len(saved) == 0 || saved[0] != ": verify" {
		t.Fatalf("the stage's first record %q", saved)
	}
	for _, rec := range saved {
		for _, base := range []string{"reboot", "health", "mark_good"} {
			if strings.Contains(rec, base) {
				t.Fatalf("a product stage reported base steps: %q", saved)
			}
		}
	}
	if got := saved[len(saved)-1]; got != "product: verify stage switch restart" {
		t.Fatalf("the stage's last record %q", got)
	}
}
