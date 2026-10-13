// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// The real-bundle job (docs/testing.md#the-real-bundle-job,
// .github/workflows/real-bundle.yml): the real Sneakers product, not the
// lab stand-ins, through the update paths a box on the field takes.
// build/realci/build.sh builds the pieces and writes the environment
// these tests read; without it they skip.

// realEnv is what build/realci/build.sh wrote.
type realEnv struct {
	keys, oldImage, oldVersion, newBase, newVersion string
	p12, p13, next                                  string
}

func needReal(t *testing.T) realEnv {
	t.Helper()
	e := realEnv{
		keys: os.Getenv("SNEAKERS_KEYS"), oldImage: os.Getenv("SNEAKERS_REAL_OLD_IMAGE"), oldVersion: os.Getenv("SNEAKERS_REAL_OLD_VERSION"),
		newBase: os.Getenv("SNEAKERS_REAL_NEW_BASE"), newVersion: os.Getenv("SNEAKERS_REAL_NEW_VERSION"),
		p12: os.Getenv("SNEAKERS_REAL_P12"), p13: os.Getenv("SNEAKERS_REAL_P13"), next: os.Getenv("SNEAKERS_REAL_NEXT"),
	}
	// The image workflow builds no real product, so the tests skip there.
	if e.oldImage == "" || e.newBase == "" || e.p12 == "" || e.p13 == "" || e.next == "" {
		t.Skip("SNEAKERS_REAL_* name the real-bundle job's builds (build/realci/build.sh)")
	}
	harness.Need(t, []string{"mcopy", "ssh", "ssh-keygen"}, e.keys, e.oldImage, e.newBase, e.p12, e.p13, e.next)
	return e
}

// productVersion is a real product bundle's version, from its build's
// name (build/realci/build.sh): product-12.bin is 0.1.0-lab.realci.12,
// product-next.bin (the product under test) 0.1.0-lab.realci.next.
func productVersion(file string) string {
	return "0.1.0-lab.realci." + strings.TrimSuffix(strings.TrimPrefix(filepath.Base(file), "product-"), ".bin")
}

// realBox is one box through the whole test: each boot takes the last
// one's disk.
type realBox struct {
	t                      *testing.T
	ctx                    context.Context
	keys                   string
	sshPort, adminPort, hp int
	alice                  *lab
	vm                     *harness.VM
	boots                  int
	// memMiB is the VM's memory; 0 is 8 GiB.
	memMiB int
}

func (b *realBox) opts(img string) harness.Options {
	mem := b.memMiB
	if mem == 0 {
		mem = 8192
	}
	return harness.Options{SecureBoot: harness.OffWithKeys, Keys: b.keys, MemMiB: mem, CPUs: 4,
		Disks: []harness.Disk{{Image: img, Move: true}}, Timeout: 5 * time.Hour,
		HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", b.sshPort), fmt.Sprintf("tcp:127.0.0.1:%d-:8443", b.adminPort), fmt.Sprintf("tcp:127.0.0.1:%d-:443", b.hp)}}
}

// keepConsole writes the boot's serial console where the job collects its
// logs (SNEAKERS_LOG_DIR), when it names one.
func (b *realBox) keepConsole(vm *harness.VM) {
	dir := os.Getenv("SNEAKERS_LOG_DIR")
	if dir == "" {
		return
	}
	n := b.boots
	b.t.Cleanup(func() {
		name := fmt.Sprintf("%s-boot%d.log", strings.ReplaceAll(b.t.Name(), "/", "-"), n)
		_ = os.WriteFile(filepath.Join(dir, name), []byte(vm.Console()), 0o600) // #nosec G703 -- the job's own log directory
	})
}

func (b *realBox) boot(img string) {
	b.t.Helper()
	b.boots++
	b.vm = harness.Boot(b.t, b.opts(img))
	b.keepConsole(b.vm)
}

// newRealBox installs the old base from its raw disk, with the lab hook's
// marker on the ESP, and sets it up.
func newRealBox(t *testing.T, e realEnv) *realBox {
	t.Helper()
	return newRealBoxFrom(t, e, e.oldImage, e.oldVersion, 0)
}

// newRealBoxFrom installs the base on the raw disk img (its version
// version), with the lab hook's marker on the ESP, in a VM of memMiB (0 is
// 8 GiB), and sets it up.
func newRealBoxFrom(t *testing.T, e realEnv, img, version string, memMiB int) *realBox {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Hour)
	t.Cleanup(cancel)
	b := &realBox{t: t, ctx: ctx, keys: e.keys, sshPort: freePort(t), adminPort: freePort(t), hp: freePort(t), memMiB: memMiB}
	marked := filepath.Join(t.TempDir(), "marked.raw")
	if out, err := exec.Command("cp", "--sparse=always", img, marked).CombinedOutput(); err != nil { // #nosec G204 -- test-only, fixed tool
		t.Fatalf("cp: %v: %s", err, out)
	}
	marker := filepath.Join(t.TempDir(), "lab-hook")
	if err := os.WriteFile(marker, []byte("real-bundle job\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	esp := fmt.Sprintf("%s@@%d", marked, disk.Installed()[0].Start)
	if out, err := exec.Command("mcopy", "-i", esp, marker, "::/lab-hook").CombinedOutput(); err != nil { // #nosec G204 -- as above
		t.Fatalf("mcopy: %v: %s", err, out)
	}
	b.boot(marked)
	b.alice = firstBoot(t, b.vm, b.adminPort)
	b.vm.WaitExit(5 * time.Minute)
	b.boot(b.vm.Disk(0))
	b.vm.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	b.vm.Expect(regexp.QuoteMeta(version), 5*time.Minute)
	return b
}

// apply uploads, stages and applies an update .bin for target.
func (b *realBox) apply(file, target string) {
	b.t.Helper()
	adm := signIn(b.t, b.adminPort, b.alice)
	var staged struct {
		Package struct {
			Version string `json:"version"`
			Target  string `json:"target"`
		} `json:"package"`
	}
	adm.call(b.t, "UpgradeService/StageUpdate", map[string]any{"uploadId": adm.upload(b.t, file)}, &staged)
	if staged.Package.Target != target {
		b.t.Fatalf("%s staged as %+v; want %s", filepath.Base(file), staged.Package, target)
	}
	adm.call(b.t, "UpgradeService/ApplyUpdate", map[string]any{"target": target, "totpCode": b.alice.code()}, &struct{}{})
	b.t.Logf("applied %s (%s %s)", filepath.Base(file), target, staged.Package.Version)
}

// updateBase applies the base update and boots it.
func (b *realBox) updateBase(file, version string) {
	b.t.Helper()
	b.apply(file, "UPDATE_TARGET_BASE")
	b.vm.WaitExit(10 * time.Minute)
	b.boot(b.vm.Disk(0))
	b.vm.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	b.vm.Expect(regexp.QuoteMeta(version), 5*time.Minute)
}

// powerLoss kills QEMU, as a power cut would, and boots the box again.
func (b *realBox) powerLoss() {
	b.t.Helper()
	b.vm.Stop()
	b.boot(b.vm.Disk(0))
	b.vm.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
}

// mcpOn turns the product's MCP switch on over SSH, as an admin does;
// the box answers once the product is ready with it.
func (b *realBox) mcpOn() {
	b.t.Helper()
	ctx, cancel := context.WithTimeout(b.ctx, 20*time.Minute)
	defer cancel()
	out, err := ssh(ctx, b.sshPort, b.alice, "sneakers", "mcp", "on")
	if err != nil || !strings.Contains(out, "MCP is on") {
		b.t.Fatalf("sneakers mcp on: %v: %s", err, out)
	}
	b.t.Logf("sneakers mcp on: %s", strings.TrimSpace(out))
}

// report is the lab hook's report on a product version the box runs.
type report struct {
	rows realRows
	pods []realPod
}

// waitReport waits for the lab hook's report on version, the box running
// it. On a timeout it answers false with the hook's last lines from while
// the box didn't run.
func (b *realBox) waitReport(version string, timeout time.Duration) (report, bool) {
	b.t.Helper()
	done := regexp.MustCompile(`realci: report version=` + regexp.QuoteMeta(version) + `\s`)
	failed := regexp.MustCompile(`realci: waiting version=` + regexp.QuoteMeta(version) + ` state=failed\b`)
	deadline := time.Now().Add(timeout)
	for {
		c := b.vm.Console()
		if done.MatchString(c) {
			break
		}
		// The box gave the product up: three reports in a row (fifteen
		// minutes) say failed, so waiting longer shows nothing new.
		if n := len(failed.FindAllString(c, -1)); n >= failedReports && strings.HasSuffix(strings.TrimSpace(lastWaiting(c)), "state=failed") {
			return report{}, false
		}
		if time.Now().After(deadline) {
			return report{}, false
		}
		time.Sleep(5 * time.Second)
	}
	console := b.vm.Console()
	rows := lastLine(console, "realci: rows running version="+version+" ")
	pods := lastLine(console, "realci: pods running version="+version+": ")
	var r report
	var err error
	if r.rows, err = readRealRows(rows); err != nil {
		b.t.Fatalf("%s: %v", version, err)
	}
	if r.pods, err = readRealPods(pods); err != nil {
		b.t.Fatalf("%s: %v", version, err)
	}
	return r, true
}

// failedReports is how many of the hook's failed states in a row end a
// wait early.
const failedReports = 3

// lastWaiting is the hook's last waiting line.
func lastWaiting(console string) string { return lastLine(console, "realci: waiting ") }

// waiting is the hook's last lines from while the box didn't run: the
// state, the pods, each pod's last wait-phase lines and the rows.
func (b *realBox) waiting() string {
	c := b.vm.Console()
	var out []string
	for _, p := range []string{`realci: waiting `, `realci: pods waiting `} {
		if l := lastLine(c, p); l != "" {
			out = append(out, l)
		}
	}
	out = append(out, waitPhaseLines(c)...)
	out = append(out, crashLines(c)...)
	if l := lastLine(c, `realci: rows waiting `); l != "" {
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

var crashLine = regexp.MustCompile(`realci: crash (\S+): [^\r\n]*`)

// crashLines is the last crash line the hook printed for each container.
func crashLines(console string) []string {
	last := map[string]string{}
	for _, m := range crashLine.FindAllStringSubmatch(console, -1) {
		last[m[1]] = m[0]
	}
	var out []string
	for _, l := range last {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

var waitPhaseLine = regexp.MustCompile(`realci: wait-phase (\S+): [^\r\n]*`)

// waitPhaseLines is the last wait-phase line the hook printed for each
// pod, in pod order.
func waitPhaseLines(console string) []string {
	last := map[string]string{}
	for _, m := range waitPhaseLine.FindAllStringSubmatch(console, -1) {
		last[m[1]] = m[0]
	}
	var out []string
	for _, l := range last {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// mustRun waits for the box to run version and checks the report: every
// phase in order with no restarts when phased, the MCP server running
// when the switch is on, and every row of base still there.
func (b *realBox) mustRun(version, when string, base realRows, phased, mcp bool) report {
	b.t.Helper()
	r, ok := b.waitReport(version, 45*time.Minute)
	if !ok {
		why := ""
		if pods, err := readRealPods(lastLine(b.vm.Console(), `realci: pods waiting `)); err == nil {
			why = strings.Join(phaseProblems(pods, phased), "\n")
		}
		b.t.Fatalf("%s: the box never ran %s within 45m (stuck):\n%s\nthe lab hook's last lines:\n%s", when, version, why, b.waiting())
	}
	problems := append(phaseProblems(r.pods, phased), rowProblems(base, r.rows)...)
	// A first start after the install is a new data directory: the
	// database the box had is gone.
	if len(base.dbs) > 0 && r.rows.start == "first" {
		problems = append(problems, "PostgreSQL started on a new data directory (initdb ran again)")
	}
	if mcp && !runningApp(r.pods, "sneakers-mcp") {
		problems = append(problems, "the MCP switch is on, but no sneakers-mcp pod runs")
	}
	if len(problems) > 0 {
		b.t.Fatalf("%s:\n%s", when, strings.Join(problems, "\n"))
	}
	b.t.Logf("%s: %s runs, %d pods, PostgreSQL start %s, rows %s", when, version, len(r.pods), r.rows.start, r.rows.summary())
	return r
}

// TestTheRealBundlesUpdateInOrder is a box on the field's path to the
// release: the old base (n6) with the real product without phases (.12)
// and the MCP switch on, the base updated to the one under test, then the
// product to the one under test (with phases), then a power loss. After
// each step the box runs the product with its phases up in order (data,
// identity, services, front), no pod restarted, and every row written at
// the start still there. (.13, the first product with phases, can't come
// up on any base: its data phase's wait fails. The recover test runs it.)
func TestTheRealBundlesUpdateInOrder(t *testing.T) {
	e := needReal(t)
	b := newRealBox(t, e)
	v12, vNext := productVersion(e.p12), productVersion(e.next)

	b.apply(e.p12, "UPDATE_TARGET_PRODUCT")
	first := b.mustRun(v12, "the install of "+v12, realRows{}, false, false)
	base := first.rows
	if p := canaryProblems(base); len(p) > 0 {
		t.Fatalf("the rows weren't written: %v", p)
	}
	b.mcpOn()

	b.updateBase(e.newBase, e.newVersion)
	b.mustRun(v12, "the base update to "+e.newVersion, base, false, true)

	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	before := b.mustRun(vNext, "the update to phases ("+v12+" to "+vNext+")", base, true, true)

	b.powerLoss()
	after := b.mustRun(vNext, "after a power loss", base, true, true)
	// Without it, a layer unpacked just before the cut can come back with
	// empty files: "exec format error" at each start of its container.
	if m := lastLine(b.vm.Console(), "realci: state mount "); !strings.Contains(m, "nodelalloc") {
		t.Fatalf("after a power loss: the state volume isn't mounted nodelalloc: %q", m)
	}
	if kept := podsKeptInPlace(before.pods, after.pods); len(kept) > 0 {
		t.Fatalf("after a power loss: %v are the pods from before it, restarted in place, not quiesced", kept)
	}
}

// TestTheRealBundlesRecoverFromAStuckUpdate starts where a box on the old
// base is left by the update to phases: the old base (n6) running the
// product without phases (.12) with the MCP switch on, then given .13,
// which that base doesn't bring up (its quiesce leaves .12's MCP server
// and Hydra running). The base under test is applied in that state, and
// whether it brings .13 up by itself is recorded; then the product under
// test must run with its phases in order and every row.
// The test says what the stuck state did to the rows, with the hook's
// lines.
func TestTheRealBundlesRecoverFromAStuckUpdate(t *testing.T) {
	e := needReal(t)
	b := newRealBox(t, e)
	v12, v13, vNext := productVersion(e.p12), productVersion(e.p13), productVersion(e.next)

	b.apply(e.p12, "UPDATE_TARGET_PRODUCT")
	base := b.mustRun(v12, "the install of "+v12, realRows{}, false, false).rows
	if p := canaryProblems(base); len(p) > 0 {
		t.Fatalf("the rows weren't written: %v", p)
	}
	b.mcpOn()

	b.apply(e.p13, "UPDATE_TARGET_PRODUCT")
	if r, ok := b.waitReport(v13, 30*time.Minute); ok {
		t.Logf("the old base ran %s within 30m, not stuck this time (%d pods, rows %s)", v13, len(r.pods), r.rows.summary())
	} else {
		t.Logf("the old base is stuck on %s, as a box on the field was; the lab hook's last lines:\n%s", v13, b.waiting())
		if l := lastLine(b.vm.Console(), `realci: rows waiting `); l != "" {
			if stuck, err := readRealRows(l); err == nil {
				switch p := rowProblems(base, stuck); {
				case len(p) == 0:
					t.Logf("in the stuck state every row is still there: %s", stuck.summary())
				case uncounted(stuck):
					t.Logf("in the stuck state PostgreSQL doesn't answer, so no row can be counted (its data directory isn't read): %s", l)
				default:
					t.Logf("in the stuck state the rows are already short:\n%s", strings.Join(p, "\n"))
				}
			}
		}
	}

	// The base under test is applied in that state. Whether it brings .13
	// up by itself is recorded; the box must then take the product under
	// test and run it with every check.
	b.updateBase(e.newBase, e.newVersion)
	if r, ok := b.waitReport(v13, 20*time.Minute); ok {
		problems := append(phaseProblems(r.pods, true), rowProblems(base, r.rows)...)
		t.Logf("on %s the box ran %s again (%d pods, rows %s); problems: %v", e.newVersion, v13, len(r.pods), r.rows.summary(), problems)
	} else {
		why := ""
		if pods, err := readRealPods(lastLine(b.vm.Console(), `realci: pods waiting `)); err == nil {
			why = strings.Join(phaseProblems(pods, true), "\n")
		}
		t.Logf("on %s the box is still stuck on %s after 20m:\n%s\nthe lab hook's last lines:\n%s", e.newVersion, v13, why, b.waiting())
	}

	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	b.mustRun(vNext, "the update to "+vNext+" from the stuck state", base, true, true)
}

// lastLine is the last console line that holds prefix, from it to the
// line's end.
func lastLine(console, prefix string) string {
	i := strings.LastIndex(console, prefix)
	if i < 0 {
		return ""
	}
	line := console[i:]
	if j := strings.IndexAny(line, "\r\n"); j >= 0 {
		line = line[:j]
	}
	return line
}

// realRows is the hook's rows line: each database's tables and their
// rows (nil for a database it couldn't count), and how PostgreSQL's
// current start began.
type realRows struct {
	version, start string
	dbs            map[string]map[string]int
}

var (
	realRowsHead = regexp.MustCompile(`realci: rows \w+ version=(\S+) start=(\S+)`)
	realRowsDB   = regexp.MustCompile(`(\w+)\[([^\]]*)\]`)
)

func readRealRows(line string) (realRows, error) {
	m := realRowsHead.FindStringSubmatch(line)
	if m == nil {
		return realRows{}, fmt.Errorf("no rows line: %q", line)
	}
	r := realRows{version: m[1], start: m[2], dbs: map[string]map[string]int{}}
	for _, d := range realRowsDB.FindAllStringSubmatch(line[len(m[0]):], -1) {
		if d[2] == "missing" {
			r.dbs[d[1]] = nil
			continue
		}
		tables := map[string]int{}
		for _, kv := range strings.Split(d[2], ",") {
			name, n, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			c, err := strconv.Atoi(n)
			if err != nil {
				return realRows{}, fmt.Errorf("%s.%s: %q isn't a count", d[1], name, n)
			}
			tables[name] = c
		}
		r.dbs[d[1]] = tables
	}
	return r, nil
}

// summary is each database's canary rows and its total.
func (r realRows) summary() string {
	var out []string
	for db, tables := range r.dbs {
		total := 0
		for _, n := range tables {
			total += n
		}
		out = append(out, fmt.Sprintf("%s=%d/%d", db, tables["realci_rows"], total))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// uncounted says no database could be counted: PostgreSQL didn't answer.
func uncounted(r realRows) bool {
	for _, tables := range r.dbs {
		if tables != nil {
			return false
		}
	}
	return true
}

// canaryRows is how many rows the lab hook writes into each database.
const canaryRows = 1000

func canaryProblems(r realRows) []string {
	var out []string
	if len(r.dbs) == 0 {
		return []string{"no database was counted"}
	}
	for db, tables := range r.dbs {
		if tables["realci_rows"] != canaryRows {
			out = append(out, fmt.Sprintf("%s holds %d of the %d rows the hook wrote", db, tables["realci_rows"], canaryRows))
		}
	}
	sort.Strings(out)
	return out
}

// rowProblems compares a later count with the first: every database still
// counts, every canary row is there, and every table that held rows
// still holds as many or more (the product only adds rows as it runs).
func rowProblems(base, now realRows) []string {
	var out []string
	for db, tables := range base.dbs {
		got, ok := now.dbs[db]
		if !ok || got == nil {
			out = append(out, fmt.Sprintf("%s can't be counted any more (it had %d tables)", db, len(tables)))
			continue
		}
		for name, n := range tables {
			m, ok := got[name]
			switch {
			case !ok:
				out = append(out, fmt.Sprintf("%s.%s is gone (it had %d rows)", db, name, n))
			case name == "realci_rows" && m != n:
				out = append(out, fmt.Sprintf("%s.%s has %d rows, not %d", db, name, m, n))
			case m < n:
				out = append(out, fmt.Sprintf("%s.%s has %d rows, fewer than %d", db, name, m, n))
			}
		}
	}
	sort.Strings(out)
	return out
}

// realPod is one pod in the hook's pods line.
type realPod struct {
	name, app, phase string
	order            int
	restarts         []int
	init             []initStatus
	// waiting is why its containers wait (PodInitializing, CrashLoopBackOff
	// and the like), space-separated; empty when none does.
	waiting string
	started time.Time
	ready   bool
	readyAt time.Time
}

// initStatus is one init container: its restarts and how it ended
// (Completed) or why it waits.
type initStatus struct {
	name, state string
	restarts    int
}

var realPodsHead = regexp.MustCompile(`realci: pods \w+ version=\S+: (.*)$`)

var realPodRE = regexp.MustCompile(`^(\S+) app=(\S*) order=(\d*) phase=(\S*) restarts=([\d ]*) init=\[([^\]]*)\] waiting=([\w ]*) started=(\S*) ready=(\w*)@(\S*)$`)

func readRealPods(line string) ([]realPod, error) {
	m := realPodsHead.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("no pods line: %q", line)
	}
	list := m[1]
	var out []realPod
	for _, item := range strings.Split(list, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		m := realPodRE.FindStringSubmatch(item)
		if m == nil {
			return nil, fmt.Errorf("%q doesn't read", item)
		}
		p := realPod{name: m[1], app: m[2], phase: m[4], waiting: strings.TrimSpace(m[7]), ready: m[9] == "True"}
		if m[3] != "" {
			p.order, _ = strconv.Atoi(m[3])
		}
		for _, f := range strings.Fields(m[5]) {
			n, _ := strconv.Atoi(f)
			p.restarts = append(p.restarts, n)
		}
		for _, c := range strings.Split(m[6], ",") {
			f := strings.SplitN(c, "/", 3)
			if len(f) != 3 {
				continue
			}
			n, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("%s init %q: %w", p.name, c, err)
			}
			p.init = append(p.init, initStatus{name: f[0], restarts: n, state: f[2]})
		}
		if m[8] != "" {
			t, err := time.Parse(time.RFC3339, m[8])
			if err != nil {
				return nil, fmt.Errorf("%s started %q: %w", p.name, m[8], err)
			}
			p.started = t
		}
		if m[10] != "" {
			t, err := time.Parse(time.RFC3339, m[10])
			if err != nil {
				return nil, fmt.Errorf("%s ready %q: %w", p.name, m[10], err)
			}
			p.readyAt = t
		}
		out = append(out, p)
	}
	return out, nil
}

// phaseOrders are the real product's phases (build/product/sneakers/product.yaml):
// data, identity, services, front.
const phaseOrders = 4

// phaseProblems checks the running pods: each Ready and every init
// container completed (a phase's wait-phase among them). For a phased
// product also no container or init container restarted, every phase is
// there and each pod started only once every pod of the phases before its
// own was Ready. A product without phases starts everything at once, and
// after a reboot the kubelet restarts its pods in place, so restarts don't
// count there. A finished Job's pod is left out.
func phaseProblems(pods []realPod, phased bool) []string {
	var out []string
	readyBy := map[int]time.Time{}
	for _, p := range pods {
		if p.phase == "Succeeded" {
			continue
		}
		for _, n := range p.restarts {
			if phased && n != 0 {
				out = append(out, fmt.Sprintf("%s restarted (%v)", p.name, p.restarts))
				break
			}
		}
		for _, c := range p.init {
			switch {
			case phased && c.restarts != 0:
				out = append(out, fmt.Sprintf("%s's init container %s restarted %d times and is %s", p.name, c.name, c.restarts, c.state))
			case c.state != "Completed":
				out = append(out, fmt.Sprintf("%s's init container %s is %s, not Completed", p.name, c.name, c.state))
			}
		}
		if !p.ready {
			why := p.phase
			if p.waiting != "" {
				why += ", " + p.waiting
			}
			out = append(out, fmt.Sprintf("%s isn't Ready (%s)", p.name, why))
		}
		if p.order > 0 && p.readyAt.After(readyBy[p.order]) {
			readyBy[p.order] = p.readyAt
		}
	}
	if !phased {
		return out
	}
	for o := 1; o <= phaseOrders; o++ {
		if _, ok := readyBy[o]; !ok {
			out = append(out, fmt.Sprintf("no pod of phase %d runs", o))
		}
	}
	for _, p := range pods {
		if p.phase == "Succeeded" || p.order < 2 {
			continue
		}
		for o := 1; o < p.order; o++ {
			if r, ok := readyBy[o]; ok && p.started.Before(r) {
				out = append(out, fmt.Sprintf("%s (phase %d) started at %s, before phase %d was Ready at %s", p.name, p.order, p.started.Format(time.RFC3339), o, r.Format(time.RFC3339)))
				break
			}
		}
	}
	return out
}

func runningApp(pods []realPod, app string) bool {
	for _, p := range pods {
		if p.app == app && p.phase == "Running" && p.ready {
			return true
		}
	}
	return false
}

// podsKeptInPlace are the running pods of after that before already had:
// the same name and start time, so restarted in place rather than made
// new.
func podsKeptInPlace(before, after []realPod) []string {
	seen := map[string]time.Time{}
	for _, p := range before {
		seen[p.name] = p.started
	}
	var out []string
	for _, p := range after {
		if t, ok := seen[p.name]; ok && p.phase == "Running" && t.Equal(p.started) {
			out = append(out, p.name)
		}
	}
	sort.Strings(out)
	return out
}
