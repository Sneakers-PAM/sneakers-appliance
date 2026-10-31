// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// The import leg (docs/testing.md#the-import-leg): an earlier install with
// a large audit chain moved onto a new box running the product under test,
// through the Import page's API, step by step, as an admin does it.

// importRecords is the size of the source's audit chain: more than the
// largest source measured (726,805 records, a 37 MB bundle), whose steps
// needed 1.6 GiB.
const importRecords = 727000

// importSourceName is the source's name, which the box's "imported from"
// audit record names.
const importSourceName = "source.example.org"

// importMemMiB is the import leg's VM: the product, held while the import
// is open, and a step's 4 GiB limit, with room for the box's own check
// that a step fits (internal/productimport).
const importMemMiB = 12288

// importEnv is what build/realci/build.sh wrote for the import leg.
type importEnv struct {
	newImage, releaseSrc, migrate, synth string
}

func needImport(t *testing.T) importEnv {
	t.Helper()
	e := importEnv{newImage: os.Getenv("SNEAKERS_REAL_NEW_IMAGE"), releaseSrc: os.Getenv("SNEAKERS_REAL_RELEASE_SRC"),
		migrate: os.Getenv("SNEAKERS_REAL_MIGRATE"), synth: os.Getenv("SNEAKERS_REAL_SYNTH")}
	if e.newImage == "" || e.releaseSrc == "" || e.migrate == "" || e.synth == "" {
		t.Skip("SNEAKERS_REAL_NEW_IMAGE, _RELEASE_SRC, _MIGRATE and _SYNTH name the import leg's builds (build/realci/build.sh)")
	}
	harness.Need(t, []string{"docker", "python3", "openssl"}, e.newImage, e.releaseSrc, e.migrate, e.synth)
	return e
}

// source is the earlier install: sneakers-release's synthetic source in
// containers on the runner (build/realci/source.sh).
type source struct {
	env []string
	up  *exec.Cmd
	out *bytes.Buffer
}

func (s *source) run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join("..", "..", "..", "build", "realci", "source.sh")}, args...)...) // #nosec G204 -- test-only, the repository's own script
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source.sh %s: %v: %s", args[0], err, out)
	}
	return string(out)
}

// startSource seeds the source while the box comes up; it's taken down
// when the test ends.
func startSource(t *testing.T, e importEnv, records int) *source {
	t.Helper()
	work := filepath.Join(t.TempDir(), "source")
	s := &source{env: append(os.Environ(), "RELEASE_SRC="+e.releaseSrc, "MIGRATE="+e.migrate, "SYNTH="+e.synth, "WORK="+work,
		"AUDIT_RECORDS="+strconv.Itoa(records), "PREFIX=realci-source", "SOURCE_NAME="+importSourceName), out: &bytes.Buffer{}}
	s.up = exec.Command("bash", filepath.Join("..", "..", "..", "build", "realci", "source.sh"), "up") // #nosec G204 -- as above
	s.up.Env, s.up.Stdout, s.up.Stderr = s.env, s.out, s.out
	if err := s.up.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = s.up.Wait()
		cmd := exec.Command("bash", filepath.Join("..", "..", "..", "build", "realci", "source.sh"), "down") // #nosec G204 -- as above
		cmd.Env = s.env
		_ = cmd.Run()
	})
	return s
}

func (s *source) ready(t *testing.T) {
	t.Helper()
	if err := s.up.Wait(); err != nil {
		t.Fatalf("source.sh up: %v: %s", err, s.out)
	}
	t.Logf("the source:\n%s", strings.TrimSpace(s.out.String()))
}

// importRun is one step in GetImport.
type importRun struct {
	Job      string `json:"job"`
	Step     string `json:"step"`
	State    string `json:"state"`
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
	Report   string `json:"report"`
	Reason   string `json:"reason"`
	Started  string `json:"startedAt"`
	Finished string `json:"finishedAt"`
}

type importPage struct {
	Open      bool        `json:"open"`
	Recipient string      `json:"recipient"`
	Imported  bool        `json:"imported"`
	Runs      []importRun `json:"runs"`
}

// try is call that answers the box's error instead of failing the test.
func (a *admin) try(method string, in, out any) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequest(http.MethodPost, a.base+"/sneakers.appliance.osadmin.v1."+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s: %s", method, resp.Status, b)
	}
	return json.Unmarshal(b, out)
}

// importUpload posts one import file of kind.
func (a *admin) importUpload(t *testing.T, kind, file string) {
	t.Helper()
	f, err := os.Open(file) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	req, err := http.NewRequest(http.MethodPost, a.base+"/import/upload?kind="+kind, f)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := a.hc.Do(req)
	if err != nil {
		t.Fatalf("upload %s: %v", kind, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload %s: %s: %s", kind, resp.Status, b)
	}
}

// importStep runs one step with a fresh sign-in (each step takes a fresh
// code) and waits for it to end; it fails the test unless the step passed.
// It answers the step and how long it took.
func (b *realBox) importStep(step string, opts map[string]any, timeout time.Duration) (importRun, time.Duration) {
	b.t.Helper()
	req := map[string]any{"step": step}
	for k, v := range opts {
		req[k] = v
	}
	adm := signIn(b.t, b.adminPort, b.alice)
	start := time.Now()
	var started struct {
		Job string `json:"job"`
	}
	deadline := start.Add(timeout)
	for {
		err := adm.try("ImportService/RunImportStep", req, &started)
		if err == nil {
			break
		}
		// Verify waits for the product to be ready again after the import.
		if !strings.Contains(err.Error(), "PRODUCT_NOT_READY") || time.Now().After(deadline) {
			b.t.Fatalf("the %s step: %v", step, err)
		}
		time.Sleep(15 * time.Second)
		adm = signIn(b.t, b.adminPort, b.alice)
	}
	for {
		var page importPage
		if err := adm.try("ImportService/GetImport", map[string]any{}, &page); err != nil {
			b.t.Logf("GetImport: %v; signing in again", err)
			adm = signIn(b.t, b.adminPort, b.alice)
			continue
		}
		for _, r := range page.Runs {
			if r.Job != started.Job || r.State == "running" {
				continue
			}
			took := time.Since(start)
			if r.State != "passed" {
				b.t.Fatalf("the %s step (%s) %s with exit %d after %s: %s\noutput:\n%s\nthe box's memory:\n%s", step, r.Job, r.State, r.ExitCode, took.Round(time.Second), r.Reason, tail(r.Output, 40), b.memoryLines())
			}
			b.t.Logf("the %s step passed in %s; peak %s", step, took.Round(time.Second), b.importPeak(r.Job))
			return r, took
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("the %s step (%s) still runs after %s\nthe box's memory:\n%s", step, started.Job, timeout, b.memoryLines())
		}
		time.Sleep(15 * time.Second)
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

var (
	importPeakLine = regexp.MustCompile(`realci: import peak pod=(\S+) peak=(\d+)`)
	memoryLine     = regexp.MustCompile(`realci: memory state=(\S*) total=(\d+) available=(\d+) pods=(\d+|unknown) import=(\S+)`)
)

// importPeak is the lab hook's peak for job's pod, once it printed it.
func (b *realBox) importPeak(job string) string {
	var peak string
	for range 12 {
		for _, m := range importPeakLine.FindAllStringSubmatch(b.vm.Console(), -1) {
			if strings.HasPrefix(m[1], job+"-") {
				peak = m[2]
			}
		}
		if peak != "" {
			n, _ := strconv.ParseInt(peak, 10, 64)
			return fmt.Sprintf("%d MiB", n>>20)
		}
		time.Sleep(5 * time.Second)
	}
	return "not read"
}

// memory is the lab hook's last memory line, read: the box's total and
// available memory and what the product's pods use, in MiB.
type memory struct {
	state                  string
	total, available, pods int64
}

func readMemory(line string) (memory, bool) {
	m := memoryLine.FindStringSubmatch(line)
	if m == nil {
		return memory{}, false
	}
	kb := func(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n >> 10 }
	mem := memory{state: m[1], total: kb(m[2]), available: kb(m[3]), pods: -1}
	if m[4] != "unknown" {
		n, _ := strconv.ParseInt(m[4], 10, 64)
		mem.pods = n >> 20
	}
	return mem, true
}

func (m memory) String() string {
	return fmt.Sprintf("state %s: %d MiB of %d MiB in use (%d MiB available), the product's pods %d MiB", m.state, m.total-m.available, m.total, m.available, m.pods)
}

// lastMemory waits for the hook's next memory line and reads it.
func (b *realBox) lastMemory() memory {
	b.t.Helper()
	n := len(memoryLine.FindAllString(b.vm.Console(), -1))
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		all := memoryLine.FindAllString(b.vm.Console(), -1)
		if len(all) > n {
			m, _ := readMemory(all[len(all)-1])
			return m
		}
		time.Sleep(5 * time.Second)
	}
	b.t.Fatalf("the lab hook printed no memory line in 3m")
	return memory{}
}

// memoryLines are the hook's last memory lines, and its last line on a
// product container that restarted.
func (b *realBox) memoryLines() string {
	all := memoryLine.FindAllString(b.vm.Console(), -1)
	if len(all) > 5 {
		all = all[len(all)-5:]
	}
	if l := lastLine(b.vm.Console(), "realci: restarted "); l != "" {
		all = append(all, l)
	}
	return strings.Join(all, "\n")
}

// takesSourceName says whether this sneakers-migrate writes bundle format
// 2.0, which leaves the audit trail on the source.
func takesSourceName(t *testing.T, migrate string) bool {
	t.Helper()
	out, err := exec.Command(migrate, "export", "--help").CombinedOutput() // #nosec G204 -- test-only, the run's own build
	if err != nil {
		t.Fatalf("sneakers-migrate export --help: %v: %s", err, out)
	}
	return strings.Contains(string(out), "--source-name")
}

var notCarriedAudit = regexp.MustCompile(`not carried: audit\.audit_records \((\d+) rows\)`)

// trailStays checks a format 2.0 import from the export's output and the
// review's, import's and verify's reports: the audit trail stayed on the
// source (records long), the box took none of it, and the box's chain
// starts with the one record of the import, naming the source.
func trailStays(name string, records int, export, review, imp, verify string) error {
	m := notCarriedAudit.FindStringSubmatch(export)
	if m == nil {
		return fmt.Errorf("the export doesn't list the audit trail as not carried:\n%s", export)
	}
	if n, _ := strconv.Atoi(m[1]); n < records {
		return fmt.Errorf("the export left %d audit records on the source, not %d", n, records)
	}
	var rv struct {
		AuditTrail string `json:"audit_trail"`
	}
	if err := json.Unmarshal([]byte(review), &rv); err != nil {
		return fmt.Errorf("the review report: %w", err)
	}
	if !strings.Contains(rv.AuditTrail, "stays on the source") {
		return fmt.Errorf("the review's audit trail note says %q", rv.AuditTrail)
	}
	type counted struct {
		Table string `json:"table"`
	}
	var ir struct {
		ImportedFrom string    `json:"imported_from"`
		Entries      int       `json:"migration_audit_entries"`
		Tables       []counted `json:"tables"`
		NotCarried   []struct {
			Name string `json:"name"`
		} `json:"not_carried"`
	}
	if err := json.Unmarshal([]byte(imp), &ir); err != nil {
		return fmt.Errorf("the import report: %w", err)
	}
	if ir.ImportedFrom != name {
		return fmt.Errorf("the import is from %q, not %q", ir.ImportedFrom, name)
	}
	if ir.Entries != 1 {
		return fmt.Errorf("the import wrote %d audit records, not 1", ir.Entries)
	}
	for _, c := range ir.Tables {
		if strings.HasPrefix(c.Table, "audit.") {
			return fmt.Errorf("the import took %s", c.Table)
		}
	}
	listed := false
	for _, n := range ir.NotCarried {
		listed = listed || n.Name == "audit.audit_records"
	}
	if !listed {
		return fmt.Errorf("the import report doesn't list the audit trail as not carried")
	}
	var vr struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"checks"`
		Counts []counted `json:"counts"`
	}
	if err := json.Unmarshal([]byte(verify), &vr); err != nil {
		return fmt.Errorf("the verify report: %w", err)
	}
	if !vr.OK {
		return fmt.Errorf("the verify report isn't ok: %s", verify)
	}
	for _, c := range vr.Counts {
		if strings.HasPrefix(c.Table, "audit.") {
			return fmt.Errorf("the verify counted %s", c.Table)
		}
	}
	head := "starting with the import record (imported from " + name + ")"
	for _, c := range vr.Checks {
		if c.Name == "audit chain" {
			if !c.OK || !strings.Contains(c.Detail, head) {
				return fmt.Errorf("the audit chain check: ok=%t %q", c.OK, c.Detail)
			}
			return nil
		}
	}
	return fmt.Errorf("the verify report has no audit chain check")
}

// TestTheRealBundleImportsALargeAuditChain moves an earlier install with
// a 727,000-record audit chain onto a new box running the product under
// test, through the Import page's API: open, the export encrypted to the
// box's key, then review, convert (a proposal sheet that renames one
// secret), check, import with the first admin's email and verify, each a
// Job that must pass. Bundle format 2.0 leaves the chain on the source, and
// the box's chain starts with one record of the import. Until the release
// pins a migrate image that writes 2.0, the leg moves the chain as format 1
// does. The box's memory is read from the lab hook with the product
// running, with the import open, and at each step's peak.
func TestTheRealBundleImportsALargeAuditChain(t *testing.T) {
	e := needReal(t)
	ie := needImport(t)
	src := startSource(t, ie, importRecords)
	legStart := time.Now()
	b := newRealBoxFrom(t, e, ie.newImage, e.newVersion, importMemMiB)
	vNext := productVersion(e.next)
	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	b.mustRun(vNext, "the install of "+vNext, realRows{}, true, false)
	running := b.lastMemory()
	t.Logf("the product runs: %s", running)

	adm := signIn(t, b.adminPort, b.alice)
	var open struct {
		Recipient string `json:"recipient"`
	}
	adm.call(t, "ImportService/OpenImport", map[string]any{}, &open)
	if !strings.HasPrefix(open.Recipient, "age1") {
		t.Fatalf("OpenImport: recipient %q", open.Recipient)
	}
	src.ready(t)
	bundle := filepath.Join(t.TempDir(), "bundle.age")
	exported := src.run(t, "export", open.Recipient, bundle)
	t.Logf("%s", strings.TrimSpace(exported))
	// The import holds the product after its services phase: the memory
	// with the import open is what the steps run next to.
	held := b.lastMemory()
	t.Logf("the import is open (the gateway and the web apps held): %s", held)
	adm = signIn(t, b.adminPort, b.alice)
	adm.importUpload(t, "bundle", bundle)

	var took []string
	timed := func(step string, d time.Duration) {
		took = append(took, fmt.Sprintf("%s %s", step, d.Round(time.Second)))
	}
	review, d := b.importStep("review", nil, time.Hour)
	timed("review", d)
	var rep struct {
		Secrets []struct {
			ID      string   `json:"id"`
			Folder  []string `json:"folder"`
			Owner   string   `json:"owner"`
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			Retired bool     `json:"retired"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(review.Report), &rep); err != nil {
		t.Fatalf("the review report: %v", err)
	}
	sheet := filepath.Join(t.TempDir(), "sheet.tsv")
	var row string
	for _, s := range rep.Secrets {
		if s.Owner == "" && !s.Retired && len(s.Folder) > 0 {
			f := s.Folder[len(s.Folder)-1]
			row = strings.Join([]string{s.ID, f, s.Name, s.Type, f, s.Name + " (moved)", s.Type, "carry"}, "\t")
			break
		}
	}
	if row == "" {
		t.Fatalf("the review lists no shared secret (%d secrets)", len(rep.Secrets))
	}
	if err := os.WriteFile(sheet, []byte("id\tcurrent_folder\tcurrent_name\tcurrent_type\tnew_folder\tnew_name\tnew_type\taction\n"+row+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adm = signIn(t, b.adminPort, b.alice)
	adm.importUpload(t, "sheet", sheet)
	_, d = b.importStep("convert", map[string]any{"personal": "owner@example.org"}, time.Hour)
	timed("convert", d)
	_, d = b.importStep("check", nil, time.Hour)
	timed("check", d)
	imp, d := b.importStep("import", map[string]any{"ownerEmail": "owner@example.org"}, 2*time.Hour)
	timed("import", d)
	if !strings.Contains(imp.Output, "parity") {
		t.Logf("the import's output has no parity lines:\n%s", tail(imp.Output, 20))
	}
	adm = signIn(t, b.adminPort, b.alice)
	var pw struct {
		Password string `json:"password"`
	}
	adm.call(t, "ImportService/TakeOwnerPassword", map[string]any{"job": imp.Job}, &pw)
	if pw.Password == "" {
		t.Fatal("the import made no one-time password for the first admin")
	}
	ver, d := b.importStep("verify", nil, time.Hour)
	timed("verify", d)
	if takesSourceName(t, ie.migrate) {
		if err := trailStays(importSourceName, importRecords, exported, review.Report, imp.Report, ver.Report); err != nil {
			t.Fatal(err)
		}
		t.Logf("the audit trail stayed on the source, and the box's chain starts with the import of %s", importSourceName)
	} else {
		t.Logf("the release's migrate image writes bundle format 1: the audit chain moved with the bundle")
	}

	adm = signIn(t, b.adminPort, b.alice)
	var page importPage
	adm.call(t, "ImportService/GetImport", map[string]any{}, &page)
	if !page.Imported {
		t.Fatal("the import passed, but the box isn't in imported-users mode")
	}
	// The hook names every product container that restarted with its
	// memory line: none may have (the audit service once ran out of
	// memory verifying a long chain).
	after := b.lastMemory()
	time.Sleep(10 * time.Second) // the restarted lines follow the memory line
	if l := lastLine(b.vm.Console(), "realci: restarted "); l != "" {
		t.Fatalf("a product container restarted during the import: %s", l)
	}
	t.Logf("after the import: %s", after)
	t.Logf("the import of %d audit records: %s; the leg took %s", importRecords, strings.Join(took, ", "), time.Since(legStart).Round(time.Minute))
	t.Logf("the box's memory: with the product running %s; with the import open %s", running, held)
	adm.call(t, "ImportService/CloseImport", map[string]any{}, &struct{}{})
	// Closed, the held phases come back and the box leaves maintenance.
	deadline := time.Now().Add(15 * time.Minute)
	for m := b.lastMemory(); m.state != "running"; m = b.lastMemory() {
		if time.Now().After(deadline) {
			t.Fatalf("15m after the close the box is still %s:\n%s", m.state, b.waiting())
		}
	}
	t.Logf("after the close the box runs the product again")
}
