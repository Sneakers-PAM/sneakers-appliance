// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"strings"
	"testing"
)

// The lab hook's real-product lines, as build/lab/overlay/usr/libexec/sneakers/lab-hook
// prints them for the real-bundle job.
const (
	realRowsLine = `lab-hook: realci: rows running version=0.1.0-lab.realci.13 start=clean sneakers_identity[admins=2,realci_rows=1000] sneakers_vault[folders=3,realci_rows=1000,secrets=0] sneakers_hydra[missing]`
	realPodsLine = `lab-hook: realci: pods running version=0.1.0-lab.realci.13: sneakers-postgres-0 app=sneakers-postgres order=1 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:00:00Z ready=True@2026-10-12T10:00:30Z;` +
		`sneakers-vault-7d9 app=sneakers-vault order=2 phase=Running restarts=0 0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:00:40Z ready=True@2026-10-12T10:01:00Z;` +
		`sneakers-workflow-5c1 app=sneakers-workflow order=3 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:01:05Z ready=True@2026-10-12T10:01:20Z;` +
		`sneakers-gateway-6b2 app=sneakers-gateway order=4 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:01:25Z ready=True@2026-10-12T10:01:40Z;` +
		`sneakers-mcp-4f3 app=sneakers-mcp order=4 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:01:25Z ready=True@2026-10-12T10:01:45Z;` +
		`sneakers-import-x app=sneakers-import order= phase=Succeeded restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T09:00:00Z ready=False@2026-10-12T09:01:00Z;`
)

func TestTheRealRowsLineReads(t *testing.T) {
	rows, err := readRealRows(realRowsLine)
	if err != nil {
		t.Fatal(err)
	}
	if rows.start != "clean" || rows.version != "0.1.0-lab.realci.13" {
		t.Fatalf("read %+v", rows)
	}
	if rows.dbs["sneakers_vault"]["folders"] != 3 || rows.dbs["sneakers_identity"]["realci_rows"] != 1000 {
		t.Fatalf("read %+v", rows.dbs)
	}
	if _, ok := rows.dbs["sneakers_hydra"]; !ok || rows.dbs["sneakers_hydra"] != nil {
		t.Fatalf("a database the hook couldn't count reads as %v", rows.dbs["sneakers_hydra"])
	}
}

func TestRowProblemsAreFound(t *testing.T) {
	base, _ := readRealRows(strings.Replace(realRowsLine, "sneakers_hydra[missing]", "sneakers_hydra[clients=1,realci_rows=1000]", 1))
	if p := rowProblems(base, base); len(p) != 0 {
		t.Fatalf("the same rows have problems: %v", p)
	}
	// A lost database: its table gone and the canary rows with it.
	now, _ := readRealRows(realRowsLine)
	p := rowProblems(base, now)
	if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), "sneakers_hydra") {
		t.Fatalf("a database that can't be counted isn't a problem: %v", p)
	}
	// A table emptied, and canary rows short.
	now, _ = readRealRows(strings.NewReplacer("folders=3", "folders=0", "sneakers_identity[admins=2,realci_rows=1000]", "sneakers_identity[admins=2,realci_rows=999]").Replace(realRowsLine))
	p = rowProblems(base, now)
	if len(p) < 2 {
		t.Fatalf("an emptied table and short canary rows: %v", p)
	}
	// More rows in a product table is fine: the product writes as it runs.
	now, _ = readRealRows(strings.Replace(strings.Replace(realRowsLine, "folders=3", "folders=9", 1), "sneakers_hydra[missing]", "sneakers_hydra[clients=4,realci_rows=1000]", 1))
	if p := rowProblems(base, now); len(p) != 0 {
		t.Fatalf("more rows is a problem: %v", p)
	}
}

func TestTheRealPodsLineReads(t *testing.T) {
	pods, err := readRealPods(realPodsLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 6 || pods[1].app != "sneakers-vault" || pods[1].order != 2 || len(pods[1].restarts) != 2 || !pods[1].ready {
		t.Fatalf("read %+v", pods)
	}
	if pods[5].order != 0 || pods[5].phase != "Succeeded" {
		t.Fatalf("read %+v", pods[5])
	}
	if p := phaseProblems(pods, true); len(p) != 0 {
		t.Fatalf("phases in order have problems: %v", p)
	}
}

func TestPhaseProblemsAreFound(t *testing.T) {
	// The front phase started before the services were Ready.
	early := strings.Replace(realPodsLine, "app=sneakers-gateway order=4 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:01:25Z", "app=sneakers-gateway order=4 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:01:10Z", 1)
	pods, _ := readRealPods(early)
	if p := phaseProblems(pods, true); len(p) != 1 || !strings.Contains(p[0], "sneakers-gateway") {
		t.Fatalf("an early start: %v", p)
	}
	// A restart, and a pod that isn't Ready.
	bad := strings.NewReplacer("restarts=0 0", "restarts=0 1", "ready=True@2026-10-12T10:01:45Z", "ready=False@2026-10-12T10:01:45Z").Replace(realPodsLine)
	pods, _ = readRealPods(bad)
	if p := phaseProblems(pods, true); len(p) != 2 {
		t.Fatalf("a restart and a pod not Ready: %v", p)
	}
	// A phased product with a phase missing.
	var kept []string
	for _, item := range strings.Split(realPodsLine, ";") {
		if !strings.Contains(item, "order=3") {
			kept = append(kept, item)
		}
	}
	pods, _ = readRealPods(strings.Join(kept, ";"))
	if p := phaseProblems(pods, true); len(p) != 1 || !strings.Contains(p[0], "phase 3") {
		t.Fatalf("a missing phase: %v", p)
	}
	// Without phases nothing is ordered and the services start at once, so
	// one may restart until the database answers: only Ready counts.
	pods, _ = readRealPods(strings.ReplaceAll(bad, "order=4", "order="))
	if p := phaseProblems(pods, false); len(p) != 1 || !strings.Contains(p[0], "sneakers-mcp-4f3 isn't Ready") {
		t.Fatalf("without phases: %v", p)
	}
}

// The data phase stuck on its wait: the PostgreSQL pod's wait-phase init
// container failing and backing off, so the server never starts.
func TestAFailingInitContainerIsFound(t *testing.T) {
	stuck := strings.Replace(realPodsLine, "sneakers-postgres-0 app=sneakers-postgres order=1 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:00:00Z ready=True@",
		"sneakers-postgres-0 app=sneakers-postgres order=1 phase=Pending restarts=0 init=[wait-phase/4/CrashLoopBackOff,] waiting=PodInitializing started=2026-10-12T10:00:00Z ready=False@", 1)
	pods, err := readRealPods(stuck)
	if err != nil {
		t.Fatal(err)
	}
	if pods[0].init[0].name != "wait-phase" || pods[0].init[0].restarts != 4 || pods[0].init[0].state != "CrashLoopBackOff" || pods[0].waiting != "PodInitializing" {
		t.Fatalf("read %+v", pods[0])
	}
	p := strings.Join(phaseProblems(pods, true), "\n")
	if !strings.Contains(p, "sneakers-postgres-0's init container wait-phase restarted 4 times and is CrashLoopBackOff") || !strings.Contains(p, "sneakers-postgres-0 isn't Ready (Pending, PodInitializing)") {
		t.Fatalf("a failing wait-phase: %s", p)
	}
	// One that completed after a restart is a problem too.
	again, _ := readRealPods(strings.Replace(realPodsLine, "init=[wait-phase/0/Completed,]", "init=[wait-phase/1/Completed,]", 1))
	if p := phaseProblems(again, true); len(p) != 1 || !strings.Contains(p[0], "wait-phase restarted 1 times") {
		t.Fatalf("an init container that restarted: %v", p)
	}
	// Without phases a pod restarted in place after a reboot runs its init
	// containers again: that's not a problem there.
	if p := phaseProblems(again, false); len(p) != 0 {
		t.Fatalf("an init container that ran again without phases: %v", p)
	}
}

func TestPodsRestartedInPlaceAreFound(t *testing.T) {
	before, _ := readRealPods(realPodsLine)
	// The running pods, the finished Job's aside.
	if got := podsKeptInPlace(before, before); len(got) != 5 {
		t.Fatalf("the same pods: %v", got)
	}
	after, _ := readRealPods(strings.Replace(realPodsLine, "started=2026-10-12T10:00:40Z", "started=2026-10-12T11:00:40Z", 1))
	if got := podsKeptInPlace(before, after); len(got) != 4 {
		t.Fatalf("one new pod: %v", got)
	}
	after, _ = readRealPods(strings.ReplaceAll(realPodsLine, "2026-10-12T10:0", "2026-10-12T11:0"))
	if got := podsKeptInPlace(before, after); len(got) != 0 {
		t.Fatalf("new pods: %v", got)
	}
}

// The report's lines are found by their literal prefix: a version's dots
// are dots, and the last line wins.
func TestTheLastLineIsFound(t *testing.T) {
	console := "lab-hook: realci: rows running version=0.1.0-lab.realci.12 start=first a[x=1]\r\n" +
		"lab-hook: realci: rows running version=0.1.0-lab.realci.12 start=clean a[x=2]\r\nlab-hook: other\n"
	got := lastLine(console, "realci: rows running version=0.1.0-lab.realci.12 ")
	if got != "realci: rows running version=0.1.0-lab.realci.12 start=clean a[x=2]" {
		t.Fatalf("got %q", got)
	}
	if got := lastLine(console, "realci: rows running version=0.1.0-lab.realci.13 "); got != "" {
		t.Fatalf("another version: %q", got)
	}
}

// The hook's memory line: the box's memory in kB, the product's pods in
// bytes, read in MiB.
func TestTheMemoryLineReads(t *testing.T) {
	m, ok := readMemory(`lab-hook: realci: memory state=maintenance total=12249088 available=7340032 pods=3221225472 import=sneakers-migrate-review-1-abcde:1610612736`)
	if !ok || m.state != "maintenance" || m.total != 11962 || m.available != 7168 || m.pods != 3072 {
		t.Fatalf("read %+v %v", m, ok)
	}
	if m, ok := readMemory(`lab-hook: realci: memory state=running total=8000000 available=4000000 pods=unknown import=none:0`); !ok || m.pods != -1 {
		t.Fatalf("pods unknown: %+v %v", m, ok)
	}
}

// A step's peak is the hook's line for its pod.
func TestTheImportPeakLineMatchesItsJob(t *testing.T) {
	m := importPeakLine.FindStringSubmatch(`lab-hook: realci: import peak pod=sneakers-migrate-review-1-abcde peak=1610612736`)
	if m == nil || !strings.HasPrefix(m[1], "sneakers-migrate-review-1-") || m[2] != "1610612736" {
		t.Fatalf("%q", m)
	}
}
