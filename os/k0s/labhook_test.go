// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const labHook = "../../build/lab/overlay/usr/libexec/sneakers/lab-hook"

// After a power loss the kubelet restarts the old pods in place before
// the box's phase loop can quiesce them, so the first Ready hello pod is
// the old one. The lab hook samples the phase pods only once the box says
// running (edgefall's /_box/state on its loopback listener), which it
// says only after the phase loop brought every phase up.
func TestTheLabHookSamplesThePhasesOnceTheBoxRuns(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	hook := string(b)
	running := strings.Index(hook, `wait_for "box running" box_running`)
	pods := strings.Index(hook, `say "phase pods:`)
	if running < 0 || pods < 0 || running > pods {
		t.Fatalf("the hook prints the phase pods before it waits for the box to run (box running at %d, phase pods at %d)", running, pods)
	}
	fn := regexp.MustCompile(`(?ms)^box_running\(\) \{\n.*?^\}\n`).FindString(hook)
	if fn == "" {
		t.Fatal("the lab hook has no box_running function")
	}
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("no nc on this host")
	}
	state := `{"state":"starting"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_box/state" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(state))
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	ask := func() bool {
		script := "set -u\n" + fn + `box_running "$1" "$2"` + "\n"
		return exec.Command("sh", "-c", script, "sh", host, port).Run() == nil // #nosec G204 -- the repo's own script
	}
	if ask() {
		t.Fatal("box_running says running while the box is starting")
	}
	state = `{"state":"running","brand":{}}`
	if !ask() {
		t.Fatal("box_running doesn't say running")
	}
}

// The durability product's report (build/lab/durability.sh): the rows are
// written once per box, the count is read back, and the server's current
// start is told apart from its log (the image's first start stops and
// starts its initdb server, so it logs a clean shutdown too); a database
// that doesn't answer counts
// as missing, never as written again.
func TestTheLabHookReportsTheDurabilityRows(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	hook := string(b)
	pg := regexp.MustCompile(`(?m)^pg_in\(\) \{.*\}\n`).FindString(hook) +
		regexp.MustCompile(`(?ms)^pg_start\(\) \{\n.*?^\}\n`).FindString(hook) +
		regexp.MustCompile(`(?m)^pg\(\) \{.*\}\n`).FindString(hook)
	report1 := regexp.MustCompile(`(?ms)^durability_report\(\) \{\n.*?^\}\n`).FindString(hook)
	if strings.Count(pg, "() {") != 3 || report1 == "" {
		t.Fatal("the lab hook has no pg_in, pg_start, pg or durability_report function")
	}
	// report runs durability_report with a fake kubectl: psql answers count
	// with rows (or fails when rows is empty), logs prints log; it answers
	// the hook's output and every psql statement it ran.
	report := func(rows, log string, marked bool) (string, string) {
		dir := t.TempDir()
		mark := dir + "/mark"
		if marked {
			if err := os.WriteFile(mark, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		script := "set -u\n" + `say() { echo "lab-hook: $*"; }
durability_mark="$1"
k() {
  case "$*" in
    *" logs "*) printf '%s\n' "$LOG" ;;
    *psql*) for a in "$@"; do last="$a"; done; echo "$last" >> "$STATEMENTS"
      case "$last" in *count*) [ -n "$ROWS" ] || return 1; echo "$ROWS" ;; esac ;;
  esac
}
` + pg + report1 + `durability_report v2` + "\n"
		cmd := exec.Command("sh", "-c", script, "sh", mark) // #nosec G204 -- the repo's own script
		cmd.Env = append(os.Environ(), "ROWS="+rows, "LOG="+log, "STATEMENTS="+dir+"/statements")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("durability_report: %v: %s", err, out)
		}
		sql, _ := os.ReadFile(dir + "/statements")
		return string(out), string(sql)
	}
	out, sql := report("10000", "LOG:  database system was shut down at 2026-10-11 01:50:01 UTC\nPostgreSQL init process complete; ready for start up.\nLOG:  database system was shut down at 2026-10-11 01:50:02 UTC\nLOG:  database system is ready to accept connections", false)
	if !strings.Contains(out, "durability: rows written") || !strings.Contains(out, "durability: version=v2 rows=10000 start=first") || !strings.Contains(sql, "INSERT INTO durability_rows") {
		t.Fatalf("the first report: %s (statements %q)", out, sql)
	}
	out, sql = report("10000", "LOG:  database system was shut down at 2026-10-11 00:52:01 UTC", true)
	if !strings.Contains(out, "version=v2 rows=10000 start=clean") || strings.Contains(sql, "INSERT") {
		t.Fatalf("a report after a clean stop: %s (statements %q)", out, sql)
	}
	out, _ = report("10000", "LOG:  database system was interrupted; last known up at 2026-10-11 00:59:19 UTC\nLOG:  database system was not properly shut down; automatic recovery in progress", true)
	if !strings.Contains(out, "start=recovered") {
		t.Fatalf("a report after a crash: %s", out)
	}
	out, sql = report("", "", true)
	if !strings.Contains(out, "rows=missing") || strings.Contains(sql, "INSERT") || strings.Contains(sql, "CREATE") {
		t.Fatalf("a database that doesn't answer: %s (statements %q)", out, sql)
	}
}

// The real-bundle job (build/realci) installs the Sneakers product itself,
// which has no hello stack: the hook takes its own path for it before it
// waits for the hello pod, and prints the rows and pods lines the image
// test reads (test/image/k0s/realbundle_test.go).
func TestTheLabHookReportsTheRealProduct(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	hook := string(b)
	real := strings.Index(hook, "\n  realci\n")
	hello := strings.Index(hook, `wait_for "hello pod ready"`)
	if real < 0 || hello < 0 || real > hello {
		t.Fatalf("the hook doesn't take the real product's path before it waits for the hello pod (realci at %d, hello at %d)", real, hello)
	}
	var defs []string
	for _, name := range []string{"pg_in", "pg_start", "realci_rows", "realci_pods"} {
		fn := regexp.MustCompile(`(?m)^` + name + `\(\) \{.*\}\n`).FindString(hook)
		if fn == "" {
			fn = regexp.MustCompile(`(?ms)^` + name + `\(\) \{[^\n]*\n.*?^\}\n`).FindString(hook)
		}
		if fn == "" {
			t.Fatalf("the lab hook has no %s function", name)
		}
		defs = append(defs, fn)
	}
	for _, v := range []string{"realci_dbs", "realci_count_sql"} {
		line := regexp.MustCompile(`(?m)^` + v + `=.*$`).FindString(hook)
		if line == "" {
			t.Fatalf("the lab hook doesn't set %s", v)
		}
		defs = append(defs, line)
	}
	// k stands in for kubectl: psql answers the tables of the database it
	// was asked about (the hydra database doesn't answer), and the log is
	// a first start's.
	stub := `say() { echo "lab-hook: $*"; }
k() {
  case "$*" in
    *"exec sneakers-postgres-0"*sneakers_hydra*) return 1 ;;
    *"exec sneakers-postgres-0"*) echo "realci_rows=1000,t=2" ;;
    *"logs sneakers-postgres-0"*) printf 'PostgreSQL init process complete\ndatabase system was shut down at x\n' ;;
    *"get pods"*) echo "p app=a order=1 phase=Running restarts=0 started=2026-10-12T10:00:00Z ready=True@2026-10-12T10:00:30Z;" ;;
  esac
}
`
	script := stub + strings.Join(defs, "\n") + "\nrealci_rows 0.1.0-x running\nrealci_pods 0.1.0-x running\n"
	out, err := exec.Command("sh", "-c", script).CombinedOutput() // #nosec G204 -- the repo's own script
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := string(out)
	rows := `lab-hook: realci: rows running version=0.1.0-x start=first sneakers_identity[realci_rows=1000,t=2] sneakers_vault[realci_rows=1000,t=2] sneakers_workflow[realci_rows=1000,t=2] sneakers_audit[realci_rows=1000,t=2] sneakers_kratos[realci_rows=1000,t=2] sneakers_hydra[missing]` + "\n"
	pods := "lab-hook: realci: pods running version=0.1.0-x: p app=a order=1 phase=Running restarts=0 started=2026-10-12T10:00:00Z ready=True@2026-10-12T10:00:30Z;\n"
	if got != rows+pods {
		t.Fatalf("the hook printed\n%s\nwant\n%s%s", got, rows, pods)
	}
}
