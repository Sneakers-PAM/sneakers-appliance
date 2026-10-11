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
// start is told apart from its log; a database that doesn't answer counts
// as missing, never as written again.
func TestTheLabHookReportsTheDurabilityRows(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	hook := string(b)
	pg := regexp.MustCompile(`(?m)^pg\(\) \{.*\}\n`).FindString(hook)
	report1 := regexp.MustCompile(`(?ms)^durability_report\(\) \{\n.*?^\}\n`).FindString(hook)
	if pg == "" || report1 == "" {
		t.Fatal("the lab hook has no pg or durability_report function")
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
	out, sql := report("10000", "PostgreSQL init process complete; ready for start up.\ndatabase system is ready to accept connections", false)
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
