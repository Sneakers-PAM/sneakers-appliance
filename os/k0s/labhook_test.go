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
	"sync/atomic"
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
	// state is read by the server's handler goroutine and written by this
	// goroutine between requests; atomic.Value keeps that race-free.
	var state atomic.Value
	state.Store(`{"state":"starting"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_box/state" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(state.Load().(string)))
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
	state.Store(`{"state":"running","brand":{}}`)
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
	// The pods line carries each init container's restarts and end, so a
	// phase stuck on its wait shows why.
	if !strings.Contains(hook, "init=[{range .status.initContainerStatuses[*]}{.name}/{.restartCount}/{.state.terminated.reason}{.state.waiting.reason},{end}]") {
		t.Fatal("the hook's pods line doesn't show the init containers")
	}
	var defs []string
	for _, name := range []string{"pg_pod", "pg_in", "pg_start", "realci_rows", "realci_certs", "realci_pods"} {
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
    *"get pod sneakers-pgha-0"*) return 1 ;;
    *"exec sneakers-postgres-0"*sneakers_hydra*) return 1 ;;
    *"exec sneakers-postgres-0"*) echo "realci_rows=1000,t=2" ;;
    *"logs sneakers-postgres-0"*) printf 'PostgreSQL init process complete\ndatabase system was shut down at x\n' ;;
    *"get issuers.cert-manager.io"*) printf 'issuer/a\nissuer/b\n' ;;  # scrub:allow=fqdn -- a Kubernetes API group
    *"get certificates.cert-manager.io"*) printf 'certificate/c%s\n' 1 2 3 4 5 6 7 8 9 ;;  # scrub:allow=fqdn -- a Kubernetes API group
    *"get secrets"*) printf 'secret/s%s-tls\nsecret/other\n' 1 2 3 4 5 6 7 8 9 ;;
    *"get pods"*) echo "p app=a order=1 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:00:00Z ready=True@2026-10-12T10:00:30Z;" ;;
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
	rows += "lab-hook: realci: database running version=0.1.0-x on=sneakers-postgres-0 move=\n"
	rows += "lab-hook: realci: certs running version=0.1.0-x issuers=2 certificates=9 secrets=9\n"
	pods := "lab-hook: realci: pods running version=0.1.0-x: p app=a order=1 phase=Running restarts=0 init=[wait-phase/0/Completed,] waiting= started=2026-10-12T10:00:00Z ready=True@2026-10-12T10:00:30Z;\n"
	if got != rows+pods {
		t.Fatalf("the hook printed\n%s\nwant\n%s%s", got, rows, pods)
	}
}

// The database comes back while the restore still runs, so the backup leg's
// line for its end has to come from the restore moving on, with the rows
// unchanged. The product then runs on other data, so it's reported again.
func TestTheLabHookFollowsARestoreToItsEnd(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^realci_later\(\) \{[^\n]*\n.*?^\}\n`).FindString(string(b))
	if fn == "" {
		t.Fatal("the lab hook has no realci_later function")
	}
	dir := t.TempDir()
	set, journal := dir+"/manifest.json", dir+"/backup-restore.json"
	if err := os.WriteFile(set, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `say() { echo "lab-hook: $*"; }
realci_set=` + set + `
realci_journal=` + journal + `
realci_later_mark=` + dir + `/mark
realci_later_was=
last=v1
pg_in() { case "$2" in CREATE*) ;; *) echo "$PRESENT" ;; esac; }
` + fn + `
tick() { PRESENT=$1; realci_later; echo "last=$last"; }
tick t
printf '{\n  "state": "running"\n}\n' > ` + journal + `
tick f
last=v1
tick f
printf '{\n  "state": "settling"\n}\n' > ` + journal + `
tick f
`
	cmd := exec.Command("sh", "-c", script) // #nosec G204 -- the repo's own script
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("realci_later: %v: %s", err, out)
	}
	want := `lab-hook: realci: later present=t restore=
last=v1
lab-hook: realci: later present=f restore=running
last=
last=v1
lab-hook: realci: later present=f restore=settling
last=
`
	if string(out) != want {
		t.Fatalf("realci_later said:\n%s\nwant:\n%s", out, want)
	}
}

// The telemetry leg's stop-on-failure check: with telemetry-break in the
// ESP marker, the first restart that runs gets sneakers-notify stuck, and
// once that restart has failed the hook frees it again for the retry. A
// later restart, and a box without the marker, are left alone.
func TestTheLabHookBreaksTheFirstTelemetryRestartOnce(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^realci_telemetry\(\) \{[^\n]*\n.*?^\}\n`).FindString(string(b))
	if fn == "" {
		t.Fatal("the lab hook has no realci_telemetry function")
	}
	run := func(marker string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/marker", []byte(marker), 0o600); err != nil {
			t.Fatal(err)
		}
		script := `say() { echo "lab-hook: $*"; }
k() { echo "k $1 $2 $3 $4 $5 $6" >&2; }
realci_pods() { echo "pods $2"; }
v=v1
realci_telemetry_run=` + dir + `/run.json
realci_telemetry_broken=` + dir + `/broken
realci_telemetry_marker=` + dir + `/marker
realci_telemetry_was=
` + fn + `
state() { printf '{"state":"%s"}\n' "$1" > "$realci_telemetry_run"; realci_telemetry; }
state running
state failed
state running
state done
`
		out, err := exec.Command("sh", "-c", script).CombinedOutput() // #nosec G204 -- the repo's own script
		if err != nil {
			t.Fatalf("realci_telemetry: %v: %s", err, out)
		}
		return string(out)
	}
	want := `lab-hook: realci: telemetry restart=running
k -n sneakers patch deployment sneakers-notify --type=strategic
lab-hook: realci: telemetry break=on
lab-hook: realci: telemetry restart=failed
k -n sneakers patch deployment sneakers-notify --type=json
lab-hook: realci: telemetry break=off
pods telemetry
lab-hook: realci: telemetry restart=running
lab-hook: realci: telemetry restart=done
pods telemetry
`
	if got := run("real-bundle job\ntelemetry-break\n"); got != want {
		t.Fatalf("with the marker, realci_telemetry said:\n%s\nwant:\n%s", got, want)
	}
	plain := `lab-hook: realci: telemetry restart=running
lab-hook: realci: telemetry restart=failed
pods telemetry
lab-hook: realci: telemetry restart=running
lab-hook: realci: telemetry restart=done
pods telemetry
`
	if got := run("real-bundle job\n"); got != plain {
		t.Fatalf("without it, realci_telemetry said:\n%s\nwant:\n%s", got, plain)
	}
}

// A pod that is Running but never Ready leaves no crash line, so at the
// wait timeout the hook has to say why itself: the Ready condition, the last
// 40 log lines of each container that isn't ready (this run's and the one
// before a restart) and the pod's events. A pod that is Ready, or that has
// finished (a phase job), is left out.
func TestTheLabHookExplainsAPodThatIsRunningButNotReady(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^realci_notready\(\) \{[^\n]*\n.*?^\}\n`).FindString(string(b))
	if fn == "" {
		t.Fatal("the lab hook has no realci_notready function")
	}
	stub := `say() { echo "lab-hook: $*"; }
k() {
  case "$*" in
    *"get pods"*) printf 'good Running True\nmcp Running False\njob Succeeded False\n' ;;
    *"get pod mcp"*"containerStatuses"*) echo "mcp" ;;
    *"get pod mcp"*) echo "ContainersNotReady/containers with unready status: [mcp]" ;;
    *"logs mcp -c mcp --previous --tail=40"*) printf 'old one\nlast words\n' ;;
    *"logs mcp -c mcp --tail=40"*) printf 'starting\nlistening\n' ;;
    *"get events"*"involvedObject.name=mcp"*) echo "Unhealthy Readiness probe failed: 503" ;;
    *) echo "unexpected k $*" >&2; return 1 ;;
  esac
}
`
	out, err := exec.Command("sh", "-c", stub+fn+"\nrealci_notready\n").CombinedOutput() // #nosec G204 -- the repo's own script
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := "lab-hook: realci: notready mcp: ContainersNotReady/containers with unready status: [mcp]\n" +
		"lab-hook: realci: notready mcp/mcp previous log: old one last words \n" +
		"lab-hook: realci: notready mcp/mcp log: starting listening \n" +
		"lab-hook: realci: notready mcp events: Unhealthy Readiness probe failed: 503\n"
	if string(out) != want {
		t.Fatalf("the hook printed\n%s\nwant\n%s", out, want)
	}
	if !strings.Contains(string(b), "realci_crashes\n        realci_notready\n") {
		t.Fatal("the wait report doesn't call realci_notready after realci_crashes")
	}
}

// A pod that stays not Ready because a dependency is unreachable needs the
// dependency's side too (#596): the gateway pods' restarts and how their last
// run ended, whether its Service has endpoints, and the node's conditions and
// events (a kubelet or sandbox change shows there). It runs after
// realci_notready at the wait timeout.
func TestTheLabHookReportsTheGatewaySide(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^realci_gateway\(\) \{[^\n]*\n.*?^\}\n`).FindString(string(b))
	if fn == "" {
		t.Fatal("the lab hook has no realci_gateway function")
	}
	stub := `say() { echo "lab-hook: $*"; }
k() {
  case "$*" in
    *"get pods -l app.kubernetes.io/name=sneakers-gateway"*) echo "gw-1 ready=True restarts=2 last=Error/1" ;;
    *"get endpoints sneakers-gateway"*) echo "192.0.2.9" ;;
    *"get nodes"*) echo "Ready=True MemoryPressure=False DiskPressure=False PIDPressure=False" ;;
    *"get events"*"involvedObject.kind=Node"*) echo "Starting kubelet; NodeReady" ;;
    *) echo "unexpected k $*" >&2; return 1 ;;
  esac
}
`
	out, err := exec.Command("sh", "-c", stub+fn+"\nrealci_gateway\n").CombinedOutput() // #nosec G204 -- the repo's own script
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := "lab-hook: realci: gateway pods: gw-1 ready=True restarts=2 last=Error/1\n" +
		"lab-hook: realci: gateway endpoints: 192.0.2.9\n" +
		"lab-hook: realci: node conditions: Ready=True MemoryPressure=False DiskPressure=False PIDPressure=False\n" +
		"lab-hook: realci: node events: Starting kubelet; NodeReady\n"
	if string(out) != want {
		t.Fatalf("the hook printed\n%s\nwant\n%s", out, want)
	}
	if !strings.Contains(string(b), "realci_notready\n        realci_gateway\n") {
		t.Fatal("the wait report doesn't call realci_gateway after realci_notready")
	}
}

// A crash-looping container's report keeps the error message, which Node
// prints before its stack (a short tail left only the last frames), and
// the kernel's ext4 lines, so a pod that breaks after a power loss shows
// whether its files or the volume were damaged.
func TestTheLabHookKeepsACrashsErrorAndTheKernelsExt4Lines(t *testing.T) {
	b, err := os.ReadFile(labHook)
	if err != nil {
		t.Fatal(err)
	}
	hook := string(b)
	crashes := regexp.MustCompile(`(?ms)^realci_crashes\(\) \{\n.*?^\}\n`).FindString(hook)
	ext4 := regexp.MustCompile(`(?ms)^realci_ext4\(\) \{\n.*?^\}\n`).FindString(hook)
	if crashes == "" || ext4 == "" {
		t.Fatal("the lab hook has no realci_crashes or realci_ext4 function")
	}
	script := "set -u\n" + `say() { echo "lab-hook: $*"; }
dmesg() { printf '%s\n' "[1.0] EXT4-fs (dm-0): recovery complete" "[2.0] eth0: link up" "[3.0] EXT4-fs error (device dm-0): ext4_find_extent: bad header"; }
k() {
  case "$*" in
    *"get pods"*) printf 'web-0 web\n' ;;
    *" logs "*) for a in "$@"; do case "$a" in --tail=*) echo "$a" >> "$TAILS" ;; esac; done
      echo "Error [ERR_MODULE_NOT_FOUND]: Cannot find module"; i=1; while [ "$i" -le 20 ]; do echo "    at frame$i"; i=$((i+1)); done; echo "Node.js v24" ;;
  esac
}
` + crashes + ext4 + "realci_crashes\nrealci_ext4\n"
	dir := t.TempDir()
	cmd := exec.Command("sh", "-c", script) // #nosec G204 -- the repo's own script
	cmd.Env = append(os.Environ(), "TAILS="+dir+"/tails")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("crashes: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "crash web-0/web: Error [ERR_MODULE_NOT_FOUND]") {
		t.Fatalf("the crash line lost the error message: %s", out)
	}
	if tails, _ := os.ReadFile(dir + "/tails"); strings.TrimSpace(string(tails)) != "--tail=40" {
		t.Fatalf("the crash's log tail is %q; want --tail=40, long enough to reach Node's error line", tails)
	}
	if !strings.Contains(string(out), "realci: ext4 [1.0] EXT4-fs (dm-0): recovery complete") || !strings.Contains(string(out), "ext4_find_extent: bad header") || strings.Contains(string(out), "eth0") {
		t.Fatalf("the ext4 lines: %s", out)
	}
}
