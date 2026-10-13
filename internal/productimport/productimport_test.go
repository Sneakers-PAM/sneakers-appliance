// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productimport_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productimport"
)

func manager(t *testing.T) *productimport.Manager {
	t.Helper()
	root := t.TempDir()
	tpl := filepath.Join("..", "..", "build", "product", "sneakers", "import-job.yaml")
	return &productimport.Manager{
		Dir: filepath.Join(root, "import"), UID: 65532, Stack: filepath.Join(root, "manifests", "sneakers-import"), Template: tpl,
		Chown: func(string, int, int) error { return nil },
	}
}

// finish stands in for the Job: it writes the step's output and exit code
// where sneakers-migrate's MIGRATE_OUTPUT_FILE puts them.
func finish(t *testing.T, m *productimport.Manager, job, output string, code int, extra map[string]string) {
	t.Helper()
	base := filepath.Join(m.Dir, productimport.OutDir, job)
	if err := os.WriteFile(base+".txt", []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
	for suffix, body := range extra {
		if err := os.WriteFile(base+suffix, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(base+".txt.exit", []byte(fmt.Sprintf("%d\n", code)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenMakesTheKeyOnTheBoxOnce(t *testing.T) {
	m := manager(t)
	rcpt, err := m.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.ParseX25519Recipient(rcpt); err != nil {
		t.Fatalf("recipient %q: %v", rcpt, err)
	}
	again, err := m.Open()
	if err != nil || again != rcpt {
		t.Fatalf("a second open made another key: %q %v", again, err)
	}
	st, err := os.Stat(filepath.Join(m.Dir, productimport.KeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", st, err)
	}
	b, _ := os.ReadFile(filepath.Join(m.Dir, productimport.KeyFile))
	ids, err := age.ParseIdentities(strings.NewReader(string(b)))
	if err != nil || ids[0].(*age.X25519Identity).Recipient().String() != rcpt {
		t.Fatal("the key doesn't match its recipient")
	}
}

func TestStepsRunAsJobsInTheImportStack(t *testing.T) {
	m := manager(t)
	if _, err := m.Start(productimport.Review, productimport.Options{}); !codes.Is(err, codes.NotAvailable) {
		t.Fatalf("a step before open: %v", err)
	}
	if _, err := m.Open(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(productimport.Review, productimport.Options{}); !codes.Is(err, codes.NotAvailable) || !strings.Contains(err.Error(), "bundle") {
		t.Fatalf("a step before the bundle: %v", err)
	}
	if _, err := m.Save(productimport.Bundle, strings.NewReader("age-encrypted")); err != nil {
		t.Fatal(err)
	}
	r, err := m.Start(productimport.Review, productimport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(m.Stack, "job-"+r.Job+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var job struct {
		Metadata struct{ Name string }
		Spec     struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Args []string
						Env  []struct{ Name, Value string }
					}
					Volumes []struct {
						HostPath struct{ Path string } `yaml:"hostPath"`
					}
				}
			}
		}
	}
	if err := yaml.Unmarshal(raw, &job); err != nil {
		t.Fatalf("the rendered Job isn't YAML: %v", err)
	}
	c := job.Spec.Template.Spec.Containers[0]
	if job.Metadata.Name != r.Job || strings.Join(c.Args[:1], "") != "review" || job.Spec.Template.Spec.Volumes[0].HostPath.Path != m.Dir {
		t.Fatalf("job %+v", job)
	}
	if _, err := m.Start(productimport.Check, productimport.Options{}); !codes.Is(err, codes.NotAvailable) || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("a second step while one runs: %v", err)
	}
	finish(t, m, r.Job, "12 secrets\n", 0, map[string]string{".template.json": `{"format":"sneakers-migrate-mapping"}`})
	runs, err := m.Runs()
	if err != nil || len(runs) != 1 || !runs[0].Done || runs[0].Exit != 0 || runs[0].Output != "12 secrets\n" || len(runs[0].Template) == 0 {
		t.Fatalf("runs %+v %v", runs, err)
	}

	if _, err := m.Save(productimport.Mapping, strings.NewReader("{}")); err != nil {
		t.Fatal(err)
	}
	imp, err := m.Start(productimport.Import, productimport.Options{Wipe: true, OwnerEmail: "owner@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(m.Stack, "job-"+imp.Job+".yaml"))
	for _, want := range []string{`"--mapping","/import/mapping.json"`, `"--wipe-target"`, `"--owner-email","owner@example.org"`, "/import/out/" + imp.Job + ".owner"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("the import Job lacks %s:\n%s", want, raw)
		}
	}
	finish(t, m, imp.Job, "parity ... ok\n", 0, map[string]string{".owner": "one-time-pass\n", ".report.json": `{"bundle_id":"b-1","mode":"cutover"}`})
	runs, _ = m.Runs()
	if !runs[1].HasOwner {
		t.Fatal("the owner password file isn't seen")
	}
	if rep, ok := productimport.ParseImportReport(runs[1].Report); !ok || rep.BundleID != "b-1" {
		t.Fatalf("report %+v", rep)
	}
	pw, err := m.TakeOwnerPassword(imp.Job)
	if err != nil || pw != "one-time-pass" {
		t.Fatalf("password %q %v", pw, err)
	}
	if _, err := m.TakeOwnerPassword(imp.Job); !codes.Is(err, codes.NotAvailable) {
		t.Fatalf("the password was shown twice: %v", err)
	}
	if _, err := m.TakeOwnerPassword("../../etc/passwd"); !codes.Is(err, codes.NotAvailable) {
		t.Fatalf("a path as a job: %v", err)
	}
	if _, err := m.Start(productimport.Import, productimport.Options{OwnerEmail: "not an email"}); !codes.Is(err, codes.NotAvailable) {
		t.Fatalf("a bad email: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("close left the import directory: the export and its key must go")
	}
	if left, _ := filepath.Glob(filepath.Join(m.Stack, "job-*.yaml")); len(left) != 0 {
		t.Fatalf("close left jobs %v", left)
	}
}

func TestConvertReplacesTheMappingFile(t *testing.T) {
	m := manager(t)
	if _, err := m.Open(); err != nil {
		t.Fatal(err)
	}
	for k, body := range map[productimport.Kind]string{productimport.Bundle: "b", productimport.Sheet: "s", productimport.Types: "[]", productimport.Mapping: "old"} {
		if _, err := m.Save(k, strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	r, err := m.Start(productimport.Convert, productimport.Options{Parent: "Infrastructure", Personal: "owner@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "mapping.json")); !os.IsNotExist(err) {
		t.Fatal("the old mapping file must move aside: mapping --tsv refuses to overwrite")
	}
	raw, _ := os.ReadFile(filepath.Join(m.Stack, "job-"+r.Job+".yaml"))
	var argv []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "args:") {
			_ = json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "args:"))), &argv)
		}
	}
	if strings.Join(argv, " ") != "mapping --bundle /import/bundle.age --identity /import/import.key --tsv /import/sheet.tsv --out /import/mapping.json --types /import/types.json --new-folder-parent Infrastructure --personal owner@example.org" {
		t.Fatalf("args %q", argv)
	}
}

func TestTheImportedMarker(t *testing.T) {
	p := filepath.Join(t.TempDir(), "platform", "imported.json")
	if _, ok := productimport.ReadMarker(p); ok {
		t.Fatal("a marker before any import")
	}
	if err := productimport.WriteMarker(p, productimport.Marker{BundleID: "b-1", Job: "sneakers-migrate-import-2", Mode: "cutover"}); err != nil {
		t.Fatal(err)
	}
	if mk, ok := productimport.ReadMarker(p); !ok || mk.BundleID != "b-1" {
		t.Fatalf("%+v", mk)
	}
}

// The step's log is written for a terminal; the Import page shows it as
// plain text, so colour codes are dropped when it's read.
func TestRunsDropColourCodesFromTheOutput(t *testing.T) {
	m := manager(t)
	if _, err := m.Open(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(productimport.Bundle, strings.NewReader("age-encrypted")); err != nil {
		t.Fatal(err)
	}
	r, err := m.Start(productimport.Review, productimport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	finish(t, m, r.Job, "\x1b[90m11:24:13\x1b[0m \x1b[32mINF\x1b[0m review done \x1b[36mtables=\x1b[0m29\x1b[K\n", 0, nil)
	runs, err := m.Runs()
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs %+v %v", runs, err)
	}
	if want := "11:24:13 INF review done tables=29\n"; runs[0].Output != want {
		t.Fatalf("output %q, want %q", runs[0].Output, want)
	}
}

// The step Jobs are sized for a large audit chain: sneakers-migrate holds
// every table in memory, about 2.3 KB an audit record, so an export of
// 727,000 records peaks at 1.6 GiB and twice that at 3.2 GiB.
func TestTheJobTemplateIsSizedForALargeAuditChain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "import-job.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var job struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Resources struct {
							Requests map[string]string
							Limits   map[string]string
						}
					}
				}
			}
		}
	}
	if err := yaml.Unmarshal([]byte(strings.NewReplacer("${ARGS}", "[]").Replace(string(raw))), &job); err != nil {
		t.Fatal(err)
	}
	r := job.Spec.Template.Spec.Containers[0].Resources
	if r.Requests["memory"] != "1Gi" || r.Limits["memory"] != "4Gi" {
		t.Fatalf("the step's memory is requests %s, limits %s; want 1Gi and 4Gi", r.Requests["memory"], r.Limits["memory"])
	}
}

// open is a manager with an import open and a bundle uploaded.
func open(t *testing.T, m *productimport.Manager) {
	t.Helper()
	if _, err := m.Open(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(productimport.Bundle, strings.NewReader("age-encrypted")); err != nil {
		t.Fatal(err)
	}
}

// A step whose limit doesn't fit in the box's available memory isn't
// started; one that fits is.
func TestAStepThatCantFitIsRefused(t *testing.T) {
	m := manager(t)
	open(t, m)
	m.MemAvailable = func() int64 { return 2 << 30 }
	_, err := m.Start(productimport.Review, productimport.Options{})
	if !codes.Is(err, codes.NotAvailable) || !strings.Contains(err.Error(), "4Gi") || !strings.Contains(err.Error(), "2.0 GiB") {
		t.Fatalf("a step that can't fit: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(m.Stack, "job-*.yaml")); len(left) != 0 {
		t.Fatalf("a refused step left a Job %v", left)
	}
	m.MemAvailable = func() int64 { return 9 << 30 }
	if _, err := m.Start(productimport.Review, productimport.Options{}); err != nil {
		t.Fatalf("a step that fits: %v", err)
	}
}

// A box that can't read its memory starts the step.
func TestAnUnknownMemoryDoesntRefuse(t *testing.T) {
	m := manager(t)
	open(t, m)
	m.MemAvailable = func() int64 { return -1 }
	if _, err := m.Start(productimport.Review, productimport.Options{}); err != nil {
		t.Fatal(err)
	}
}

// jobs is the cluster's answer for each step Job: kubectl get job -o json
// and get pods -o json. A Job not there answers empty.
type jobs map[string][2]string

func (j jobs) read(_ context.Context, namespace, job string) ([]byte, []byte, error) {
	if namespace != "sneakers" {
		return nil, nil, fmt.Errorf("namespace %q", namespace)
	}
	a, ok := j[job]
	if !ok {
		return nil, []byte(`{"items":[]}`), nil
	}
	return []byte(a[0]), []byte(a[1]), nil
}

const (
	failedJob  = `{"metadata":{"name":"%s"},"status":{"failed":1,"conditions":[{"type":"FailureTarget","status":"True","reason":"BackoffLimitExceeded"},{"type":"Failed","status":"True","reason":"BackoffLimitExceeded","message":"Job has reached the specified backoff limit","lastTransitionTime":"2026-10-13T10:05:00Z"}]}}`
	runningJob = `{"metadata":{"name":"%s"},"status":{"active":1}}`
	pod        = `{"items":[{"metadata":{"name":"%s-abcde"},"spec":{"containers":[{"name":"migrate","resources":{"limits":{"memory":"1Gi"},"requests":{"memory":"256Mi"}}}]},"status":{"phase":"%s","containerStatuses":[{"name":"migrate","state":%s}]}}]}`
	oomKilled  = `{"terminated":{"exitCode":137,"reason":"OOMKilled","finishedAt":"2026-10-13T10:04:59Z"}}`
)

// A step the kernel killed for its memory never writes its exit code: the
// box reads the Job, marks the step failed with 137 and says why, and a
// new step may start.
func TestAnOOMKilledStepEndsWithItsReason(t *testing.T) {
	m := manager(t)
	open(t, m)
	r, err := m.Start(productimport.Review, productimport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	m.Jobs = jobs{r.Job: {fmt.Sprintf(failedJob, r.Job), fmt.Sprintf(pod, r.Job, "Failed", oomKilled)}}.read
	runs, err := m.Runs()
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs %+v %v", runs, err)
	}
	got := runs[0]
	if !got.Done || got.Exit != 137 || got.Reason != "the review step ran out of memory (limit 1Gi)" || got.Finished.IsZero() {
		t.Fatalf("an OOMKilled step: done %v exit %d reason %q finished %v", got.Done, got.Exit, got.Reason, got.Finished)
	}
	if _, err := m.Start(productimport.Review, productimport.Options{}); err != nil {
		t.Fatalf("a step after a failed one: %v", err)
	}
	// What the box read is kept: once k0s takes the Job away the step
	// still shows how it ended.
	m.Jobs = jobs{}.read
	runs, _ = m.Runs()
	if !runs[0].Done || runs[0].Exit != 137 || runs[0].Reason != got.Reason {
		t.Fatalf("after the Job went: %+v", runs[0])
	}
}

// A Job that failed before its step wrote anything (no output, no pod
// left, or a container that ended in an error) ends the step too.
func TestAJobThatFailedBeforeWritingEndsTheStep(t *testing.T) {
	for name, c := range map[string]struct {
		pods   func(job string) string
		reason string
		exit   int
	}{
		"no pod": {func(string) string { return `{"items":[]}` }, "the review step's Job failed (BackoffLimitExceeded: Job has reached the specified backoff limit)", 1},
		"container exit": {func(job string) string {
			return fmt.Sprintf(pod, job, "Failed", `{"terminated":{"exitCode":2,"reason":"Error","finishedAt":"2026-10-13T10:04:59Z"}}`)
		}, "the review step ended with exit code 2 (Error) before it wrote its result", 2},
		"evicted": {func(job string) string {
			return `{"items":[{"metadata":{"name":"` + job + `-abcde"},"status":{"phase":"Failed","reason":"Evicted","message":"The node was low on resource: memory."}}]}`
		}, "the review step's pod was evicted (The node was low on resource: memory.)", 1},
	} {
		t.Run(name, func(t *testing.T) {
			m := manager(t)
			open(t, m)
			r, err := m.Start(productimport.Review, productimport.Options{})
			if err != nil {
				t.Fatal(err)
			}
			m.Jobs = jobs{r.Job: {fmt.Sprintf(failedJob, r.Job), c.pods(r.Job)}}.read
			runs, err := m.Runs()
			if err != nil || len(runs) != 1 {
				t.Fatalf("runs %+v %v", runs, err)
			}
			if got := runs[0]; !got.Done || got.Exit != c.exit || got.Reason != c.reason {
				t.Fatalf("done %v exit %d reason %q; want exit %d reason %q", got.Done, got.Exit, got.Reason, c.exit, c.reason)
			}
			if _, err := m.Start(productimport.Review, productimport.Options{}); err != nil {
				t.Fatalf("a step after a failed one: %v", err)
			}
		})
	}
}

// A container that ended but whose Job isn't marked failed yet ends the
// step: the Job's restart policy is Never and it takes no retry.
func TestAContainerThatEndedEndsTheStepBeforeTheJobSaysSo(t *testing.T) {
	m := manager(t)
	open(t, m)
	r, err := m.Start(productimport.Review, productimport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	m.Jobs = jobs{r.Job: {fmt.Sprintf(runningJob, r.Job), fmt.Sprintf(pod, r.Job, "Failed", oomKilled)}}.read
	runs, _ := m.Runs()
	if !runs[0].Done || runs[0].Exit != 137 {
		t.Fatalf("%+v", runs[0])
	}
}

// A step still running, or whose Job k0s hasn't applied yet, stays
// running, and no second step starts.
func TestAStepStillRunningStaysRunning(t *testing.T) {
	for name, j := range map[string]func(job string) jobs{
		"running": func(job string) jobs {
			return jobs{job: {fmt.Sprintf(runningJob, job), fmt.Sprintf(pod, job, "Running", `{"running":{"startedAt":"2026-10-13T10:00:00Z"}}`)}}
		},
		"pending":     func(job string) jobs { return jobs{job: {fmt.Sprintf(runningJob, job), `{"items":[]}`}} },
		"not applied": func(string) jobs { return jobs{} },
	} {
		t.Run(name, func(t *testing.T) {
			m := manager(t)
			open(t, m)
			r, err := m.Start(productimport.Review, productimport.Options{})
			if err != nil {
				t.Fatal(err)
			}
			m.Jobs = j(r.Job).read
			runs, err := m.Runs()
			if err != nil || len(runs) != 1 || runs[0].Done || runs[0].Reason != "" {
				t.Fatalf("runs %+v %v", runs, err)
			}
			if _, err := m.Start(productimport.Check, productimport.Options{}); !codes.Is(err, codes.NotAvailable) || !strings.Contains(err.Error(), "still running") {
				t.Fatalf("a second step while one runs: %v", err)
			}
		})
	}
}

// The step's own exit code wins over the Job's: a step that wrote it is
// done as it said, and the cluster isn't asked.
func TestTheStepsOwnExitCodeWins(t *testing.T) {
	m := manager(t)
	open(t, m)
	r, err := m.Start(productimport.Review, productimport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	m.Jobs = func(context.Context, string, string) ([]byte, []byte, error) {
		t.Fatal("the cluster was asked about a step that wrote its exit code")
		return nil, nil, nil
	}
	finish(t, m, r.Job, "bad mapping\n", 3, nil)
	runs, _ := m.Runs()
	if !runs[0].Done || runs[0].Exit != 3 || runs[0].Reason != "" {
		t.Fatalf("%+v", runs[0])
	}
}

// A Job the box can't read leaves the step as it was.
func TestAJobThatCantBeReadLeavesTheStepRunning(t *testing.T) {
	m := manager(t)
	open(t, m)
	if _, err := m.Start(productimport.Review, productimport.Options{}); err != nil {
		t.Fatal(err)
	}
	m.Jobs = func(context.Context, string, string) ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("the API server is down")
	}
	runs, err := m.Runs()
	if err != nil || runs[0].Done {
		t.Fatalf("runs %+v %v", runs, err)
	}
}
