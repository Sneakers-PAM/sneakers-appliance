// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productimport_test

import (
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
