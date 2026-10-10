// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

const importYAML = valuesYAML + `switches:
  - name: import
    label: Import from an earlier Sneakers
    stacks: [sneakers-import]
import:
  label: Import from an earlier Sneakers
  switch: import
  job: import/job.yaml
  uid: 65532
  setup: setup-token
  restart: [sneakers/deployment/sneakers-vault]
`

const importJob = "apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: ${JOB_NAME}\nspec:\n  template:\n    spec:\n      containers:\n        - name: migrate\n          image: example.org/sneakers-migrate@sha256:00\n          args: ${ARGS}\n      volumes:\n        - name: import\n          hostPath: {path: ${HOST_DIR}}\n"

type importBox struct {
	b        *box
	sw       *productswitch.Switches
	restarts []string
}

func newImportBox(t *testing.T, mods ...func(*box, *osadmin.Options)) *importBox {
	t.Helper()
	ib := &importBox{}
	k := &fakeKube{secrets: map[string]map[string]string{"sneakers/sneakers-setup-token": {"SETUP_TOKEN": "stp_value"}}, state: `{"needsSetup": true}`}
	ib.b = newBox(t, true, func(b *box, o *osadmin.Options) {
		o.Exposed = k
		o.ImportChown = func(string, int, int) error { return nil }
		ib.sw = &productswitch.Switches{Dir: filepath.Join(b.state, "platform"), Slot: filepath.Join(b.state, "product", "current"), Manifests: filepath.Join(b.state, "k0s-manifests"),
			Restart: func(_ context.Context, ns, kind, name string) error {
				ib.restarts = append(ib.restarts, ns+"/"+kind+"/"+name)
				return nil
			}}
		o.Switches = ib.sw
		for _, m := range mods {
			m(b, o)
		}
	})
	dir := filepath.Join(ib.b.state, "product")
	installProduct(t, dir, importYAML)
	for p, body := range map[string]string{"manifests/sneakers-import/sa.yaml": "kind: ServiceAccount\n", "import/job.yaml": importJob} {
		full := filepath.Join(dir, "a", p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(ib.sw.Manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	return ib
}

func (br *browser) importUpload(t *testing.T, kind string, body []byte) int {
	t.Helper()
	resp, err := br.hc.Post(br.b.ts.URL+"/import/upload?kind="+kind, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// stepDone stands in for the Job: the step's output and exit code, where
// MIGRATE_OUTPUT_FILE puts them.
func (ib *importBox) stepDone(t *testing.T, job string, code int, extra map[string]string) {
	t.Helper()
	base := filepath.Join(ib.b.state, "import", "out", job)
	files := map[string]string{".txt": "done\n"}
	for k, v := range extra {
		files[k] = v
	}
	files[".txt.exit"] = fmt.Sprintf("%d\n", code)
	for _, suffix := range []string{".txt", ".report.json", ".owner", ".txt.exit"} {
		if body, ok := files[suffix]; ok {
			if err := os.WriteFile(base+suffix, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// The Import page: an import opens with a step-up (the switch on, the key
// made on the box), takes the export and the mapping, runs each step as a
// Job in the import stack, marks the box imported and restarts the vault
// once an import passes, shows the first admin's password once, and on
// close takes the switch, the export and its key away.
func TestTheImportPageRunsAnImport(t *testing.T) {
	ib := newImportBox(t)
	ctx := context.Background()
	alice := ib.b.browser()
	alice.signIn("alice")
	ic := osadminv1connect.NewImportServiceClient(alice.hc, ib.b.ts.URL)
	g, err := ic.GetImport(ctx, connect.NewRequest(&osadminv1.GetImportRequest{}))
	if err != nil || !g.Msg.GetAvailable() || g.Msg.GetOpen() || g.Msg.GetSetupDone() || g.Msg.GetImported() {
		t.Fatalf("%v %v", g, err)
	}
	if code := alice.importUpload(t, "bundle", []byte("x")); code != http.StatusBadRequest {
		t.Fatalf("an upload before open: %d", code)
	}
	ib.b.clk.Advance(6 * time.Minute)
	_, err = ic.OpenImport(ctx, connect.NewRequest(&osadminv1.OpenImportRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	alice.stepUp("alice")
	open, err := ic.OpenImport(ctx, connect.NewRequest(&osadminv1.OpenImportRequest{}))
	if err != nil || !strings.HasPrefix(open.Msg.GetRecipient(), "age1") {
		t.Fatalf("%v %v", open, err)
	}
	if _, err := os.Stat(filepath.Join(ib.sw.Manifests, "sneakers-import", "sa.yaml")); err != nil {
		t.Fatalf("the import stack isn't in front of k0s: %v", err)
	}
	if code := alice.importUpload(t, "bundle", []byte("age-encrypted export")); code != http.StatusOK {
		t.Fatalf("bundle upload: %d", code)
	}
	if code := alice.importUpload(t, "mapping", []byte(`{"format":"sneakers-migrate-mapping"}`)); code != http.StatusOK {
		t.Fatalf("mapping upload: %d", code)
	}
	if e := lastEntry(t, ib.b.log, "import.upload"); e.Outcome != "ok" || e.Target != "mapping" {
		t.Fatalf("audit %+v", e)
	}
	if code := alice.importUpload(t, "passwords", []byte("x")); code != http.StatusBadRequest {
		t.Fatalf("an unknown kind: %d", code)
	}

	run, err := ic.RunImportStep(ctx, connect.NewRequest(&osadminv1.RunImportStepRequest{Step: "import", Wipe: true, OwnerEmail: "owner@example.org"}))
	if err != nil {
		t.Fatal(err)
	}
	job := run.Msg.GetJob()
	raw, err := os.ReadFile(filepath.Join(ib.sw.Manifests, "sneakers-import", "job-"+job+".yaml"))
	if err != nil || !strings.Contains(string(raw), `"--owner-email","owner@example.org"`) || !strings.Contains(string(raw), filepath.Join(ib.b.state, "import")) {
		t.Fatalf("job %s: %s %v", job, raw, err)
	}
	if e := lastEntry(t, ib.b.log, "import.run"); e.Outcome != "ok" || e.Detail["step"] != "import" {
		t.Fatalf("audit %+v", e)
	}
	ib.stepDone(t, job, 0, map[string]string{".report.json": `{"bundle_id":"b-42","mode":"cutover"}`, ".owner": "one-time-pass\n"})
	g, _ = ic.GetImport(ctx, connect.NewRequest(&osadminv1.GetImportRequest{}))
	r := g.Msg.GetRuns()[0]
	if r.GetState() != "passed" || !r.GetOwnerPasswordWaiting() || !g.Msg.GetImported() || g.Msg.GetImportedBundle() != "b-42" || len(ib.restarts) != 1 || ib.restarts[0] != "sneakers/deployment/sneakers-vault" {
		t.Fatalf("after the import: %v restarts %v", g.Msg, ib.restarts)
	}
	if _, err := ic.GetImport(ctx, connect.NewRequest(&osadminv1.GetImportRequest{})); err != nil || len(ib.restarts) != 1 {
		t.Fatalf("the vault restarted twice for one import: %v", ib.restarts)
	}
	pw, err := ic.TakeOwnerPassword(ctx, connect.NewRequest(&osadminv1.TakeOwnerPasswordRequest{Job: job}))
	if err != nil || pw.Msg.GetPassword() != "one-time-pass" {
		t.Fatalf("%v %v", pw, err)
	}
	if _, err := ic.TakeOwnerPassword(ctx, connect.NewRequest(&osadminv1.TakeOwnerPasswordRequest{Job: job})); err == nil {
		t.Fatal("the password was shown twice")
	}
	es, _ := ib.b.log.Entries()
	for _, e := range es {
		if strings.Contains(fmt.Sprint(e), "one-time-pass") {
			t.Fatal("the audit carries the password")
		}
	}

	// Imported-users mode: the product's own setup token is done with.
	pc := osadminv1connect.NewProductServiceClient(alice.hc, ib.b.ts.URL)
	lv, err := pc.ListExposedValues(ctx, connect.NewRequest(&osadminv1.ListExposedValuesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range lv.Msg.GetValues() {
		if v.GetName() == "setup-token" && !v.GetConsumed() {
			t.Fatal("an imported box still offers the product's setup token")
		}
	}

	if _, err := ic.CloseImport(ctx, connect.NewRequest(&osadminv1.CloseImportRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ib.b.state, "import")); !os.IsNotExist(err) {
		t.Fatal("close left the export and its key")
	}
	if _, err := os.Stat(filepath.Join(ib.sw.Manifests, "sneakers-import")); !os.IsNotExist(err) {
		t.Fatal("close left the import stack in front of k0s")
	}
	// A re-import still opens on an imported box.
	if _, err := ic.OpenImport(ctx, connect.NewRequest(&osadminv1.OpenImportRequest{})); err != nil {
		t.Fatalf("a re-import: %v", err)
	}
}

// Once the product's own setup is done (and the box wasn't imported), no
// import opens.
func TestNoImportOpensAfterTheProductsOwnSetup(t *testing.T) {
	ib := newImportBox(t)
	marker := filepath.Join(ib.b.state, "osadmin-api", "exposed", "sneakers-setup-token.consumed")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	alice := ib.b.browser()
	alice.signIn("alice")
	ic := osadminv1connect.NewImportServiceClient(alice.hc, ib.b.ts.URL)
	g, err := ic.GetImport(ctx, connect.NewRequest(&osadminv1.GetImportRequest{}))
	if err != nil || !g.Msg.GetSetupDone() || g.Msg.GetReason() == "" {
		t.Fatalf("%v %v", g, err)
	}
	_, err = ic.OpenImport(ctx, connect.NewRequest(&osadminv1.OpenImportRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "NOT_AVAILABLE")
	if e := lastEntry(t, ib.b.log, "import.open"); e.Outcome == "ok" {
		t.Fatalf("audit %+v", e)
	}
}

// The vault restarts once an import passes, so Verify waits until the
// product is ready again: while it rolls out, Verify is refused with what
// it waits for, and runs once it's ready.
func TestVerifyWaitsForTheProductToBeReady(t *testing.T) {
	p := &fakeProbe{}
	ib := newImportBox(t, withProbe(p))
	ctx := context.Background()
	alice := ib.b.browser()
	alice.signIn("alice")
	alice.stepUp("alice")
	ic := osadminv1connect.NewImportServiceClient(alice.hc, ib.b.ts.URL)
	if _, err := ic.OpenImport(ctx, connect.NewRequest(&osadminv1.OpenImportRequest{})); err != nil {
		t.Fatal(err)
	}
	if alice.importUpload(t, "bundle", []byte("age-encrypted export")) != http.StatusOK || alice.importUpload(t, "mapping", []byte(`{"format":"sneakers-migrate-mapping"}`)) != http.StatusOK {
		t.Fatal("the uploads failed")
	}
	run, err := ic.RunImportStep(ctx, connect.NewRequest(&osadminv1.RunImportStepRequest{Step: "import", Wipe: true, OwnerEmail: "owner@example.org"}))
	if err != nil {
		t.Fatal(err)
	}
	ib.stepDone(t, run.Msg.GetJob(), 0, map[string]string{".report.json": `{"bundle_id":"b-42","mode":"cutover"}`})
	if _, err := ic.GetImport(ctx, connect.NewRequest(&osadminv1.GetImportRequest{})); err != nil || len(ib.restarts) != 1 {
		t.Fatalf("the vault didn't restart: %v %v", ib.restarts, err)
	}
	p.set("pods", "Rolling out (4 of 5 ready): waiting for app/vault, 0 of 1 updated, 1 running", nil)
	_, err = ic.RunImportStep(ctx, connect.NewRequest(&osadminv1.RunImportStepRequest{Step: "verify"}))
	if err == nil || !strings.Contains(err.Error(), "PRODUCT_NOT_READY") || !strings.Contains(err.Error(), "waiting for app/vault") {
		t.Fatalf("verify while the product rolls out: %v", err)
	}
	p.set("", "", nil)
	if _, err := ic.RunImportStep(ctx, connect.NewRequest(&osadminv1.RunImportStepRequest{Step: "verify"})); err != nil {
		t.Fatalf("verify once the product is ready: %v", err)
	}
}
