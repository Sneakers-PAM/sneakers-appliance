// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/supportbundle"
)

const (
	bundleSecret   = "pl4nted-" + "box-secret-value"
	bundlePassword = "hunter2-" + "planted"
)

func bundleOptions(_ *box, o *osadmin.Options) {
	o.Support = &supportbundle.Config{
		K0s: "/slot/k0s", Kubeconfig: "/k0s/admin.conf", State: "/state", RunDir: "/run/s", Manifests: "/k0s/manifests",
		Exec: func(_ context.Context, argv []string, w io.Writer) error {
			_, err := io.WriteString(w, strings.Join(argv, " ")+" "+bundleSecret+" password="+bundlePassword+"\n")
			return err
		},
	}
	o.SupportSecrets = func() ([]string, error) { return []string{bundleSecret}, nil }
}

func bundleEntry(t *testing.T, b *box, action string) osaudit.Entry {
	t.Helper()
	all, err := b.log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Action == action {
			return all[i]
		}
	}
	t.Fatalf("no %s entry", action)
	return osaudit.Entry{}
}

func TestSupportBundleOverTheShell(t *testing.T) {
	b := newBox(t, false, bundleOptions)
	var out bytes.Buffer
	if err := b.srv.WriteSupportBundle(context.Background(), &out, osadmin.Local{Admin: "alice", KeyFP: "SHA256:x", Source: "192.0.2.9"}, supportbundle.Short); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"##### support-bundle", "form: short", "box: box1.sneakers.example.org", "##### 1. status", "timeline", "##### end "} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q isn't in:\n%s", want, text)
		}
	}
	for _, gone := range []string{bundleSecret, bundlePassword} {
		if strings.Contains(text, gone) {
			t.Fatalf("%q survived:\n%s", gone, text)
		}
	}
	e := bundleEntry(t, b, "support.bundle")
	if e.Actor != "alice" || e.KeyFP != "SHA256:x" || e.Source != "192.0.2.9" || e.Outcome != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if e.Detail["surface"] != osadmin.SurfaceSSH || e.Detail["form"] != "short" || e.Detail["bytes"] == "" || e.Detail["sections"] == "" {
		t.Fatalf("detail %+v", e.Detail)
	}
}

// The product's sections join the base's, read from the installed slot.
func TestSupportBundleRunsTheProductsSections(t *testing.T) {
	b := newBox(t, false, bundleOptions)
	b.installProduct("1.0.0")
	slot := filepath.Join(b.state, "product", "current")
	spec := "format: 2\nsupport:\n  - {title: The acme workloads, short: true, kubectl: {verb: get, resource: deployments, namespace: acme}}\n"
	if err := os.WriteFile(filepath.Join(slot, "product.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := b.srv.WriteSupportBundle(context.Background(), &out, osadmin.Local{Admin: "alice"}, supportbundle.Short); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "==== Product: ") || !strings.Contains(out.String(), ". The acme workloads\n") {
		t.Fatalf("got:\n%s", out.String())
	}
}

// A second bundle while one runs is refused, and audited.
func TestOneSupportBundleAtATime(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	b := newBox(t, false, bundleOptions, func(_ *box, o *osadmin.Options) {
		o.Support.Status = func(context.Context, io.Writer) error {
			close(entered)
			<-release
			return nil
		}
	})
	done := make(chan error, 1)
	go func() {
		done <- b.srv.WriteSupportBundle(context.Background(), io.Discard, osadmin.Local{Admin: "alice"}, supportbundle.Short)
	}()
	<-entered
	err := b.srv.WriteSupportBundle(context.Background(), io.Discard, osadmin.Local{Admin: "alice"}, supportbundle.Short)
	if !codes.Is(err, codes.NotAvailable) {
		t.Fatalf("err %v", err)
	}
	if e := bundleEntry(t, b, "support.bundle"); e.Outcome != "refused" {
		t.Fatalf("audit %+v", e)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupportBundleNotConfigured(t *testing.T) {
	b := newBox(t, false)
	if err := b.srv.WriteSupportBundle(context.Background(), io.Discard, osadmin.Local{Admin: "alice"}, supportbundle.Short); !codes.Is(err, codes.NotAvailable) {
		t.Fatalf("err %v", err)
	}
}

func TestSupportBundleDownload(t *testing.T) {
	b := newBox(t, false, bundleOptions)
	alice := b.browser()
	alice.signIn("alice")
	resp, err := alice.hc.Get(b.ts.URL + "/export/support-bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %s", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, "support-bundle-box1") || !strings.Contains(cd, ".txt") {
		t.Fatalf("disposition %s", cd)
	}
	text := string(body)
	if !strings.Contains(text, "form: full") || strings.Contains(text, bundleSecret) || strings.Contains(text, "\x1b") {
		t.Fatalf("got:\n%s", text)
	}
	e := bundleEntry(t, b, "support.bundle")
	if e.Actor != "alice" || e.Detail["surface"] != osaudit.SurfaceAdmin || e.Detail["form"] != "full" || e.Outcome != "ok" {
		t.Fatalf("audit %+v", e)
	}
}

func TestSupportBundleDownloadNeedsASession(t *testing.T) {
	b := newBox(t, false, bundleOptions)
	resp, err := b.browser().hc.Get(b.ts.URL + "/export/support-bundle")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 401 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if e := bundleEntry(t, b, "support.bundle"); e.Outcome != "refused" {
		t.Fatalf("audit %+v", e)
	}
}
