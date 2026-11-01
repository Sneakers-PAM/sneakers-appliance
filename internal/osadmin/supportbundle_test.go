// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// bundleZip reads a download's one entry, and how it was stored.
func bundleZip(t *testing.T, body []byte) (*zip.File, string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("%d entries", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	text, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return zr.File[0], string(text)
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
	if ct := resp.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content type %s", ct)
	}
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatal(err)
	}
	name := params["filename"]
	if !strings.HasPrefix(name, "support-bundle-box1-") || !strings.HasSuffix(name, "Z.zip") {
		t.Fatalf("file name %s", name)
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("disposition %s", resp.Header.Get("Content-Disposition"))
	}
	f, text := bundleZip(t, body)
	if f.Name != strings.TrimSuffix(name, ".zip")+".txt" {
		t.Fatalf("entry %s, file %s", f.Name, name)
	}
	if f.Method != zip.Deflate {
		t.Fatalf("method %d", f.Method)
	}
	if f.Flags&0x1 != 0 {
		t.Fatal("the entry is encrypted")
	}
	if f.Modified.IsZero() {
		t.Fatal("the entry has no time")
	}
	if !strings.Contains(text, "form: full") || !strings.Contains(text, "##### end ") || strings.Contains(text, bundleSecret) || strings.Contains(text, "\x1b") {
		t.Fatalf("got:\n%s", text)
	}
	e := bundleEntry(t, b, "support.bundle")
	if e.Actor != "alice" || e.Detail["surface"] != osaudit.SurfaceAdmin || e.Detail["form"] != "full" || e.Outcome != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if e.Detail["bytes"] != strconv.Itoa(len(text)) {
		t.Fatalf("audit bytes %s, text %d", e.Detail["bytes"], len(text))
	}
}

// The entry comes out about the size of one pass at the best level.
func TestSupportBundleDownloadIsCompressed(t *testing.T) {
	b := newBox(t, false, bundleOptions, func(_ *box, o *osadmin.Options) {
		o.Support.Status = func(_ context.Context, w io.Writer) error {
			words := []string{"pod", "restart", "volume", "gateway", "ready", "mount", "probe", "lease", "token_type", "sync"}
			r := rand.New(rand.NewPCG(1, 2))
			for range 100000 {
				if _, err := fmt.Fprintf(w, "%s %s %s id=%d\n", words[r.IntN(10)], words[r.IntN(10)], words[r.IntN(10)], r.IntN(1000)); err != nil {
					return err
				}
			}
			return nil
		}
	})
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
	f, text := bundleZip(t, body)
	var best bytes.Buffer
	fw, err := flate.NewWriter(&best, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, text); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	var def bytes.Buffer
	fd, err := flate.NewWriter(&def, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fd, text); err != nil {
		t.Fatal(err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	// The sections' flushes add a few bytes each to what one pass makes.
	limit := uint64(best.Len()) + 512
	if limit >= uint64(def.Len()) {
		t.Fatalf("this text can't tell the levels apart: best %d, default %d", best.Len(), def.Len())
	}
	if f.CompressedSize64 > limit {
		t.Fatalf("%d compressed, one pass at the best level makes %d", f.CompressedSize64, best.Len())
	}
}

// A refused bundle is the plain 503 the pages read, with nothing of a zip
// sent: not a type, not a file name, not a byte.
func TestSupportBundleDownloadRefusedWhileOneRuns(t *testing.T) {
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
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d: %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type %s", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		t.Fatalf("disposition %s", cd)
	}
	if !strings.Contains(string(body), "a support bundle is being made") || bytes.HasPrefix(body, []byte("PK")) {
		t.Fatalf("body %q", body)
	}
}

// The forwarder gives accessd two minutes to answer, and deflate holds on
// to what it's given, so the zip has to pass the bundle's flushes on: the
// answer starts before the first section ends.
func TestSupportBundleDownloadStreams(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	b := newBox(t, false, bundleOptions, func(_ *box, o *osadmin.Options) {
		o.Support.Status = func(context.Context, io.Writer) error {
			close(entered)
			<-release
			return nil
		}
	})
	alice := b.browser()
	alice.signIn("alice")
	type answer struct {
		resp *http.Response
		err  error
	}
	got := make(chan answer, 1)
	go func() {
		resp, err := alice.hc.Get(b.ts.URL + "/export/support-bundle")
		got <- answer{resp, err}
	}()
	<-entered
	var resp *http.Response
	select {
	case a := <-got:
		if a.err != nil {
			close(release)
			t.Fatal(a.err)
		}
		resp = a.resp
	case <-time.After(10 * time.Second):
		close(release)
		a := <-got
		if a.err == nil {
			_ = a.resp.Body.Close()
		}
		t.Fatal("no answer until the section ended")
	}
	defer func() { _ = resp.Body.Close() }()
	head := make([]byte, 4)
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(resp.Body, head)
		read <- err
	}()
	select {
	case err := <-read:
		close(release)
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("no bytes until the section ended")
	}
	if string(head) != "PK\x03\x04" {
		t.Fatalf("starts %q", head)
	}
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, text := bundleZip(t, append(head, rest...)); !strings.Contains(text, "##### end ") {
		t.Fatalf("got:\n%s", text)
	}
}

// A request that ends part way stops the sections, and what was written
// is still a zip that opens.
func TestSupportBundleDownloadCutShortIsAValidZip(t *testing.T) {
	entered := make(chan struct{})
	b := newBox(t, false, bundleOptions, func(_ *box, o *osadmin.Options) {
		o.Support.Status = func(ctx context.Context, w io.Writer) error {
			_, _ = io.WriteString(w, "written before the cut\n")
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
	})
	alice := b.browser()
	alice.signIn("alice")
	u, err := url.Parse(b.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/export/support-bundle", nil)
	for _, c := range alice.hc.Jar.Cookies(u) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	go func() {
		<-entered
		cancel()
	}()
	b.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	_, text := bundleZip(t, rec.Body.Bytes())
	if !strings.Contains(text, "written before the cut") || !strings.Contains(text, "# skipped: the bundle's time limit") {
		t.Fatalf("got:\n%s", text)
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
