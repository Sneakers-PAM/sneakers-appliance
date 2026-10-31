// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type bundleAccessd struct {
	body   string
	status int
	form   string
	key    string
	source string
}

func (f *bundleAccessd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.form, f.key, f.source = r.URL.Query().Get("form"), r.Header.Get(accessapi.KeyHeader), r.Header.Get(accessapi.SourceHeader)
	if r.URL.Path != accessapi.SupportBundlePath {
		http.NotFound(w, r)
		return
	}
	if f.status != 0 {
		http.Error(w, f.body, f.status)
		return
	}
	_, _ = io.WriteString(w, f.body)
}

func runBundleOver(t *testing.T, f *bundleAccessd, line string) (string, string, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	s.UseBundleClient(http.DefaultClient, srv.URL)
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: s, In: strings.NewReader(""), Out: &out, Err: &errb}
	err := shell.Run(context.Background(), e, line)
	return out.String(), errb.String(), err
}

// The text comes straight through, and accessd learns who asked: the audit
// entry names the login's key and the SSH client's address.
func TestSupportBundleStreamsFromAccessd(t *testing.T) {
	f := &bundleAccessd{body: "##### support-bundle\nthe rest\n"}
	out, _, err := runBundleOver(t, f, "support-bundle full")
	if err != nil || out != f.body {
		t.Fatalf("%v %q", err, out)
	}
	if f.form != "full" {
		t.Fatalf("form %q", f.form)
	}
	if f.key != "SHA256:abc" || f.source != "192.0.2.60" {
		t.Fatalf("key %q source %q", f.key, f.source)
	}
	if _, _, err := runBundleOver(t, f, "support-bundle"); err != nil || f.form == "full" {
		t.Fatalf("%v form %q", err, f.form)
	}
}

// A refusal reads as one, with nothing on standard output.
func TestSupportBundleRefusalReadsAsOne(t *testing.T) {
	f := &bundleAccessd{status: http.StatusServiceUnavailable, body: "a support bundle is being made; try again when it's done"}
	out, stderr, err := runBundleOver(t, f, "support-bundle")
	if !codes.Is(err, codes.NotAvailable) || out != "" || !strings.Contains(stderr, "a support bundle is being made") {
		t.Fatalf("%v out %q err %q", err, out, stderr)
	}
	f = &bundleAccessd{status: http.StatusForbidden, body: "this login isn't an admin"}
	if _, _, err := runBundleOver(t, f, "support-bundle"); !codes.Is(err, codes.AccessForbidden) {
		t.Fatalf("%v", err)
	}
}
