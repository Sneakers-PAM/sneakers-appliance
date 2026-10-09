// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

func issuedFingerprint(t *testing.T, r *rig, admin string) string {
	t.Helper()
	st, err := access.ReadState(filepath.Join(r.state, "access"))
	if err != nil {
		t.Fatal(err)
	}
	a, ok := st.Admin(admin)
	if !ok || len(a.Keys) == 0 {
		t.Fatalf("no key for %s", admin)
	}
	return a.Keys[0].Fingerprint
}

// sshd logs a key it refused; when that's a box-issued key sent without
// its certificate, the refusal is audited with the key and the source, so
// :8443 shows why the login failed. Everything sshd logs still reaches
// the log, split writes and all.
func TestABareIssuedKeyIsAudited(t *testing.T) {
	r := newRig(t)
	r.writeStore("alice")
	fp := issuedFingerprint(t, r, "alice")
	var out bytes.Buffer
	w := sshdrun.NewLogWatch(sshdrun.LogWatchOptions{StateDir: r.state, Audit: r.audit, Out: &out,
		Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) }})
	lines := []string{
		"Connection from 192.0.2.50 port 50122 on 192.0.2.10 port 22 rdomain \"\"",
		"Failed publickey for alice from 192.0.2.50 port 50122 ssh2: ED25519 " + fp,
		"Failed publickey for alice from 192.0.2.50 port 50124 ssh2: ED25519-CERT " + fp + " ID alice serial=9 fp=" + fp + " (serial 9) CA ED25519 SHA256:ca",
		"Failed publickey for alice from 192.0.2.50 port 50126 ssh2: ED25519 SHA256:notOneOfOurs",
	}
	all := strings.Join(lines, "\n") + "\n"
	for i := 0; i < len(all); i += 7 {
		if _, err := w.Write([]byte(all[i:min(i+7, len(all))])); err != nil {
			t.Fatal(err)
		}
	}
	if out.String() != all {
		t.Fatalf("the log was changed:\n%s", out.String())
	}
	got := r.audit.all()
	if len(got) != 1 {
		b, _ := json.Marshal(got)
		t.Fatalf("want one audit entry, got %s", b)
	}
	e := got[0]
	if e.Action != "ssh.login" || e.Outcome != "refused" || e.Actor != "alice" || e.Source != "192.0.2.50" || e.KeyFP != fp ||
		e.Code != "ACCESS_KEY_NO_CERTIFICATE" || e.Detail["reason"] != "the box-issued key was sent without its certificate" || e.Detail["serial"] != "1" {
		t.Fatalf("audit %+v", e)
	}
}

func TestTheLogWatchNeedsNoStore(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	w := sshdrun.NewLogWatch(sshdrun.LogWatchOptions{StateDir: dir, Audit: &memAudit{}, Out: &out})
	if _, err := w.Write([]byte("Failed publickey for alice from 192.0.2.50 port 1 ssh2: ED25519 SHA256:x\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "access")); !os.IsNotExist(err) {
		t.Fatal("the watch made the store")
	}
}
