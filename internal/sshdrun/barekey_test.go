// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

// The pinned sshd refuses a box-issued key sent without its certificate,
// and the log watch audits that refusal; the same key with its
// certificate logs in and isn't audited.
func TestRealSshdAuditsABareIssuedKey(t *testing.T) {
	sshd := requireSshd(t)
	u, err := user.Current()
	if err != nil || !access.ValidName(u.Username) {
		t.Skipf("the test user %q can't be an admin name", u.Username)
	}
	r := newRig(t)
	r.writeStore(u.Username)
	signer, pub := signerAndPub(t)
	st, err := access.ReadState(filepath.Join(r.state, "access"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := access.ParseLoginKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := st.Admin(u.Username)
	a.Keys = []access.AdminKey{{Key: k, Added: time.Now(), AddedBy: u.Username, Via: access.ViaIssued, Serial: 5}}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.state, "access", access.FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}

	o := r.options()
	o.Paths = realPaths(t, sshd, r.run)
	keys := filepath.Dir(o.Paths.UserCA)
	root, err := rootkey.Load(&sealer{items: map[string][]byte{}}, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(keys, rootkey.PublicFile), o.Paths.UserCA); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	o.Port = port
	o.Addresses = func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	o.Check = func(dir string) error { return sshconfig.Check(sshd, dir) }
	o.Start = sshdrun.Exec(sshd, sshdrun.NewLogWatch(sshdrun.LogWatchOptions{StateDir: r.state, Audit: r.audit, Out: os.Stderr}))
	run := sshdrun.New(o)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := run.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- run.Run(ctx, nil) }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	waitBanner(t, addr)

	now := time.Now()
	cert, err := root.IssueUserCert(pub, u.Username, 5, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := tryLogin(t, addr, u.Username, cs); err != nil {
		t.Fatalf("the key with its certificate was refused: %v", err)
	}
	if n := len(r.audit.all()); n != 0 {
		t.Fatalf("a certificate login was audited as a refusal: %+v", r.audit.all())
	}
	if err := tryLogin(t, addr, u.Username, signer); err == nil {
		t.Fatal("the bare issued key logged in")
	}
	waitFor(t, func() bool {
		for _, e := range r.audit.all() {
			if e.Action == "ssh.login" && e.Outcome == "refused" && e.KeyFP == k.Fingerprint && e.Code == "ACCESS_KEY_NO_CERTIFICATE" {
				return true
			}
		}
		return false
	})
	cancel()
	<-done
}
