// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var setupTokenLine = regexp.MustCompile(`(?m)^\s+([A-Za-z0-9_-]{20,})\s*$`)

// setupTokenFrom is the token `sneakers setup-token` prints on a line of its
// own.
func setupTokenFrom(out string) string {
	if m := setupTokenLine.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

func TestTheSetupTokenIsReadFromTheCommandsOutput(t *testing.T) {
	out := "Sneakers setup token:\n\n    8c6qK-zLu0FcLaqc8-SXFs9LVtc6swXZGJ5wJG50NxQ\n\nUse it at https://box.example.org/admin/setup\nIt works once; after that it's removed.\nAuthenticator code: \n"
	if got := setupTokenFrom(out); got != "8c6qK-zLu0FcLaqc8-SXFs9LVtc6swXZGJ5wJG50NxQ" {
		t.Fatalf("token %q", got)
	}
	if got := setupTokenFrom("Sneakers setup token:\n\nUse it at https://box.example.org/admin/setup\n"); got != "" {
		t.Fatalf("a token from output with none: %q", got)
	}
}

// productAdmin creates the product's first admin through its own setup page,
// with the setup token the closed shell prints, so the product writes its own
// first audit records: the admin's, and the vault's seeding of its built-in
// types, which carries no attributes (the audit service stores that as JSON
// null). The data move's audit-chain check has to read a trail the product
// wrote, not only one a harness made.
func (b *realBox) productAdmin() {
	b.t.Helper()
	out, err := ssh(b.ctx, b.sshPort, b.alice, "sneakers", "setup-token")
	if err != nil {
		b.t.Fatalf("sneakers setup-token: %v: %s", err, out)
	}
	token := setupTokenFrom(out)
	if token == "" {
		b.t.Fatalf("sneakers setup-token printed no token: %s", out)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- the box's own certificate
	base := "https://127.0.0.1:" + strconv.Itoa(b.hp)
	deadline := time.Now().Add(3 * time.Minute)
	for {
		resp, err := c.Get(base + "/admin/setup")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("the product's setup page didn't answer: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
	form := url.Values{"intent": {"create"}, "username": {"realci"}, "name": {"Real CI"}, "email": {"realci@example.org"},
		"password": {"Real-ci-lab-passphrase-1!"}, "confirm": {"Real-ci-lab-passphrase-1!"}, "setupToken": {token}}
	resp, err := c.PostForm(base+"/admin/setup", form)
	if err != nil {
		b.t.Fatalf("the product's first admin: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasSuffix(resp.Header.Get("Location"), "/admin/sign-in") {
		b.t.Fatalf("the product's first admin: %s, redirect %q", resp.Status, resp.Header.Get("Location"))
	}
	b.t.Logf("the product's first admin created: its audit trail has the admin's record and the vault's seeding")
}
