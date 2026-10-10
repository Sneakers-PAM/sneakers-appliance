// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func relayEmail() Email {
	return Email{Host: "relay.example.org", Port: 587, From: "no-reply@sneakers.example.org", Username: "mailer", Password: "p@ss:w/rd", TLS: TLSStartTLS, Verify: true}
}

// With nothing saved the box has no relay, and every setting still has a
// value, so no placeholder is ever left in a stack.
func TestNoRelayIsTheDefault(t *testing.T) {
	st := &Store{Dir: t.TempDir()}
	e, err := st.Email()
	if err != nil {
		t.Fatal(err)
	}
	if e.Host != "" || e.Port != 587 || e.TLS != TLSStartTLS || !e.Verify || e.Configured() {
		t.Fatalf("default = %+v", e)
	}
	v := e.Values()
	for _, name := range []string{productspec.SettingEmailHost, productspec.SettingEmailPort, productspec.SettingEmailFrom, productspec.SettingEmailUsername,
		productspec.SettingEmailTLS, productspec.SettingEmailSkipVerify, productspec.SettingEmailCA, productspec.SettingEmailPassword, productspec.SettingEmailURI} {
		if _, ok := v[name]; !ok {
			t.Errorf("no value for %s", name)
		}
	}
	if v[productspec.SettingEmailHost] != "" || v[productspec.SettingEmailPort] != "587" || v[productspec.SettingEmailSkipVerify] != "false" {
		t.Errorf("values = %v", v)
	}
	if u := v[productspec.SettingEmailURI]; !strings.HasPrefix(u, "smtp://localhost:25/") {
		t.Errorf("the URI with no relay = %q", u)
	}
}

// Saved settings are kept 0600 (they hold the password) and read back.
func TestTheSettingsAreKept(t *testing.T) {
	dir := t.TempDir()
	st := &Store{Dir: dir}
	e := relayEmail()
	e.CA = testCA(t)
	if err := st.SetEmail(e); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, File))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	got, err := (&Store{Dir: dir}).Email()
	if err != nil {
		t.Fatal(err)
	}
	if got != e {
		t.Fatalf("got %+v, want %+v", got, e)
	}
	v, err := st.Values()
	if err != nil {
		t.Fatal(err)
	}
	if v[productspec.SettingEmailPassword] != e.Password || v[productspec.SettingEmailCA] != e.CA {
		t.Fatal("the values aren't the saved ones")
	}
}

// Every TLS mode, with verify on or off, comes out the same way to the
// product's sender (its settings) and to Ory's courier (the URI).
func TestTheValuesFollowEveryMode(t *testing.T) {
	for _, c := range []struct {
		tls    string
		verify bool
		scheme string
		query  url.Values
	}{
		{TLSNone, false, "smtp", url.Values{"disable_starttls": {"true"}, "skip_ssl_verify": {"true"}}},
		{TLSNone, true, "smtp", url.Values{"disable_starttls": {"true"}}},
		{TLSStartTLS, true, "smtp", url.Values{}},
		{TLSStartTLS, false, "smtp", url.Values{"skip_ssl_verify": {"true"}}},
		{TLSImplicit, true, "smtps", url.Values{}},
		{TLSImplicit, false, "smtps", url.Values{"skip_ssl_verify": {"true"}}},
	} {
		e := relayEmail()
		e.TLS, e.Verify = c.tls, c.verify
		v := e.Values()
		if v[productspec.SettingEmailTLS] != c.tls || v[productspec.SettingEmailSkipVerify] != map[bool]string{true: "false", false: "true"}[c.verify] {
			t.Errorf("%s verify %v: values %v", c.tls, c.verify, v)
		}
		u, err := url.Parse(v[productspec.SettingEmailURI])
		if err != nil {
			t.Fatal(err)
		}
		pass, _ := u.User.Password()
		if u.Scheme != c.scheme || u.Host != "relay.example.org:587" || u.User.Username() != "mailer" || pass != e.Password || u.Query().Encode() != c.query.Encode() {
			t.Errorf("%s verify %v: URI %s", c.tls, c.verify, u.Redacted())
		}
	}
	e := relayEmail()
	e.Username, e.Password = "", ""
	if u, _ := url.Parse(e.URI()); u.User != nil {
		t.Errorf("a relay with no account has userinfo: %s", u.Redacted())
	}
}

func TestBadSettingsAreRefused(t *testing.T) {
	for name, f := range map[string]func(*Email){
		"a host with a space":          func(e *Email) { e.Host = "relay example" },
		"a port of 0":                  func(e *Email) { e.Port = 0 },
		"a port over 65535":            func(e *Email) { e.Port = 70000 },
		"no from address":              func(e *Email) { e.From = "" },
		"a from that isn't an address": func(e *Email) { e.From = "Mailer" },
		"a from with a name":           func(e *Email) { e.From = "Mailer <no-reply@sneakers.example.org>" },
		"an unknown TLS mode":          func(e *Email) { e.TLS = "ssl" },
		"a CA that isn't PEM":          func(e *Email) { e.CA = "not a certificate" },
		"a password with no username":  func(e *Email) { e.Username = "" },
		"a username with a newline":    func(e *Email) { e.Username = "a\r\nRCPT TO:<x@example.org>" },
		"a password with a newline":    func(e *Email) { e.Password = "a\nb" },
	} {
		e := relayEmail()
		f(&e)
		if err := e.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := (&Store{Dir: t.TempDir()}).SetEmail(e); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
	if err := (Email{Port: 587, TLS: TLSStartTLS}).Check(); err != nil {
		t.Errorf("no relay is refused: %v", err)
	}
	e := relayEmail()
	e.Host = "192.0.2.25"
	if err := e.Check(); err != nil {
		t.Errorf("an address as the host: %v", err)
	}
}

// The test email goes out the way the product's mail will, in every mode.
func TestSendTestEmailInEveryMode(t *testing.T) {
	for _, c := range []struct {
		name               string
		tls                string
		implicit, starttls bool
		ca, verify         bool
		wantTLS            bool
	}{
		{"none, authenticated", TLSNone, false, false, false, false, false},
		{"starttls with the relay's CA", TLSStartTLS, false, true, true, true, true},
		{"starttls, verify off", TLSStartTLS, false, true, false, false, true},
		{"implicit tls with the relay's CA", TLSImplicit, true, false, true, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRelay(t, c.implicit, c.starttls, "PLAIN", "LOGIN")
			e := Email{Host: "127.0.0.1", Port: r.port(), From: "no-reply@sneakers.example.org", Username: r.user, Password: r.pass, TLS: c.tls, Verify: c.verify}
			if c.ca {
				e.CA = r.caPEM
			}
			if _, err := Send(context.Background(), e, "admin@example.org"); err != nil {
				t.Fatalf("Send: %v", err)
			}
			s := onlySession(t, r)
			if s.tls != c.wantTLS || s.authUser != r.user || s.rcpt != "admin@example.org" || !strings.Contains(s.data, "Subject: ") {
				t.Fatalf("session %+v", s)
			}
		})
	}
}

func TestSendTestEmailSaysWhatWentWrong(t *testing.T) {
	r := newRelay(t, false, true, "PLAIN")
	e := Email{Host: "127.0.0.1", Port: r.port(), From: "no-reply@sneakers.example.org", TLS: TLSStartTLS, Verify: true}
	if _, err := Send(context.Background(), e, "admin@example.org"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an unknown CA: %v", err)
	}
	e.TLS = TLSNone
	e.Username, e.Password = r.user, "wrong"
	if _, err := Send(context.Background(), e, "admin@example.org"); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("bad credentials: %v (the password must never be in the error)", err)
	}
	if _, err := Send(context.Background(), relayEmail(), "not an address"); err == nil {
		t.Fatal("a bad recipient is accepted")
	}
	if _, err := Send(context.Background(), Email{Port: 587, TLS: TLSStartTLS}, "admin@example.org"); err == nil {
		t.Fatal("no relay sends")
	}
}

func onlySession(t *testing.T, r *relay) session {
	t.Helper()
	got := r.sessions()
	if len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	return got[0]
}

func testCA(t *testing.T) string {
	t.Helper()
	_, ca := testCert(t)
	return ca
}
