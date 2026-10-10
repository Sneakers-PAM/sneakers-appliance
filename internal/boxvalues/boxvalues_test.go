// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxvalues_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// The FQDN is the host name netd reports (the setting, else DHCP's name
// and domain), else the first management address, else the box's own name.
func TestTheFQDNFallsBackFromTheHostNameToAnAddressToTheOwnName(t *testing.T) {
	for _, c := range []struct {
		host  string
		addrs []string
		want  string
	}{
		{"sneakers.example.org", []string{"192.0.2.10"}, "sneakers.example.org"},
		{"Sneakers.Example.org.", nil, "sneakers.example.org"},
		{"", []string{"192.0.2.10", "2001:db8::10"}, "192.0.2.10"},
		{"", []string{"2001:db8::10"}, "[2001:db8::10]"},
		{"", nil, "sneakers-0a1b2c3d"},
	} {
		if got := boxvalues.FQDN(c.host, c.addrs, "sneakers-0a1b2c3d"); got != c.want {
			t.Errorf("FQDN(%q, %v) = %q, want %q", c.host, c.addrs, got, c.want)
		}
	}
}

func slot(t *testing.T, placeholders string) string {
	t.Helper()
	dir := t.TempDir()
	if placeholders != "" {
		if err := os.WriteFile(filepath.Join(dir, productspec.BoxValuesFile), []byte(placeholders), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// placeholder is the Sneakers bundle's.
const placeholder = "sneakers.box.invalid" // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved

var stack = strings.ReplaceAll(`env:
  - name: OAUTH_PUBLIC_URL
    value: https://PH
  - name: HYDRA_ISSUER
    value: https://PH/oauth
  - name: SMTP_FROM
    value: no-reply@PH
`, "PH", placeholder)

// A stack's placeholders become the box's values; a slot that declares
// none is copied as it is.
func TestSubstituteReplacesEveryPlaceholder(t *testing.T) {
	s := slot(t, placeholder+" box.fqdn\n")
	tbl := boxvalues.Table(s, map[string]string{productspec.BoxFQDN: "box1.example.org"}, "unused")
	got := string(boxvalues.Substitute([]byte(stack), tbl))
	want := `env:
  - name: OAUTH_PUBLIC_URL
    value: https://box1.example.org
  - name: HYDRA_ISSUER
    value: https://box1.example.org/oauth
  - name: SMTP_FROM
    value: no-reply@box1.example.org
`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if got := boxvalues.Substitute([]byte(stack), boxvalues.Table(slot(t, ""), nil, "x")); string(got) != stack {
		t.Fatalf("a slot with no box values changed the stack:\n%s", got)
	}
	// With no FQDN recorded yet (a box whose product came before box
	// values), the kernel's host name stands in.
	tbl = boxvalues.Table(s, nil, "sneakers-0a1b2c3d")
	if got := string(boxvalues.Substitute([]byte("h: "+placeholder+"\n"), tbl)); got != "h: sneakers-0a1b2c3d\n" {
		t.Fatalf("fallback: %q", got)
	}
}

func TestTheValuesAreKeptOnTheStateVolume(t *testing.T) {
	dir := t.TempDir()
	if got := boxvalues.Read(dir); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if err := boxvalues.Write(dir, map[string]string{productspec.BoxFQDN: "box1.example.org"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, boxvalues.File))
	if err != nil || string(b) != "box.fqdn box1.example.org\n" {
		t.Fatalf("%q %v", b, err)
	}
	if got := boxvalues.Read(dir)[productspec.BoxFQDN]; got != "box1.example.org" {
		t.Fatalf("%q", got)
	}
}

// Box records the FQDN the product's stacks were put in place with, and
// says whether the box's names moved on since.
func TestTheBoxRecordsItsFQDN(t *testing.T) {
	dir := t.TempDir()
	host := ""
	b := &boxvalues.Box{
		Dir:   dir,
		Names: func(context.Context) (string, []string, error) { return host, []string{"192.0.2.10"}, nil },
		Own:   func() string { return "sneakers-0a1b2c3d" },
	}
	ctx := context.Background()
	if got, err := b.FQDN(ctx); err != nil || got != "192.0.2.10" {
		t.Fatalf("%q %v", got, err)
	}
	if b.Recorded() != "" {
		t.Fatal("a value before Record")
	}
	got, changed, err := b.Ensure(ctx)
	if err != nil || got != "192.0.2.10" || !changed || b.Recorded() != "192.0.2.10" {
		t.Fatalf("%q %v %v", got, changed, err)
	}
	if _, changed, _ := b.Ensure(ctx); changed {
		t.Fatal("changed with nothing new")
	}
	host = "box1.example.org"
	if got, changed, err := b.Ensure(ctx); err != nil || got != "box1.example.org" || !changed {
		t.Fatalf("%q %v %v", got, changed, err)
	}
	// netd not answering keeps what was recorded.
	b.Names = func(context.Context) (string, []string, error) { return "", nil, errors.New("down") }
	if _, _, err := b.Ensure(ctx); err == nil || b.Recorded() != "box1.example.org" {
		t.Fatalf("%v %q", err, b.Recorded())
	}
}

// RecordVersions keeps the Base OS and Base Web versions next to the FQDN,
// for the stacks k0s-interim and productswitch put in place; a version
// that couldn't be used as stack text is left out, and the FQDN stays.
func TestTheBoxRecordsItsVersions(t *testing.T) {
	dir := t.TempDir()
	if err := boxvalues.Write(dir, map[string]string{productspec.BoxFQDN: "box1.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := boxvalues.RecordVersions(dir, "0.1.0-m", "0.1.0-m+web.2"); err != nil {
		t.Fatal(err)
	}
	got := boxvalues.Read(dir)
	if got[productspec.BoxFQDN] != "box1.example.org" || got[productspec.BoxOSVersion] != "0.1.0-m" || got[productspec.BoxWebVersion] != "0.1.0-m+web.2" {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"", "0.1.0 m", "0.1.0/m", "0.1.0&m", `0.1.0\m`, strings.Repeat("1", 65)} {
		if err := boxvalues.RecordVersions(dir, bad, bad); err != nil {
			t.Fatal(err)
		}
		got := boxvalues.Read(dir)
		if _, ok := got[productspec.BoxOSVersion]; ok {
			t.Fatalf("%q: recorded %v", bad, got)
		}
		if _, ok := got[productspec.BoxWebVersion]; ok {
			t.Fatalf("%q: recorded %v", bad, got)
		}
		if got[productspec.BoxFQDN] != "box1.example.org" {
			t.Fatalf("%q: the FQDN went: %v", bad, got)
		}
	}
}

// The box's versions go into a stack like its FQDN.
func TestTheVersionsReachTheStacks(t *testing.T) {
	slot := t.TempDir()
	if err := os.WriteFile(filepath.Join(slot, productspec.BoxValuesFile), []byte("baseos-version.invalid box.os.version\nbaseweb-version.invalid box.web.version\n"), 0o644); err != nil { // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := boxvalues.RecordVersions(dir, "0.1.0-m", "0.1.0-m"); err != nil {
		t.Fatal(err)
	}
	out := boxvalues.Substitute([]byte("os: baseos-version.invalid\nweb: baseweb-version.invalid\n"), boxvalues.Table(slot, boxvalues.Read(dir), "sneakers-0a1b2c3d")) // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
	if string(out) != "os: 0.1.0-m\nweb: 0.1.0-m\n" {
		t.Fatalf("%q", out)
	}
}
