// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
)

const (
	brandYAML = "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.svg\ncolours:\n  background: \"#0b1f33\"\n  text: \"#ffffff\"\n  accent: \"#ffb000\"\n"
	brandSVG  = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#ffb000"/></svg>`
)

// product lays out the product slots as the box does: current names a
// slot, and the slot's brand/ holds files.
func product(t *testing.T, slot string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	setSlot(t, dir, slot, files)
	return dir
}

func setSlot(t *testing.T, dir, slot string, files map[string]string) {
	t.Helper()
	if files != nil {
		b := filepath.Join(dir, slot, "brand")
		if err := os.MkdirAll(b, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(b, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	} else if err := os.MkdirAll(filepath.Join(dir, slot), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".current.new")
	_ = os.Remove(tmp)
	if err := os.Symlink(slot, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
}

func brandDir(dir string) string { return filepath.Join(dir, "current", "brand") }

func serveBranded(t *testing.T, s boxstate.State, dir string) (*httptest.Server, *edgefall.Server) {
	t.Helper()
	srv := edgefall.NewServer(func() boxstate.State { return s })
	if _, _, err := srv.LoadBrand(brandDir(dir)); err != nil {
		t.Logf("brand: %v", err)
	}
	ts := httptest.NewUnstartedServer(nil)
	ts.Config = edgefall.HTTPServer(srv)
	ts.Start()
	t.Cleanup(ts.Close)
	return ts, srv
}

func styleOf(t *testing.T, res *http.Response, body string) string {
	t.Helper()
	_, rest, _ := strings.Cut(body, "<style>")
	css, _, _ := strings.Cut(rest, "</style>")
	sum := sha256.Sum256([]byte(css))
	if want := "style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"; !strings.Contains(res.Header.Get("Content-Security-Policy"), want) {
		t.Fatalf("CSP %q lacks %q", res.Header.Get("Content-Security-Policy"), want)
	}
	return css
}

func strictCSP(t *testing.T, csp string) {
	t.Helper()
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "img-src 'self' data:", "style-src 'sha256-", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "*") || strings.Count(csp, "style-src") != 1 {
		t.Fatalf("CSP %q is weaker", csp)
	}
}

func TestWithNoProductThePageKeepsTheBaseLook(t *testing.T) {
	base, basePage := get(t, serve(t, boxstate.Rebooting).URL+"/")
	for name, dir := range map[string]string{"no product": t.TempDir(), "no brand": product(t, "a", nil)} {
		ts, _ := serveBranded(t, boxstate.Rebooting, dir)
		res, body := get(t, ts.URL+"/")
		if body != basePage || res.Header.Get("Content-Security-Policy") != base.Header.Get("Content-Security-Policy") {
			t.Fatalf("%s: the page changed: %s", name, body)
		}
		if strings.Contains(body, "/_box/logo") || !strings.Contains(body, `class="mark"`) {
			t.Fatalf("%s: %s", name, body)
		}
		if r, _ := get(t, ts.URL+"/_box/logo"); r.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s: /_box/logo answered %d without a logo", name, r.StatusCode)
		}
		_, st := get(t, ts.URL+"/_box/state")
		if st != `{"state":"rebooting"}` {
			t.Fatalf("%s: state %s", name, st)
		}
	}
}

func TestAProductsBrandShowsOnThePage(t *testing.T) {
	dir := product(t, "a", map[string]string{"brand.yaml": brandYAML, "logo.svg": brandSVG})
	ts, _ := serveBranded(t, boxstate.Rebooting, dir)
	res, body := get(t, ts.URL+"/")
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Sneakers-PAM is rebooting") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	// The page carries the logo itself, so it shows even when 443 goes
	// away between the page and a second request.
	if !strings.Contains(html.UnescapeString(body), `<img class="logo" src="data:image/svg+xml;base64,`+base64.StdEncoding.EncodeToString([]byte(brandSVG))+`"`) || strings.Contains(body, `class="mark"`) {
		t.Fatalf("no logo: %s", body)
	}
	strictCSP(t, res.Header.Get("Content-Security-Policy"))
	css := styleOf(t, res, body)
	for _, want := range []string{"#0b1f33", "#ffffff", "#ffb000"} {
		if !strings.Contains(css, want) {
			t.Fatalf("the style lacks %s: %s", want, css)
		}
	}
	if strings.Count(body, "<style") != 1 || strings.Contains(body, "style=") {
		t.Fatalf("styles: %s", body)
	}

	lr, logo := get(t, ts.URL+"/_box/logo")
	if lr.StatusCode != http.StatusOK || logo != brandSVG || lr.Header.Get("Content-Type") != "image/svg+xml" ||
		lr.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(lr.Header.Get("Content-Security-Policy"), "sandbox") ||
		!strings.Contains(lr.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("logo: %d %v", lr.StatusCode, lr.Header)
	}

	_, st := get(t, ts.URL+"/_box/state")
	var got struct {
		State string `json:"state"`
		Brand struct {
			Background, Text, Accent, Logo string
		} `json:"brand"`
	}
	if err := json.Unmarshal([]byte(st), &got); err != nil || got.State != "rebooting" || got.Brand.Background != "#0b1f33" ||
		got.Brand.Text != "#ffffff" || got.Brand.Accent != "#ffb000" || got.Brand.Logo != "/_box/logo" {
		t.Fatalf("state %s %v", st, err)
	}
}

// A brand the bundle check would refuse never reaches the page.
func TestAMalformedBrandIsIgnored(t *testing.T) {
	_, basePage := get(t, serve(t, boxstate.Rebooting).URL+"/")
	for name, files := range map[string]map[string]string{
		"script":   {"brand.yaml": brandYAML, "logo.svg": `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`},
		"bad hex":  {"brand.yaml": strings.Replace(brandYAML, `"#0b1f33"`, `"#000;}*{x:y"`, 1), "logo.svg": brandSVG},
		"no logo":  {"brand.yaml": brandYAML},
		"not yaml": {"brand.yaml": "{", "logo.svg": brandSVG},
	} {
		dir := product(t, "a", files)
		srv := edgefall.NewServer(func() boxstate.State { return boxstate.Rebooting })
		if _, _, err := srv.LoadBrand(brandDir(dir)); err == nil {
			t.Errorf("%s: no error", name)
		}
		ts := httptest.NewServer(srv)
		res, body := get(t, ts.URL+"/")
		ts.Close()
		if body != basePage {
			t.Errorf("%s: the page changed: %s", name, body)
		}
		strictCSP(t, res.Header.Get("Content-Security-Policy"))
	}
}

// Colours that fail the contrast check fall back to the base colours; the
// logo still shows.
func TestPoorContrastKeepsTheBaseColours(t *testing.T) {
	dir := product(t, "a", map[string]string{"brand.yaml": strings.Replace(brandYAML, `"#ffffff"`, `"#102030"`, 1), "logo.svg": brandSVG})
	srv := edgefall.NewServer(func() boxstate.State { return boxstate.Rebooting })
	_, warn, err := srv.LoadBrand(brandDir(dir))
	if err != nil || len(warn) != 1 {
		t.Fatalf("%v %v", warn, err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	res, body := get(t, ts.URL+"/")
	css := styleOf(t, res, body)
	if strings.Contains(css, "#0b1f33") || !strings.Contains(body, `class="logo"`) {
		t.Fatalf("%s", body)
	}
}

// Applying or reverting a product moves current, and the brand follows it
// at the next load; an unchanged slot isn't read again.
func TestTheBrandFollowsTheSlot(t *testing.T) {
	dir := product(t, "a", nil)
	srv := edgefall.NewServer(func() boxstate.State { return boxstate.Updating })
	ts := httptest.NewServer(srv)
	defer ts.Close()
	load := func() bool {
		changed, _, err := srv.LoadBrand(brandDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	load()
	if _, body := get(t, ts.URL+"/"); strings.Contains(body, `class="logo"`) {
		t.Fatal("a logo before any brand")
	}
	setSlot(t, dir, "b", map[string]string{"brand.yaml": brandYAML, "logo.svg": brandSVG})
	if !load() {
		t.Fatal("the apply wasn't seen")
	}
	if _, body := get(t, ts.URL+"/"); !strings.Contains(body, `class="logo"`) {
		t.Fatal("no logo after the apply")
	}
	if load() {
		t.Fatal("an unchanged slot loaded again")
	}
	setSlot(t, dir, "a", nil)
	if !load() {
		t.Fatal("the revert wasn't seen")
	}
	if _, body := get(t, ts.URL+"/"); strings.Contains(body, `class="logo"`) {
		t.Fatal("the logo stayed after the revert")
	}
}

func TestThePollerUsesTheBrand(t *testing.T) {
	_, js := get(t, serve(t, boxstate.Running).URL+"/_box/poll.js")
	for _, want := range []string{"j.brand", "/_box/logo", "#[0-9a-f]{6}"} {
		if !strings.Contains(js, want) {
			t.Errorf("poll.js lacks %s", want)
		}
	}
}
